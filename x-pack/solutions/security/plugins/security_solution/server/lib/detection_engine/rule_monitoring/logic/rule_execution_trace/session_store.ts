/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Logger, SavedObjectsClientContract } from '@kbn/core/server';

import {
  RULE_EXECUTION_TRACE_SESSION_SO_TYPE,
  type RuleExecutionTraceSessionAttributes,
} from './session_saved_object';

export interface TraceSession {
  id: string;
  ruleId: string;
  createdAt: string;
  expiresAt: string;
}

export class RuleExecutionTraceSessionStore {
  constructor(
    private readonly soClient: SavedObjectsClientContract,
    private readonly logger: Logger
  ) {}

  public async upsertSession({
    ruleId,
    ttlMs,
  }: {
    ruleId: string;
    ttlMs: number;
  }): Promise<TraceSession> {
    const now = Date.now();
    const createdAt = new Date(now).toISOString();
    const expiresAt = new Date(now + ttlMs).toISOString();

    this.logger.debug(`[SESSION] upsertSession: ruleId=${ruleId}, ttlMs=${ttlMs}`);

    // Best-effort pruning so session SOs remain short-lived even if callers never disconnect.
    await this.deleteExpiredSessions({ nowMs: now, limit: 200 }).catch(() => {});

    const attributes: RuleExecutionTraceSessionAttributes = {
      rule_id: ruleId,
      created_at: createdAt,
      expires_at: expiresAt,
    };

    const created = await this.soClient.create<RuleExecutionTraceSessionAttributes>(
      RULE_EXECUTION_TRACE_SESSION_SO_TYPE,
      attributes,
      // Use ruleId as SO id for per-rule sessions (space-scoped).
      // Use refresh: true (not wait_for) for faster availability
      { id: ruleId, overwrite: true, refresh: true }
    );

    return {
      id: created.id,
      ruleId,
      createdAt,
      expiresAt,
    };
  }

  public async isSessionActive({
    ruleId,
    nowMs = Date.now(),
  }: {
    ruleId: string;
    nowMs?: number;
  }): Promise<boolean> {
    try {
      const so = await this.soClient.get<RuleExecutionTraceSessionAttributes>(
        RULE_EXECUTION_TRACE_SESSION_SO_TYPE,
        ruleId
      );
      const expiresAtMs = Date.parse(so.attributes.expires_at);
      return Number.isFinite(expiresAtMs) && expiresAtMs > nowMs;
    } catch {
      return false;
    }
  }

  public async deleteExpiredSessions({
    nowMs = Date.now(),
    limit = 200,
  }: {
    nowMs?: number;
    limit?: number;
  }): Promise<void> {
    // KQL for saved objects: <type>.attributes.<field>
    const filter = `${RULE_EXECUTION_TRACE_SESSION_SO_TYPE}.attributes.expires_at < ${nowMs}`;
    const res = await this.soClient.find<RuleExecutionTraceSessionAttributes>({
      type: RULE_EXECUTION_TRACE_SESSION_SO_TYPE,
      filter,
      perPage: limit,
      page: 1,
    });

    await Promise.all(
      res.saved_objects.map((so) =>
        this.soClient.delete(RULE_EXECUTION_TRACE_SESSION_SO_TYPE, so.id).catch((e) => {
          const reason = e instanceof Error ? e.message : String(e);
          this.logger.debug(`Failed deleting expired trace session [${so.id}]: ${reason}`);
        })
      )
    );
  }
}


