/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger, SavedObjectsClientContract } from '@kbn/core/server';

import type { RuleExecutionTraceService } from './service';
import { RuleExecutionTraceSessionStore } from './session_store';
import type { RuleExecutionTraceLogDoc } from './types';

const DEFAULT_MAX_DOCS_PER_EXECUTION = 10_000;
const DEFAULT_MAX_MESSAGE_CHARS = 20_000;

export interface TraceWriteContext {
  spaceId: string;
  ruleId: string;
  executionId: string;
}

/**
 * Writes trace log docs to the per-space data stream.
 * Best-effort: never throws.
 */
export class RuleExecutionTraceWriter {
  constructor(
    private readonly deps: {
      logger: Logger;
      esClient: ElasticsearchClient;
      traceService: RuleExecutionTraceService;
    }
  ) {}

  public async maybeWriteLog({
    soClient,
    context,
    nowIso,
    seq,
    level,
    loggerName,
    messageText,
    message,
    maxDocsPerExecution = DEFAULT_MAX_DOCS_PER_EXECUTION,
  }: {
    soClient: SavedObjectsClientContract;
    context: TraceWriteContext;
    nowIso: string;
    seq: number;
    level: string;
    loggerName: string;
    messageText: string;
    message?: unknown;
    maxDocsPerExecution?: number;
  }): Promise<void> {
    try {
      // Skip if over doc limit
      if (seq > maxDocsPerExecution) {
        return;
      }

      // Check if session is active
      const sessions = new RuleExecutionTraceSessionStore(
        soClient,
        this.deps.logger.get('sessions')
      );
      const active = await sessions.isSessionActive({ ruleId: context.ruleId });
      if (!active) {
        return;
      }

      // Ensure data stream exists and get index name
      const index = await this.deps.traceService.ensureSpaceDataStream(context.spaceId);

      // Truncate message if too long
      const trimmed =
        messageText.length > DEFAULT_MAX_MESSAGE_CHARS
          ? `${messageText.slice(0, DEFAULT_MAX_MESSAGE_CHARS)}…(truncated)`
          : messageText;

      const doc: RuleExecutionTraceLogDoc = {
        '@timestamp': nowIso,
        doc_kind: 'log',
        rule_id: context.ruleId,
        execution_id: context.executionId,
        ts: nowIso,
        seq,
        level,
        logger: loggerName,
        message_text: trimmed,
        ...(message !== undefined ? { message } : {}),
      };

      await this.deps.esClient.index({ index, document: doc });
    } catch (e) {
      // Never break execution - trace is best-effort
      this.deps.logger.debug(`[TRACE_WRITER] Failed to write trace: ${e}`);
    }
  }
}
