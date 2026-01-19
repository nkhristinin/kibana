/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import type { DataStreamSpacesAdapter } from '@kbn/data-stream-adapter';
import { ReplaySubject } from 'rxjs';

import { createRuleExecutionTraceDatastream } from './data_stream';

/**
 * Service for managing rule execution trace data streams.
 *
 * Uses Data Stream Lifecycle (DSL) for retention, which works in both
 * serverless and traditional Elasticsearch deployments.
 */
export class RuleExecutionTraceService {
  private readonly stop$ = new ReplaySubject<void>(1);
  private ds: DataStreamSpacesAdapter | undefined;
  private started = false;

  constructor(private readonly logger: Logger) {}

  public setup({ retention }: { retention?: string } = {}) {
    this.ds = createRuleExecutionTraceDatastream({ retention });
  }

  public async start({ esClient }: { esClient: ElasticsearchClient }): Promise<void> {
    if (this.started) return;
    if (!this.ds) {
      throw new Error('RuleExecutionTraceService not setup');
    }

    await this.ds.install({
      logger: this.logger,
      esClient,
      pluginStop$: this.stop$,
    });

    this.started = true;
  }

  public stop() {
    this.stop$.next();
    this.stop$.complete();
  }

  /**
   * Ensures the per-space data stream exists and returns its concrete name.
   */
  public async ensureSpaceDataStream(spaceId: string): Promise<string> {
    if (!this.ds) {
      throw new Error('RuleExecutionTraceService not setup');
    }
    return this.ds.installSpace(spaceId);
  }

  public async getInstalledSpaceDataStream(spaceId: string): Promise<string | undefined> {
    if (!this.ds) {
      return undefined;
    }
    return this.ds.getInstalledSpaceName(spaceId);
  }
}
