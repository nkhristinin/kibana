/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient } from '@kbn/core/server';
import { RULE_EXECUTION_TRACE_DATA_STREAM_PREFIX } from './constants';
import type { RuleExecutionTraceLogDoc } from './types';

/**
 * Constructs the data stream name for a given space.
 */
export function getTraceDataStreamName(spaceId: string): string {
  return `${RULE_EXECUTION_TRACE_DATA_STREAM_PREFIX}-${spaceId}`;
}

/**
 * Common search parameters for trace log queries.
 */
export interface TraceSearchParams {
  ruleId: string;
  dateStartIso: string;
  limit: number;
  searchAfter?: unknown[];
}

/**
 * Builds the ES query for searching trace logs.
 */
export function buildTraceSearchQuery(params: TraceSearchParams) {
  const { ruleId, dateStartIso, limit, searchAfter } = params;

  return {
    size: limit,
    sort: [{ '@timestamp': 'asc' as const }, { seq: 'asc' as const }],
    ...(searchAfter ? { search_after: searchAfter } : {}),
    query: {
      bool: {
        filter: [
          { term: { doc_kind: 'log' } },
          { term: { rule_id: ruleId } },
          { range: { '@timestamp': { gte: dateStartIso } } },
        ],
      },
    },
    track_total_hits: false,
    ignore_unavailable: true,
    allow_no_indices: true,
  };
}

/**
 * Searches trace logs with graceful handling for missing data streams.
 * Returns empty array if data stream doesn't exist.
 */
export async function searchTraceLogs(
  esClient: ElasticsearchClient,
  index: string,
  params: TraceSearchParams
): Promise<Array<{ _source?: RuleExecutionTraceLogDoc; sort?: unknown[] }>> {
  try {
    const res = await esClient.search<RuleExecutionTraceLogDoc>({
      index,
      ...buildTraceSearchQuery(params),
    });
    return res.hits.hits ?? [];
  } catch {
    // Data stream likely doesn't exist - return empty
    return [];
  }
}

/**
 * Maps a trace log doc to the API response format.
 */
export function mapTraceDocToItem(doc: RuleExecutionTraceLogDoc) {
  return {
    ts: doc.ts,
    seq: doc.seq,
    level: doc.level,
    logger: doc.logger,
    execution_id: doc.execution_id,
    message_text: doc.message_text,
    ...(doc.message !== undefined ? { message: doc.message } : {}),
  };
}

/**
 * Default time range for trace queries (5 minutes ago).
 */
export function getDefaultDateStart(): string {
  return new Date(Date.now() - 5 * 60 * 1000).toISOString();
}

