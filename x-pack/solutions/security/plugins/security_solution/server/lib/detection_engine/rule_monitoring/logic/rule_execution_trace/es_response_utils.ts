/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Common security-relevant fields to extract from ES hits for AI analysis.
 */
const KEY_FIELD_PATHS = [
  'host.name',
  'host.hostname',
  'host.ip',
  'user.name',
  'user.domain',
  'process.name',
  'process.executable',
  'process.args',
  'process.parent.name',
  'process.parent.executable',
  'event.action',
  'event.category',
  'event.type',
  'event.outcome',
  'file.path',
  'file.name',
  'destination.ip',
  'destination.port',
  'source.ip',
  'source.port',
  'url.full',
  'url.domain',
  'agent.name',
  'agent.type',
  '@timestamp',
  'message',
] as const;

/**
 * Extracts key security-relevant fields from an ES document source.
 * Used to provide focused context for AI analysis without overwhelming with full _source.
 */
export function extractKeyFields(source: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!source) return {};
  const result: Record<string, unknown> = {};

  for (const path of KEY_FIELD_PATHS) {
    const value = getNestedValue(source, path);
    if (value !== undefined) {
      result[path] = value;
    }
  }
  return result;
}

/**
 * Gets a nested value from an object using a dot-separated path.
 */
function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.');
  let value: unknown = obj;
  for (const part of parts) {
    if (value && typeof value === 'object' && part in value) {
      value = (value as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return value;
}

/**
 * Limits aggregation buckets to prevent large payloads.
 */
export function limitAggregationBuckets(
  aggregations: Record<string, unknown> | undefined,
  maxBuckets = 10
): Record<string, unknown> | undefined {
  if (!aggregations) return undefined;

  const limited: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(aggregations)) {
    if (value && typeof value === 'object' && 'buckets' in value) {
      const aggValue = value as { buckets: unknown[]; [k: string]: unknown };
      limited[key] = {
        ...aggValue,
        buckets: Array.isArray(aggValue.buckets)
          ? aggValue.buckets.slice(0, maxBuckets)
          : aggValue.buckets,
        buckets_truncated: Array.isArray(aggValue.buckets) && aggValue.buckets.length > maxBuckets,
      };
    } else {
      limited[key] = value;
    }
  }
  return limited;
}

/**
 * Creates a summarized ES response for trace logging.
 * Extracts key fields from sample hits instead of full _source.
 */
export function summarizeEsResponse(
  response: {
    took?: number;
    timed_out?: boolean;
    _shards?: unknown;
    hits?: {
      total?: number | { value: number };
      max_score?: number | null;
      hits?: Array<{ _index?: string; _id?: string; _score?: number | null; _source?: unknown }>;
    };
    aggregations?: Record<string, unknown>;
  },
  sampleSize = 3
) {
  const totalHits =
    typeof response.hits?.total === 'number'
      ? response.hits.total
      : response.hits?.total?.value ?? 0;

  const hitsArray = response.hits?.hits;

  return {
    took: response.took,
    timed_out: response.timed_out,
    _shards: response._shards,
    hits: {
      total: totalHits,
      max_score: response.hits?.max_score,
      sample_hits: hitsArray?.slice(0, sampleSize)?.map((hit) => ({
        _index: hit._index,
        _id: hit._id,
        _score: hit._score,
        fields: extractKeyFields(hit._source as Record<string, unknown>),
      })),
      more_hits: totalHits > sampleSize,
    },
    aggregations: limitAggregationBuckets(response.aggregations),
  };
}

