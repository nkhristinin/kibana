/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import { ToolType } from '@kbn/agent-builder-common';
import { ToolResultType } from '@kbn/agent-builder-common/tools/tool_result';
import type { BuiltinToolDefinition } from '@kbn/agent-builder-server';
import type { Logger } from '@kbn/logging';
import { DEFAULT_ALERTS_INDEX } from '../../../../common/constants';
import { securityTool } from '../constants';
import { getAgentBuilderResourceAvailability } from '../../utils/get_agent_builder_resource_availability';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../../plugin_contract';

export const SECURITY_AGGREGATE_ALERTS_FOR_RULE_TOOL_ID = securityTool(
  'core.aggregate_alerts_for_rule'
);

const aggregateAlertsForRuleSchema = z.object({
  rule_id: z
    .string()
    .describe('The rule saved-object id (matches `kibana.alert.rule.uuid` on alerts).'),
  timeframe_hours: z
    .number()
    .int()
    .min(1)
    .max(720)
    .default(24)
    .describe('Look-back window in hours. Defaults to last 24 hours.'),
  bucket_size: z
    .number()
    .int()
    .min(1)
    .max(50)
    .default(10)
    .describe('Number of top buckets to return per aggregation.'),
});

interface BucketResult {
  value: string;
  count: number;
}

const extractBuckets = (aggBuckets: unknown): BucketResult[] => {
  if (!Array.isArray(aggBuckets)) return [];
  return aggBuckets
    .filter(
      (b): b is { key: string; doc_count: number } =>
        typeof b === 'object' && b !== null && typeof (b as { key?: unknown }).key === 'string'
    )
    .map((b) => ({ value: b.key, count: b.doc_count }));
};

export const aggregateAlertsForRuleTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof aggregateAlertsForRuleSchema> => ({
  id: SECURITY_AGGREGATE_ALERTS_FOR_RULE_TOOL_ID,
  type: ToolType.builtin,
  description: `Aggregate recent alerts produced by a rule, grouped by the entities most useful for FP tuning: host.name, user.name, process.parent.name, process.name. Returns top buckets for each. A single dominant parent process or host in the results is the strongest signal for choosing an exclusion target.`,
  schema: aggregateAlertsForRuleSchema,
  tags: ['security', 'detection', 'alerts'],
  availability: {
    cacheMode: 'space',
    handler: async ({ request }) => getAgentBuilderResourceAvailability({ core, request, logger }),
  },
  handler: async (
    { rule_id: ruleId, timeframe_hours: timeframeHours, bucket_size: bucketSize },
    { esClient, spaceId }
  ) => {
    try {
      const index = `${DEFAULT_ALERTS_INDEX}-${spaceId}`;
      const response = await esClient.asCurrentUser.search({
        index,
        size: 0,
        track_total_hits: true,
        query: {
          bool: {
            filter: [
              { term: { 'kibana.alert.rule.uuid': ruleId } },
              {
                range: {
                  '@timestamp': { gte: `now-${timeframeHours}h`, lte: 'now' },
                },
              },
            ],
          },
        },
        aggs: {
          by_host: { terms: { field: 'host.name', size: bucketSize } },
          by_user: { terms: { field: 'user.name', size: bucketSize } },
          by_parent_process: {
            terms: { field: 'process.parent.name', size: bucketSize },
          },
          by_process: { terms: { field: 'process.name', size: bucketSize } },
        },
      });

      const total =
        typeof response.hits.total === 'number'
          ? response.hits.total
          : response.hits.total?.value ?? 0;

      const aggs = (response.aggregations ?? {}) as Record<string, { buckets?: unknown }>;

      return {
        results: [
          {
            type: ToolResultType.other,
            data: {
              rule_id: ruleId,
              timeframe_hours: timeframeHours,
              total,
              by_host: extractBuckets(aggs.by_host?.buckets),
              by_user: extractBuckets(aggs.by_user?.buckets),
              by_parent_process: extractBuckets(aggs.by_parent_process?.buckets),
              by_process: extractBuckets(aggs.by_process?.buckets),
            },
          },
        ],
      };
    } catch (error) {
      logger.error(`aggregate_alerts_for_rule failed: ${error.message}`, error);
      return {
        results: [
          {
            type: ToolResultType.error,
            data: { message: `Failed to aggregate alerts: ${error.message}` },
          },
        ],
      };
    }
  },
});
