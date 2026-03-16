/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { estypes } from '@elastic/elasticsearch';
import { z } from '@kbn/zod/v4';
import { ToolType, ToolResultType } from '@kbn/agent-builder-common';
import type { BuiltinToolDefinition } from '@kbn/agent-builder-server';
import type { Logger } from '@kbn/logging';
import { HealthIntervalGranularity } from '../../../common/api/detection_engine/rule_monitoring';
import {
  getRuleExecutionStatsAggregation,
  normalizeRuleExecutionStatsAggregationResult,
} from '../../lib/detection_engine/rule_monitoring/logic/detection_engine_health/event_log/aggregations/rule_execution_stats';
import {
  getRuleHealthAggregation,
  normalizeRuleHealthAggregationResult,
} from '../../lib/detection_engine/rule_monitoring/logic/detection_engine_health/event_log/aggregations/health_stats_for_rule';
import type { RawData } from '../../lib/detection_engine/rule_monitoring/logic/utils/normalization';
import { getAgentBuilderResourceAvailability } from '../utils/get_agent_builder_resource_availability';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../plugin_contract';
import { securityTool } from './constants';

export const SECURITY_EXECUTION_STATS_TOOL_ID = securityTool('execution_stats');

const EVENT_LOG_INDEX = '.kibana-event-log-*';

const ALERTING_PROVIDER = 'alerting';
const RULE_EXECUTION_LOG_PROVIDER = 'securitySolution.ruleExecution';
const RULE_ID_FIELD = 'rule.id';
const RULE_NAME_FIELD = 'rule.name';
const SCHEDULE_DELAY_FIELD = 'kibana.task.schedule_delay';
const TOTAL_RUN_DURATION_MS_FIELD = 'kibana.alert.rule.execution.metrics.total_run_duration_ms';
const TOTAL_SEARCH_DURATION_MS_FIELD =
  'kibana.alert.rule.execution.metrics.total_search_duration_ms';
const GAP_DURATION_S_FIELD = 'kibana.alert.rule.execution.metrics.execution_gap_duration_s';
const RULE_EXECUTION_UUID_FIELD = 'kibana.alert.rule.execution.uuid';
const NS_TO_MS = 1_000_000;

type TopRulesByMetric = (typeof TOP_RULES_BY_VALUES)[number];

interface TopRuleEntry {
  rule_id: string;
  rule_name: string;
  metric_value: number;
  metric_p95?: number;
  total_executions: number;
}

function buildTopRulesAggregation(metric: TopRulesByMetric, size: number): Record<string, unknown> {
  const executeEventFilter = {
    bool: {
      filter: [
        { term: { 'event.provider': ALERTING_PROVIDER } },
        { term: { 'event.action': 'execute' } },
        { term: { 'event.category': 'siem' } },
      ],
    },
  };
  const executionMetricsFilter = {
    bool: {
      filter: [
        { term: { 'event.provider': RULE_EXECUTION_LOG_PROVIDER } },
        { term: { 'event.action': 'execution-metrics' } },
      ],
    },
  };
  const errorEventsFilter = {
    bool: {
      filter: [
        { term: { 'event.provider': RULE_EXECUTION_LOG_PROVIDER } },
        { terms: { 'event.action': ['status-change', 'message'] } },
        { term: { 'log.level': 'error' } },
      ],
    },
  };

  let metricFilterAgg: Record<string, unknown>;
  let sortPath: string;

  switch (metric) {
    case 'schedule_delay':
      metricFilterAgg = {
        filter: executeEventFilter,
        aggs: {
          avgScheduleDelay: { avg: { field: SCHEDULE_DELAY_FIELD } },
          p95ScheduleDelay: {
            percentiles: { field: SCHEDULE_DELAY_FIELD, percents: [95] },
          },
          totalExecutions: {
            cardinality: { field: RULE_EXECUTION_UUID_FIELD },
          },
        },
      };
      sortPath = 'metricFilter.avgScheduleDelay';
      break;
    case 'execution_duration':
      metricFilterAgg = {
        filter: executeEventFilter,
        aggs: {
          avgExecutionDuration: { avg: { field: TOTAL_RUN_DURATION_MS_FIELD } },
          p95ExecutionDuration: {
            percentiles: {
              field: TOTAL_RUN_DURATION_MS_FIELD,
              percents: [95],
            },
          },
          totalExecutions: {
            cardinality: { field: RULE_EXECUTION_UUID_FIELD },
          },
        },
      };
      sortPath = 'metricFilter.avgExecutionDuration';
      break;
    case 'search_duration':
      metricFilterAgg = {
        filter: executionMetricsFilter,
        aggs: {
          avgSearchDuration: { avg: { field: TOTAL_SEARCH_DURATION_MS_FIELD } },
          p95SearchDuration: {
            percentiles: {
              field: TOTAL_SEARCH_DURATION_MS_FIELD,
              percents: [95],
            },
          },
          totalExecutions: {
            cardinality: { field: RULE_EXECUTION_UUID_FIELD },
          },
        },
      };
      sortPath = 'metricFilter.avgSearchDuration';
      break;
    case 'gap_duration':
      metricFilterAgg = {
        filter: executionMetricsFilter,
        aggs: {
          sumGapDuration: { sum: { field: GAP_DURATION_S_FIELD } },
          totalExecutions: {
            cardinality: { field: RULE_EXECUTION_UUID_FIELD },
          },
        },
      };
      sortPath = 'metricFilter.sumGapDuration';
      break;
    case 'errors':
      metricFilterAgg = {
        filter: errorEventsFilter,
        aggs: {
          errorCount: { value_count: { field: RULE_ID_FIELD } },
          totalExecutions: {
            cardinality: { field: RULE_EXECUTION_UUID_FIELD },
          },
        },
      };
      sortPath = 'metricFilter.errorCount';
      break;
    default:
      return {};
  }

  // Use bucket_sort pipeline to sort by nested metric; terms agg cannot order by
  // a path through a filter (single-bucket) agg in some ES versions.
  const BUCKET_SORT_FETCH_SIZE = 500;
  return {
    terms: {
      field: RULE_ID_FIELD,
      size: BUCKET_SORT_FETCH_SIZE,
      order: { _key: 'asc' as const },
      min_doc_count: metric === 'errors' ? 1 : 1,
    },
    aggs: {
      ruleName: { terms: { field: RULE_NAME_FIELD, size: 1 } },
      metricFilter: metricFilterAgg,
      sortBuckets: {
        bucket_sort: {
          sort: [{ [sortPath]: { order: 'desc' as const } }],
          from: 0,
          size,
        },
      },
    },
  };
}

function normalizeTopRules(
  topRulesAgg: Record<string, RawData> | undefined,
  metric: TopRulesByMetric
): TopRuleEntry[] {
  const buckets = (topRulesAgg?.buckets ?? []) as Array<Record<string, RawData>>;
  return buckets.map((bucket) => {
    const ruleId = String(bucket.key ?? '');
    const ruleNameBucket = (bucket.ruleName as { buckets?: Array<{ key?: string }> })?.buckets;
    const ruleName =
      (ruleNameBucket?.length ?? 0) > 0 ? String(ruleNameBucket?.[0]?.key ?? '') : '';

    const metricFilter = bucket.metricFilter as Record<string, RawData>;
    const totalExecutionsAgg = metricFilter?.totalExecutions as { value?: number };
    const totalExecutions = Number(totalExecutionsAgg?.value ?? 0);

    let metricValue = 0;
    let metricP95: number | undefined;

    switch (metric) {
      case 'schedule_delay': {
        const avg = (metricFilter?.avgScheduleDelay as { value?: number })?.value;
        const p95 = (metricFilter?.p95ScheduleDelay as { values?: { '95.0'?: number } })?.values;
        metricValue = Number(avg ?? 0) / NS_TO_MS;
        metricP95 = p95?.['95.0'] != null ? Number(p95['95.0']) / NS_TO_MS : undefined;
        break;
      }
      case 'execution_duration': {
        const avg = (metricFilter?.avgExecutionDuration as { value?: number })?.value;
        const p95 = (metricFilter?.p95ExecutionDuration as { values?: { '95.0'?: number } })
          ?.values;
        metricValue = Number(avg ?? 0);
        metricP95 = p95?.['95.0'];
        break;
      }
      case 'search_duration': {
        const avg = (metricFilter?.avgSearchDuration as { value?: number })?.value;
        const p95 = (metricFilter?.p95SearchDuration as { values?: { '95.0'?: number } })?.values;
        metricValue = Number(avg ?? 0);
        metricP95 = p95?.['95.0'];
        break;
      }
      case 'gap_duration': {
        const sum = (metricFilter?.sumGapDuration as { value?: number })?.value;
        metricValue = Number(sum ?? 0);
        break;
      }
      case 'errors': {
        const errorCount = (metricFilter?.errorCount as { value?: number })?.value;
        metricValue = Number(errorCount ?? 0);
        break;
      }
    }

    return {
      rule_id: ruleId,
      rule_name: ruleName,
      metric_value: Math.round(metricValue * 1000) / 1000,
      ...(metricP95 != null && { metric_p95: Math.round(metricP95 * 1000) / 1000 }),
      total_executions: totalExecutions,
    };
  });
}

const TOP_RULES_BY_VALUES = [
  'schedule_delay',
  'execution_duration',
  'search_duration',
  'gap_duration',
  'errors',
] as const;

const executionStatsSchema = z.object({
  start: z
    .string()
    .optional()
    .describe('ISO date for the start of the time range (default: 24 hours ago)'),
  end: z.string().optional().describe('ISO date for the end of the time range (default: now)'),
  rule_id: z
    .string()
    .optional()
    .describe(
      'Optional rule saved-object ID to scope stats to a single rule. If omitted, stats cover all SIEM rules in the space.'
    ),
  include_history: z
    .boolean()
    .optional()
    .describe('If true, include time-series buckets (hourly) of execution stats. Default: false.'),
  top_rules_by: z
    .enum(TOP_RULES_BY_VALUES)
    .optional()
    .describe(
      'Return the top N rules ranked by this metric. Useful for identifying which specific rules are most delayed, slowest, or erroring.'
    ),
  top_rules_count: z
    .number()
    .int()
    .min(1)
    .max(50)
    .optional()
    .describe('Number of top rules to return when using top_rules_by. Default: 10.'),
});

export const executionStatsTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof executionStatsSchema> => {
  return {
    id: SECURITY_EXECUTION_STATS_TOOL_ID,
    type: ToolType.builtin,
    description:
      'Query the rule execution event log for detailed execution statistics: execution duration percentiles (p50/p95/p99), schedule delay percentiles, search and indexing duration percentiles, execution outcome breakdown, top error and warning messages, message counts by log level, and gap statistics. Optionally includes time-series history. When top_rules_by is specified, also returns the top N rules ranked by that metric (e.g. most delayed, slowest, most errors), enabling drill-down from aggregate stats to specific rules. Use for performance analysis, trend detection, and questions like "what are the top errors?", "what is the p95 execution time?", "is schedule delay increasing?", "which rules are most delayed?", "which rules are slowest?".',
    schema: executionStatsSchema,
    tags: ['security', 'detection', 'rules', 'monitoring', 'execution', 'event-log'],
    availability: {
      cacheMode: 'space',
      handler: async ({ request }) => {
        return getAgentBuilderResourceAvailability({ core, request, logger });
      },
    },
    handler: async (params, { esClient, spaceId }) => {
      try {
        const now = new Date();
        const defaultStart = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const start = params.start ?? defaultStart.toISOString();
        const end = params.end ?? now.toISOString();

        const queryFilters: Array<Record<string, unknown>> = [
          { range: { '@timestamp': { gte: start, lte: end } } },
          { term: { 'kibana.space_ids': spaceId } },
        ];
        if (params.rule_id) {
          queryFilters.push({ term: { 'rule.id': params.rule_id } });
        }

        const aggs: Record<string, unknown> = params.include_history
          ? (getRuleHealthAggregation(HealthIntervalGranularity.hour) as Record<string, unknown>)
          : (getRuleExecutionStatsAggregation('whole-interval') as Record<string, unknown>);

        if (params.top_rules_by) {
          const topCount = params.top_rules_count ?? 10;
          aggs.topRules = buildTopRulesAggregation(params.top_rules_by, topCount);
        }

        const response = await esClient.asCurrentUser.search({
          index: EVENT_LOG_INDEX,
          size: 0,
          query: {
            bool: {
              filter: queryFilters,
            },
          },
          aggs: aggs as Record<string, estypes.AggregationsAggregationContainer>,
        });

        const aggregations = (response.aggregations ?? {}) as Record<string, RawData>;

        const topRules =
          params.top_rules_by && aggregations.topRules
            ? normalizeTopRules(
                aggregations.topRules as Record<string, RawData>,
                params.top_rules_by
              )
            : undefined;

        if (params.include_history) {
          const healthResult = normalizeRuleHealthAggregationResult(
            { aggregations },
            aggs as Record<string, estypes.AggregationsAggregationContainer>
          );
          return {
            results: [
              {
                type: ToolResultType.other,
                data: {
                  interval: { start, end },
                  stats_over_interval: healthResult.stats_over_interval,
                  history_over_interval: healthResult.history_over_interval,
                  ...(topRules != null && { top_rules: topRules }),
                },
              },
            ],
          };
        }

        const stats = normalizeRuleExecutionStatsAggregationResult(aggregations, 'whole-interval');
        return {
          results: [
            {
              type: ToolResultType.other,
              data: {
                interval: { start, end },
                stats_over_interval: stats,
                ...(topRules != null && { top_rules: topRules }),
              },
            },
          ],
        };
      } catch (error) {
        logger.error(`execution_stats tool failed: ${error.message}`);
        return {
          results: [
            {
              type: ToolResultType.error,
              data: { message: `Failed to get execution stats: ${error.message}` },
            },
          ],
        };
      }
    },
  };
};
