/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import { ToolType, ToolResultType } from '@kbn/agent-builder-common';
import type { BuiltinToolDefinition } from '@kbn/agent-builder-server';
import type { Logger } from '@kbn/logging';
import type { RuleLastRunOutcomes } from '@kbn/alerting-types';
import { getAgentBuilderResourceAvailability } from '../utils/get_agent_builder_resource_availability';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../plugin_contract';
import { securityTool } from './constants';

export const SECURITY_RULES_HEALTH_TOOL_ID = securityTool('rules_health');

const rulesHealthSchema = z.object({
  interval_start: z
    .string()
    .optional()
    .describe('ISO date for the start of the stats interval (default: 24 hours ago)'),
  interval_end: z
    .string()
    .optional()
    .describe('ISO date for the end of the stats interval (default: now)'),
});

const SIEM_RULE_FILTER = 'alert.attributes.consumer: "siem"';

export const rulesHealthTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof rulesHealthSchema> => {
  return {
    id: SECURITY_RULES_HEALTH_TOOL_ID,
    type: ToolType.builtin,
    description:
      'Get a health overview of all detection rules in the current space. Returns rule counts by outcome (succeeded/warning/failed), execution KPIs (success/failure/warning counts, alert totals, action totals), per-rule performance metrics (p50/p95 duration, success ratio), top failing rules with error messages, and gap summary. Use to answer questions like "how healthy are my rules?", "what are the top errors?", "are rules performing well?". If the interval has more than 10,000 execution events, pass a shorter interval_start/interval_end (e.g. last 1–6 hours).',
    schema: rulesHealthSchema,
    tags: ['security', 'detection', 'rules', 'health', 'monitoring'],
    availability: {
      cacheMode: 'space',
      handler: async ({ request }) => {
        return getAgentBuilderResourceAvailability({ core, request, logger });
      },
    },
    handler: async (params, { request }) => {
      try {
        const [, startPlugins] = await core.getStartServices();
        const rulesClient = await startPlugins.alerting.getRulesClientWithRequest(request);

        const now = new Date();
        const defaultStart = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const dateStart = params.interval_start ?? defaultStart.toISOString();
        const dateEnd = params.interval_end ?? now.toISOString();

        const [rulesResult, kpiResult, gapsResult] = await Promise.all([
          rulesClient.find({
            options: {
              filter: SIEM_RULE_FILTER,
              perPage: 1000,
              page: 1,
              sortField: 'executionStatus.lastExecutionDate',
              sortOrder: 'desc',
            },
            excludeFromPublicApi: false,
          }),
          rulesClient.getGlobalExecutionKpiWithAuth({
            dateStart,
            dateEnd,
          }),
          rulesClient
            .getRuleIdsWithGaps({
              start: dateStart,
              end: dateEnd,
            })
            .catch(() => null),
        ]);

        const rules = rulesResult.data;
        const byOutcome: Record<string, number> = { succeeded: 0, warning: 0, failed: 0 };
        let enabledCount = 0;
        let disabledCount = 0;
        const failingRules: Array<{ id: string; name: string; outcome: string; error: string }> =
          [];
        let totalSuccessRatio = 0;
        let rulesWithMetrics = 0;
        const durations: number[] = [];

        for (const rule of rules) {
          if (rule.enabled) {
            enabledCount++;
          } else {
            disabledCount++;
          }

          const outcome = (rule.lastRun?.outcome ?? 'unknown') as RuleLastRunOutcomes | 'unknown';
          if (outcome in byOutcome) {
            byOutcome[outcome]++;
          }

          if (outcome === 'failed' || outcome === 'warning') {
            failingRules.push({
              id: rule.id,
              name: rule.name,
              outcome,
              error: rule.lastRun?.outcomeMsg?.join('; ') ?? 'No error message',
            });
          }

          const metrics = rule.monitoring?.run?.calculated_metrics;
          if (metrics) {
            totalSuccessRatio += metrics.success_ratio;
            rulesWithMetrics++;
            if (metrics.p95 != null) {
              durations.push(metrics.p95);
            }
          }
        }

        failingRules.sort((a, b) => (a.outcome === 'failed' ? -1 : 1));

        const avgSuccessRatio = rulesWithMetrics > 0 ? totalSuccessRatio / rulesWithMetrics : null;

        durations.sort((a, b) => a - b);
        const p50Index = Math.floor(durations.length * 0.5);
        const p95Index = Math.floor(durations.length * 0.95);

        const healthData = {
          rules_summary: {
            total: rulesResult.total,
            enabled: enabledCount,
            disabled: disabledCount,
            by_outcome: byOutcome,
          },
          execution_kpi: {
            success: kpiResult.success,
            failure: kpiResult.failure,
            warning: kpiResult.warning,
            total_active_alerts: kpiResult.activeAlerts,
            total_new_alerts: kpiResult.newAlerts,
            total_recovered_alerts: kpiResult.recoveredAlerts,
            total_triggered_actions: kpiResult.triggeredActions,
            total_errored_actions: kpiResult.erroredActions,
          },
          performance: {
            avg_success_ratio: avgSuccessRatio,
            p50_p95_duration_ms:
              durations.length > 0 ? { p50: durations[p50Index], p95: durations[p95Index] } : null,
          },
          top_failing_rules: failingRules.slice(0, 10),
          gap_summary: gapsResult
            ? {
                rules_with_gaps: gapsResult.total,
                summary: gapsResult.summary,
              }
            : null,
        };

        return {
          results: [
            {
              type: ToolResultType.other,
              data: healthData,
            },
          ],
        };
      } catch (error) {
        logger.error(`rules_health tool failed: ${error.message}`);
        const limitMsg =
          'Too many execution events in the selected interval. Narrow the time range by setting interval_start and interval_end (e.g. last 1–6 hours) and try again.';
        const message = error?.message?.includes('10,000 documents')
          ? limitMsg
          : `Failed to get rules health: ${error.message}`;
        return {
          results: [
            {
              type: ToolResultType.error,
              data: { message },
            },
          ],
        };
      }
    },
  };
};
