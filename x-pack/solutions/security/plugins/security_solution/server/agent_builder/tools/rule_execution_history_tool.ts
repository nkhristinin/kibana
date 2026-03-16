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
import { getAgentBuilderResourceAvailability } from '../utils/get_agent_builder_resource_availability';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../plugin_contract';
import { securityTool } from './constants';

export const SECURITY_RULE_EXECUTION_HISTORY_TOOL_ID = securityTool('rule_execution_history');

const ruleExecutionHistorySchema = z.object({
  rule_id: z.string().describe('The rule ID to get execution history for'),
  start: z
    .string()
    .optional()
    .describe('ISO date for the start of the time range (default: 24 hours ago)'),
  end: z.string().optional().describe('ISO date for the end of the time range (default: now)'),
  sort_field: z
    .enum([
      'timestamp',
      'execution_duration',
      'schedule_delay',
      'num_triggered_actions',
      'num_active_alerts',
      'num_new_alerts',
    ])
    .optional()
    .describe('Field to sort execution records by (default: timestamp)'),
  sort_order: z.enum(['asc', 'desc']).optional().describe('Sort direction (default: desc)'),
  page: z.number().int().min(1).optional().describe('Page number (default: 1)'),
  per_page: z.number().int().min(1).max(50).optional().describe('Results per page (default: 20)'),
});

export const ruleExecutionHistoryTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof ruleExecutionHistorySchema> => {
  return {
    id: SECURITY_RULE_EXECUTION_HISTORY_TOOL_ID,
    type: ToolType.builtin,
    description:
      'Get the execution history for a specific detection rule. Shows per-run details including status, duration, alert counts, action counts, schedule delay, and error messages. Use to investigate rule performance, find failures, or check if a rule is producing alerts.',
    schema: ruleExecutionHistorySchema,
    tags: ['security', 'detection', 'rules', 'monitoring', 'execution'],
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
        const sortField = params.sort_field ?? 'timestamp';
        const sortOrder = params.sort_order ?? 'desc';

        const result = await rulesClient.getExecutionLogForRule({
          id: params.rule_id,
          dateStart: params.start ?? defaultStart.toISOString(),
          dateEnd: params.end ?? now.toISOString(),
          page: params.page ?? 1,
          perPage: params.per_page ?? 20,
          sort: [{ [sortField]: { order: sortOrder } }],
        });

        const executions = result.data.map((exec) => ({
          id: exec.id,
          timestamp: exec.timestamp,
          duration_ms: exec.duration_ms,
          status: exec.status,
          message: exec.message,
          num_active_alerts: exec.num_active_alerts,
          num_new_alerts: exec.num_new_alerts,
          num_recovered_alerts: exec.num_recovered_alerts,
          num_triggered_actions: exec.num_triggered_actions,
          num_succeeded_actions: exec.num_succeeded_actions,
          num_errored_actions: exec.num_errored_actions,
          total_search_duration_ms: exec.total_search_duration_ms,
          es_search_duration_ms: exec.es_search_duration_ms,
          schedule_delay_ms: exec.schedule_delay_ms,
          timed_out: exec.timed_out,
        }));

        return {
          results: [
            {
              type: ToolResultType.other,
              data: { total: result.total, executions },
            },
          ],
        };
      } catch (error) {
        logger.error(`rule_execution_history tool failed: ${error.message}`);
        return {
          results: [
            {
              type: ToolResultType.error,
              data: { message: `Failed to get execution history: ${error.message}` },
            },
          ],
        };
      }
    },
  };
};
