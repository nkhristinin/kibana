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

export const SECURITY_RULE_GAPS_TOOL_ID = securityTool('rule_gaps');

const ruleGapsSchema = z.object({
  rule_id: z
    .string()
    .optional()
    .describe(
      'If provided, show gaps for this specific rule. If omitted, show which rules have gaps.'
    ),
  start: z
    .string()
    .optional()
    .describe('ISO date for the start of the time range (default: 7 days ago)'),
  end: z.string().optional().describe('ISO date for the end of the time range (default: now)'),
  statuses: z
    .array(z.enum(['unfilled', 'partially_filled', 'filled']))
    .optional()
    .describe('Filter gaps by fill status'),
  page: z.number().int().min(1).optional().describe('Page number (default: 1)'),
  per_page: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .describe('Results per page (default: 20)'),
});

export const ruleGapsTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof ruleGapsSchema> => {
  return {
    id: SECURITY_RULE_GAPS_TOOL_ID,
    type: ToolType.builtin,
    description:
      'Find detection rule coverage gaps. Without a rule_id, returns which rules have gaps and a summary of total unfilled/filled durations. With a rule_id, returns individual gaps for that rule with their status, time range, and fill progress.',
    schema: ruleGapsSchema,
    tags: ['security', 'detection', 'rules', 'gaps', 'monitoring'],
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
        const defaultStart = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        const start = params.start ?? defaultStart.toISOString();
        const end = params.end ?? now.toISOString();

        if (params.rule_id) {
          const result = await rulesClient.findGaps({
            ruleId: params.rule_id,
            start,
            end,
            page: params.page ?? 1,
            perPage: params.per_page ?? 20,
            statuses: params.statuses,
            sortField: '@timestamp',
            sortOrder: 'desc',
          });

          const gaps = result.data.map((gap) => ({
            id: gap.id,
            status: gap.status,
            range: gap.range,
            total_gap_duration_ms: gap.totalGapDurationMs,
            filled_duration_ms: gap.filledDurationMs,
            unfilled_duration_ms: gap.unfilledDurationMs,
            in_progress_duration_ms: gap.inProgressDurationMs,
          }));

          return {
            results: [
              {
                type: ToolResultType.other,
                data: {
                  rule_id: params.rule_id,
                  total: result.total,
                  page: result.page,
                  per_page: result.perPage,
                  gaps,
                },
              },
            ],
          };
        }

        const result = await rulesClient.getRuleIdsWithGaps({
          start,
          end,
          statuses: params.statuses,
        });

        return {
          results: [
            {
              type: ToolResultType.other,
              data: {
                total_rules_with_gaps: result.total,
                rule_ids: result.ruleIds,
                summary: result.summary,
              },
            },
          ],
        };
      } catch (error) {
        logger.error(`rule_gaps tool failed: ${error.message}`);
        return {
          results: [
            {
              type: ToolResultType.error,
              data: { message: `Failed to get gap information: ${error.message}` },
            },
          ],
        };
      }
    },
  };
};
