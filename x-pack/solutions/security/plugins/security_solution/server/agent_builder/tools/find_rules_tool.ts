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

export const SECURITY_FIND_RULES_TOOL_ID = securityTool('find_rules');

const findRulesSchema = z.object({
  status: z
    .enum(['succeeded', 'warning', 'failed'])
    .optional()
    .describe('Filter rules by their last run outcome'),
  enabled: z.boolean().optional().describe('Filter by enabled/disabled state'),
  name: z.string().optional().describe('Search rules by name (partial match)'),
  tags: z.array(z.string()).optional().describe('Filter rules that have all of these tags'),
  sort_field: z
    .enum([
      'name',
      'updatedAt',
      'executionStatus.lastExecutionDate',
    ])
    .optional()
    .describe('Field to sort results by'),
  sort_order: z.enum(['asc', 'desc']).optional().describe('Sort direction'),
  page: z.number().int().min(1).optional().describe('Page number (default: 1)'),
  per_page: z.number().int().min(1).max(100).optional().describe('Results per page (default: 20)'),
});

const SIEM_RULE_FILTER = 'alert.attributes.consumer: "siem"';

const buildKqlFilter = (params: z.infer<typeof findRulesSchema>): string => {
  const filters: string[] = [SIEM_RULE_FILTER];

  if (params.status) {
    filters.push(`alert.attributes.lastRun.outcome: "${params.status}"`);
  }

  if (params.enabled !== undefined) {
    filters.push(`alert.attributes.enabled: ${params.enabled}`);
  }

  if (params.name) {
    filters.push(`alert.attributes.name: "${params.name}"`);
  }

  if (params.tags?.length) {
    for (const tag of params.tags) {
      filters.push(`alert.attributes.tags: "${tag}"`);
    }
  }

  return filters.join(' AND ');
};

export const findRulesTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof findRulesSchema> => {
  return {
    id: SECURITY_FIND_RULES_TOOL_ID,
    type: ToolType.builtin,
    description:
      'Search and filter security detection rules. Returns rules with their status, last execution outcome, alert counts, performance metrics, and schedule. Use to answer questions like "which rules are failing?", "show me disabled rules", "which rules are slowest?".',
    schema: findRulesSchema,
    tags: ['security', 'detection', 'rules', 'monitoring'],
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

        const filter = buildKqlFilter(params);
        const result = await rulesClient.find({
          options: {
            filter,
            sortField: params.sort_field ?? 'executionStatus.lastExecutionDate',
            sortOrder: params.sort_order ?? 'desc',
            page: params.page ?? 1,
            perPage: params.per_page ?? 20,
          },
          excludeFromPublicApi: false,
        });

        const rules = result.data.map((rule) => ({
          id: rule.id,
          name: rule.name,
          enabled: rule.enabled,
          type: rule.alertTypeId,
          last_outcome: rule.lastRun?.outcome ?? 'unknown',
          last_execution_date: rule.executionStatus?.lastExecutionDate?.toISOString() ?? null,
          last_duration_ms: rule.executionStatus?.lastDuration ?? null,
          success_ratio: rule.monitoring?.run?.calculated_metrics?.success_ratio ?? null,
          p50_duration_ms: rule.monitoring?.run?.calculated_metrics?.p50 ?? null,
          p95_duration_ms: rule.monitoring?.run?.calculated_metrics?.p95 ?? null,
          alerts_count: {
            active: rule.lastRun?.alertsCount?.active ?? 0,
            new: rule.lastRun?.alertsCount?.new ?? 0,
            recovered: rule.lastRun?.alertsCount?.recovered ?? 0,
          },
          error_message:
            rule.lastRun?.outcome === 'failed' || rule.lastRun?.outcome === 'warning'
              ? rule.lastRun?.outcomeMsg?.join('; ')
              : undefined,
          schedule_interval: rule.schedule?.interval ?? null,
          tags: rule.tags,
        }));

        return {
          results: [
            {
              type: ToolResultType.other,
              data: { total: result.total, page: result.page, per_page: result.perPage, rules },
            },
          ],
        };
      } catch (error) {
        logger.error(`find_rules tool failed: ${error.message}`);
        return {
          results: [
            {
              type: ToolResultType.error,
              data: { message: `Failed to search rules: ${error.message}` },
            },
          ],
        };
      }
    },
  };
};
