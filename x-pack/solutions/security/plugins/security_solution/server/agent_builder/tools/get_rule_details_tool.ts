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

export const SECURITY_GET_RULE_DETAILS_TOOL_ID = securityTool('get_rule_details');

const getRuleDetailsSchema = z.object({
  rule_id: z
    .string()
    .describe(
      'The rule ID (saved object ID) to fetch. This is the unique identifier returned by the find_rules tool.'
    ),
});

export const getRuleDetailsTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof getRuleDetailsSchema> => {
  return {
    id: SECURITY_GET_RULE_DETAILS_TOOL_ID,
    type: ToolType.builtin,
    description:
      'Get full configuration details for a specific detection rule including its query, index patterns, severity, risk score, schedule, exceptions, and actions. Use after find_rules to drill into a specific rule.',
    schema: getRuleDetailsSchema,
    tags: ['security', 'detection', 'rules'],
    availability: {
      cacheMode: 'space',
      handler: async ({ request }) => {
        return getAgentBuilderResourceAvailability({ core, request, logger });
      },
    },
    handler: async ({ rule_id: ruleId }, { request }) => {
      try {
        const [, startPlugins] = await core.getStartServices();
        const rulesClient = await startPlugins.alerting.getRulesClientWithRequest(request);

        const rule = await rulesClient.get({ id: ruleId });

        const ruleParams = rule.params as Record<string, unknown>;

        const details = {
          id: rule.id,
          name: rule.name,
          description: ruleParams.description ?? null,
          enabled: rule.enabled,
          type: ruleParams.type ?? rule.alertTypeId,
          severity: ruleParams.severity ?? null,
          risk_score: ruleParams.riskScore ?? null,
          tags: rule.tags,
          index_patterns: ruleParams.index ?? null,
          data_view_id: ruleParams.dataViewId ?? null,
          query: ruleParams.query ?? null,
          language: ruleParams.language ?? null,
          filters: ruleParams.filters ?? null,
          threshold: ruleParams.threshold ?? null,
          machine_learning_job_id: ruleParams.machineLearningJobId ?? null,
          anomaly_threshold: ruleParams.anomalyThreshold ?? null,
          threat_query: ruleParams.threatQuery ?? null,
          threat_mapping: ruleParams.threatMapping ?? null,
          new_terms_fields: ruleParams.newTermsFields ?? null,
          history_window_start: ruleParams.historyWindowStart ?? null,
          schedule: { interval: rule.schedule?.interval },
          from: ruleParams.from ?? null,
          to: ruleParams.to ?? null,
          threat: ruleParams.threat ?? [],
          actions: rule.actions?.map((a) => ({
            group: a.group,
            action_type_id: a.actionTypeId,
          })) ?? [],
          exceptions_list: ruleParams.exceptionsList ?? [],
          created_at: rule.createdAt?.toISOString() ?? null,
          updated_at: rule.updatedAt?.toISOString() ?? null,
          created_by: rule.createdBy,
          revision: rule.revision,
          last_outcome: rule.lastRun?.outcome ?? 'unknown',
          last_execution_date: rule.executionStatus?.lastExecutionDate?.toISOString() ?? null,
          success_ratio: rule.monitoring?.run?.calculated_metrics?.success_ratio ?? null,
        };

        return {
          results: [
            {
              type: ToolResultType.other,
              data: details,
            },
          ],
        };
      } catch (error) {
        logger.error(`get_rule_details tool failed: ${error.message}`);
        return {
          results: [
            {
              type: ToolResultType.error,
              data: { message: `Failed to get rule details: ${error.message}` },
            },
          ],
        };
      }
    },
  };
};
