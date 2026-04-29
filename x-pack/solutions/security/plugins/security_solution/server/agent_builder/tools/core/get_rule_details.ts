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
import { readRules } from '../../../lib/detection_engine/rule_management/logic/detection_rules_client/read_rules';
import { convertAlertingRuleToRuleResponse } from '../../../lib/detection_engine/rule_management/logic/detection_rules_client/converters/convert_alerting_rule_to_rule_response';
import { securityTool } from '../constants';
import { getAgentBuilderResourceAvailability } from '../../utils/get_agent_builder_resource_availability';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../../plugin_contract';

export const SECURITY_GET_RULE_DETAILS_TOOL_ID = securityTool('core.get_rule_details');

const getRuleDetailsSchema = z.object({
  rule_id: z
    .string()
    .describe(
      'The saved-object id of the detection rule (the `id` field on the rule, NOT `rule_id`).'
    ),
});

export const getRuleDetailsTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof getRuleDetailsSchema> => ({
  id: SECURITY_GET_RULE_DETAILS_TOOL_ID,
  type: ToolType.builtin,
  description: `Fetch the full JSON of a detection rule by its saved-object id. Returns name, description, query, language, index, tags, severity, risk_score, threat, interval, from, enabled, and all other rule fields.`,
  schema: getRuleDetailsSchema,
  tags: ['security', 'detection', 'rule'],
  availability: {
    cacheMode: 'space',
    handler: async ({ request }) => getAgentBuilderResourceAvailability({ core, request, logger }),
  },
  handler: async ({ rule_id: ruleId }, { request }) => {
    try {
      const [, startPlugins] = await core.getStartServices();
      const rulesClient = await startPlugins.alerting.getRulesClientWithRequest(request);
      const rule = await readRules({ rulesClient, id: ruleId, ruleId: undefined });
      if (!rule) {
        return {
          results: [
            {
              type: ToolResultType.error,
              data: { message: `Rule not found: ${ruleId}` },
            },
          ],
        };
      }
      const ruleResponse = convertAlertingRuleToRuleResponse(rule);
      return {
        results: [
          {
            type: ToolResultType.other,
            data: { rule: ruleResponse },
          },
        ],
      };
    } catch (error) {
      logger.error(`get_rule_details failed: ${error.message}`, error);
      return {
        results: [
          {
            type: ToolResultType.error,
            data: { message: `Failed to fetch rule: ${error.message}` },
          },
        ],
      };
    }
  },
});
