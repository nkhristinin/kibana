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
import { readRules } from '../../../lib/detection_engine/rule_management/logic/detection_rules_client/read_rules';
import { convertAlertingRuleToRuleResponse } from '../../../lib/detection_engine/rule_management/logic/detection_rules_client/converters/convert_alerting_rule_to_rule_response';
import { securityTool } from '../constants';
import { getAgentBuilderResourceAvailability } from '../../utils/get_agent_builder_resource_availability';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../../plugin_contract';

export const SECURITY_FIND_NOISY_RULES_TOOL_ID = securityTool('core.find_noisy_rules');

const findNoisyRulesSchema = z.object({
  timeframe_hours: z
    .number()
    .int()
    .min(1)
    .max(720)
    .default(1)
    .describe('Look-back window in hours. Defaults to 1.'),
  top_n: z
    .number()
    .int()
    .min(1)
    .max(20)
    .default(3)
    .describe('How many top rules to return, ranked by alert count. Defaults to 3.'),
});

interface NoisyRule {
  rule_id: string;
  name: string;
  severity?: string;
  enabled?: boolean;
  alert_count: number;
}

export const findNoisyRulesTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof findNoisyRulesSchema> => ({
  id: SECURITY_FIND_NOISY_RULES_TOOL_ID,
  type: ToolType.builtin,
  description: `Return the top-N detection rules by alert volume in a recent time window. Use this when the user asks which rules are noisy / firing the most / producing the most alerts. Returns rule_id, name, severity, enabled, and alert_count for each, ordered descending by alert_count.`,
  schema: findNoisyRulesSchema,
  tags: ['security', 'detection', 'alerts'],
  availability: {
    cacheMode: 'space',
    handler: async ({ request }) => getAgentBuilderResourceAvailability({ core, request, logger }),
  },
  handler: async ({ timeframe_hours: timeframeHours, top_n: topN }, { esClient, request, spaceId }) => {
    try {
      const index = `${DEFAULT_ALERTS_INDEX}-${spaceId}`;
      const response = await esClient.asCurrentUser.search({
        index,
        size: 0,
        track_total_hits: false,
        query: {
          bool: {
            filter: [
              { range: { '@timestamp': { gte: `now-${timeframeHours}h`, lte: 'now' } } },
            ],
          },
        },
        aggs: {
          by_rule: {
            terms: { field: 'kibana.alert.rule.uuid', size: topN },
          },
        },
      });

      const buckets = (response.aggregations as { by_rule?: { buckets?: Array<{ key: string; doc_count: number }> } } | undefined)
        ?.by_rule?.buckets ?? [];

      if (buckets.length === 0) {
        return {
          results: [
            {
              type: ToolResultType.other,
              data: {
                timeframe_hours: timeframeHours,
                top_n: topN,
                rules: [] as NoisyRule[],
                note: `No alerts found in the last ${timeframeHours}h.`,
              },
            },
          ],
        };
      }

      const [, startPlugins] = await core.getStartServices();
      const rulesClient = await startPlugins.alerting.getRulesClientWithRequest(request);

      const rules: NoisyRule[] = await Promise.all(
        buckets.map(async (bucket) => {
          try {
            const rule = await readRules({ rulesClient, id: bucket.key, ruleId: undefined });
            if (!rule) {
              return {
                rule_id: bucket.key,
                name: '<unknown rule — possibly deleted>',
                alert_count: bucket.doc_count,
              };
            }
            const ruleResponse = convertAlertingRuleToRuleResponse(rule);
            return {
              rule_id: bucket.key,
              name: ruleResponse.name,
              severity: ruleResponse.severity,
              enabled: ruleResponse.enabled,
              alert_count: bucket.doc_count,
            };
          } catch {
            return {
              rule_id: bucket.key,
              name: '<rule metadata unavailable>',
              alert_count: bucket.doc_count,
            };
          }
        })
      );

      return {
        results: [
          {
            type: ToolResultType.other,
            data: {
              timeframe_hours: timeframeHours,
              top_n: topN,
              rules,
            },
          },
        ],
      };
    } catch (error) {
      logger.error(`find_noisy_rules failed: ${error.message}`, error);
      return {
        results: [
          {
            type: ToolResultType.error,
            data: { message: `Failed to find noisy rules: ${error.message}` },
          },
        ],
      };
    }
  },
});
