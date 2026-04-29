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

export const SECURITY_SEARCH_ALERTS_BY_RULE_TOOL_ID = securityTool('core.search_alerts_by_rule');

const searchAlertsByRuleSchema = z.object({
  rule_id: z
    .string()
    .describe('The rule saved-object id (matches `kibana.alert.rule.uuid` on alerts).'),
  size: z
    .number()
    .int()
    .min(1)
    .max(100)
    .default(20)
    .describe('Maximum number of alert documents to return.'),
  timeframe_hours: z
    .number()
    .int()
    .min(1)
    .max(720)
    .default(24)
    .describe('Look-back window in hours. Defaults to last 24 hours.'),
});

const SOURCE_FIELDS = [
  '@timestamp',
  'kibana.alert.rule.name',
  'kibana.alert.rule.uuid',
  'kibana.alert.severity',
  'kibana.alert.risk_score',
  'host.name',
  'user.name',
  'process.name',
  'process.parent.name',
  'process.command_line',
  'source.ip',
  'destination.ip',
  'event.action',
  'event.category',
];

export const searchAlertsByRuleTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof searchAlertsByRuleSchema> => ({
  id: SECURITY_SEARCH_ALERTS_BY_RULE_TOOL_ID,
  type: ToolType.builtin,
  description: `Fetch a sample of recent alerts produced by a specific detection rule. Returns the most recent alert documents (sorted by @timestamp desc) and the total count for the time window. Use this to see what the rule is currently producing and decide whether the volume is elevated.`,
  schema: searchAlertsByRuleSchema,
  tags: ['security', 'detection', 'alerts'],
  availability: {
    cacheMode: 'space',
    handler: async ({ request }) => getAgentBuilderResourceAvailability({ core, request, logger }),
  },
  handler: async (
    { rule_id: ruleId, size, timeframe_hours: timeframeHours },
    { esClient, spaceId }
  ) => {
    try {
      const index = `${DEFAULT_ALERTS_INDEX}-${spaceId}`;
      const response = await esClient.asCurrentUser.search({
        index,
        size,
        sort: [{ '@timestamp': { order: 'desc' } }],
        track_total_hits: true,
        _source: SOURCE_FIELDS,
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
      });

      const total =
        typeof response.hits.total === 'number'
          ? response.hits.total
          : response.hits.total?.value ?? 0;

      return {
        results: [
          {
            type: ToolResultType.other,
            data: {
              rule_id: ruleId,
              timeframe_hours: timeframeHours,
              total,
              alerts: response.hits.hits.map((hit) => ({
                _id: hit._id,
                ...(typeof hit._source === 'object' && hit._source !== null ? hit._source : {}),
              })),
            },
          },
        ],
      };
    } catch (error) {
      logger.error(`search_alerts_by_rule failed: ${error.message}`, error);
      return {
        results: [
          {
            type: ToolResultType.error,
            data: { message: `Failed to search alerts: ${error.message}` },
          },
        ],
      };
    }
  },
});
