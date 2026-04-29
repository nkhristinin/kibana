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

export const SECURITY_PREVIEW_RULE_TOOL_ID = securityTool('core.preview_rule');

// Stage 1 MVP: lightweight simulator. Counts how many of the rule's already-produced
// alerts in the look-back window would survive a proposed exclusion filter. This
// gives the agent a real, quantitative signal to reason over without depending on
// the full detection-engine preview infrastructure. Stage 2 will swap this out for
// a true preview that re-runs the rule against live source data.

const exclusionSchema = z.object({
  field: z
    .string()
    .describe(
      'Alert field to exclude on, e.g. `process.parent.name`, `user.name`, `host.name`, `process.name`.'
    ),
  values: z
    .array(z.string())
    .min(1)
    .describe(
      'Values on `field` to exclude. An alert matches if its value for `field` is in this list.'
    ),
});

const previewRuleSchema = z.object({
  rule_id: z.string().describe('The rule saved-object id.'),
  exclusions: z
    .array(exclusionSchema)
    .min(1)
    .describe(
      'List of exclusion filters to evaluate. An alert is considered filtered-out if it matches ANY of the exclusions.'
    ),
  timeframe_hours: z.number().int().min(1).max(720).default(24),
});

export const previewRuleTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof previewRuleSchema> => ({
  id: SECURITY_PREVIEW_RULE_TOOL_ID,
  type: ToolType.builtin,
  description: `Simulate how much a proposed exclusion would reduce a rule's alert volume, by counting the rule's recent alerts before and after applying the exclusion filter to the existing alerts index. Returns original count, surviving count, reduction, and reduction percentage. MUST be called before proposing a query change to the user, to verify the change actually reduces noise without dropping volume to zero.`,
  schema: previewRuleSchema,
  tags: ['security', 'detection', 'preview'],
  availability: {
    cacheMode: 'space',
    handler: async ({ request }) => getAgentBuilderResourceAvailability({ core, request, logger }),
  },
  handler: async (
    { rule_id: ruleId, exclusions, timeframe_hours: timeframeHours },
    { esClient, spaceId }
  ) => {
    try {
      const index = `${DEFAULT_ALERTS_INDEX}-${spaceId}`;
      const baseFilter = [
        { term: { 'kibana.alert.rule.uuid': ruleId } },
        {
          range: {
            '@timestamp': { gte: `now-${timeframeHours}h`, lte: 'now' },
          },
        },
      ];

      const exclusionShoulds = exclusions.map((ex) => ({
        terms: { [ex.field]: ex.values },
      }));

      const [originalResp, survivingResp] = await Promise.all([
        esClient.asCurrentUser.search({
          index,
          size: 0,
          track_total_hits: true,
          query: { bool: { filter: baseFilter } },
        }),
        esClient.asCurrentUser.search({
          index,
          size: 0,
          track_total_hits: true,
          query: {
            bool: {
              filter: baseFilter,
              must_not: [
                {
                  bool: {
                    should: exclusionShoulds,
                    minimum_should_match: 1,
                  },
                },
              ],
            },
          },
        }),
      ]);

      const asCount = (v: unknown) =>
        typeof v === 'number' ? v : (v as { value?: number })?.value ?? 0;
      const originalCount = asCount(originalResp.hits.total);
      const survivingCount = asCount(survivingResp.hits.total);
      const reduction = originalCount - survivingCount;
      const reductionPercent =
        originalCount > 0 ? Math.round((reduction / originalCount) * 1000) / 10 : 0;

      const isImproved = reduction > 0;
      const isOverTuned = originalCount > 0 && survivingCount === 0;
      let verdict: string;
      if (originalCount === 0) {
        verdict = 'No alerts in the window — cannot evaluate.';
      } else if (!isImproved) {
        verdict = 'No improvement — exclusion did not filter any alerts.';
      } else if (isOverTuned) {
        verdict =
          'Over-tuned — exclusion removes ALL alerts. Likely too broad; consider narrower exclusion or a different field.';
      } else {
        verdict = `Would reduce alerts from ${originalCount} to ${survivingCount} (${reductionPercent}% reduction).`;
      }

      return {
        results: [
          {
            type: ToolResultType.other,
            data: {
              rule_id: ruleId,
              timeframe_hours: timeframeHours,
              exclusions,
              original_count: originalCount,
              surviving_count: survivingCount,
              reduction,
              reduction_percent: reductionPercent,
              is_improved: isImproved,
              is_over_tuned: isOverTuned,
              verdict,
              simulation_note:
                'This is a simulation over the existing alerts index — not a full rule preview. Stage 2 upgrades to real preview.',
            },
          },
        ],
      };
    } catch (error) {
      logger.error(`preview_rule failed: ${error.message}`, error);
      return {
        results: [
          {
            type: ToolResultType.error,
            data: { message: `Failed to simulate rule preview: ${error.message}` },
          },
        ],
      };
    }
  },
});
