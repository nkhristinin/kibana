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

export const SECURITY_PREBUILT_RULES_STATUS_TOOL_ID = securityTool('prebuilt_rules_status');

const prebuiltRulesStatusSchema = z.object({});

const PREBUILT_RULES_FILTER =
  'alert.attributes.consumer: "siem" AND alert.attributes.params.immutable: true';

export const prebuiltRulesStatusTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof prebuiltRulesStatusSchema> => {
  return {
    id: SECURITY_PREBUILT_RULES_STATUS_TOOL_ID,
    type: ToolType.builtin,
    description:
      'Get the status of prebuilt (Elastic) detection rules: how many are installed, enabled vs disabled, their health breakdown, and common tags. Use to answer "are our prebuilt rules up to date?", "how many Elastic rules are installed?", "how many prebuilt rules are enabled?".',
    schema: prebuiltRulesStatusSchema,
    tags: ['security', 'detection', 'rules', 'prebuilt'],
    availability: {
      cacheMode: 'space',
      handler: async ({ request }) => {
        return getAgentBuilderResourceAvailability({ core, request, logger });
      },
    },
    handler: async (_params, { request }) => {
      try {
        const [, startPlugins] = await core.getStartServices();
        const rulesClient = await startPlugins.alerting.getRulesClientWithRequest(request);

        let page = 1;
        const perPage = 1000;
        let totalInstalled = 0;
        let enabledCount = 0;
        let disabledCount = 0;
        const byOutcome: Record<string, number> = { succeeded: 0, warning: 0, failed: 0 };
        const tagCounts = new Map<string, number>();
        const failingRules: Array<{ id: string; name: string; error: string }> = [];

        while (true) {
          const result = await rulesClient.find({
            options: {
              filter: PREBUILT_RULES_FILTER,
              perPage,
              page,
              sortField: 'name',
              sortOrder: 'asc',
            },
            excludeFromPublicApi: false,
          });

          for (const rule of result.data) {
            totalInstalled++;
            if (rule.enabled) {
              enabledCount++;
            } else {
              disabledCount++;
            }

            const outcome = rule.lastRun?.outcome ?? 'unknown';
            if (outcome in byOutcome) {
              byOutcome[outcome]++;
            }

            if (outcome === 'failed') {
              failingRules.push({
                id: rule.id,
                name: rule.name,
                error: rule.lastRun?.outcomeMsg?.join('; ') ?? 'No error message',
              });
            }

            for (const tag of rule.tags) {
              tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);
            }
          }

          if (result.data.length < perPage) break;
          page++;
        }

        const topTags = Array.from(tagCounts.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 20)
          .map(([tag, count]) => ({ tag, count }));

        return {
          results: [
            {
              type: ToolResultType.other,
              data: {
                total_installed: totalInstalled,
                enabled: enabledCount,
                disabled: disabledCount,
                by_outcome: byOutcome,
                top_tags: topTags,
                failing_rules: failingRules.slice(0, 10),
              },
            },
          ],
        };
      } catch (error) {
        logger.error(`prebuilt_rules_status tool failed: ${error.message}`);
        return {
          results: [
            {
              type: ToolResultType.error,
              data: { message: `Failed to get prebuilt rules status: ${error.message}` },
            },
          ],
        };
      }
    },
  };
};
