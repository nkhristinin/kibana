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
import { convertPrebuiltRuleAssetToRuleResponse } from '../../../lib/detection_engine/rule_management/logic/detection_rules_client/converters/convert_prebuilt_rule_asset_to_rule_response';
import { createPrebuiltRuleAssetsClient } from '../../../lib/detection_engine/prebuilt_rules/logic/rule_assets/prebuilt_rule_assets_client';
import { createPrebuiltRuleObjectsClient } from '../../../lib/detection_engine/prebuilt_rules/logic/rule_objects/prebuilt_rule_objects_client';
import { securityTool } from '../constants';
import { getAgentBuilderResourceAvailability } from '../../utils/get_agent_builder_resource_availability';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../../plugin_contract';

export const SECURITY_REVIEW_PREBUILT_RULES_TO_INSTALL_TOOL_ID = securityTool(
  'core.review_prebuilt_rules_to_install'
);

const reviewPrebuiltRulesToInstallSchema = z.object({
  tags: z
    .array(z.string())
    .optional()
    .describe('Optional tags to match against prebuilt rule tags.'),
  names: z
    .array(z.string())
    .optional()
    .describe('Optional name fragments or exact names to match against prebuilt rule names.'),
  limit: z
    .number()
    .int()
    .min(1)
    .max(20)
    .default(10)
    .describe('Maximum number of candidate rules to return.'),
});

export const reviewPrebuiltRulesToInstallTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof reviewPrebuiltRulesToInstallSchema> => ({
  id: SECURITY_REVIEW_PREBUILT_RULES_TO_INSTALL_TOOL_ID,
  type: ToolType.builtin,
  description:
    'List installable prebuilt detection rules, optionally filtered by tags or names. This is a lightweight reader intended for skills that want to propose rule installation from chat.',
  schema: reviewPrebuiltRulesToInstallSchema,
  tags: ['security', 'prebuilt-rules', 'install'],
  availability: {
    cacheMode: 'space',
    handler: async ({ request }) => getAgentBuilderResourceAvailability({ core, request, logger }),
  },
  handler: async ({ tags = [], names = [], limit }, { request }) => {
    try {
      const [coreStart, startPlugins] = await core.getStartServices();
      const soClient = coreStart.savedObjects.getScopedClient(request);
      const rulesClient = await startPlugins.alerting.getRulesClientWithRequest(request);
      const ruleAssetsClient = createPrebuiltRuleAssetsClient(soClient);
      const ruleObjectsClient = createPrebuiltRuleObjectsClient(rulesClient);

      const installedVersions = await ruleObjectsClient.fetchInstalledRuleVersions();
      const installedRuleIds = new Set(installedVersions.map((rule) => rule.rule_id));
      const filter =
        tags.length > 0 || names.length > 0
          ? {
              fields: {
                ...(names.length > 0 ? { name: { include: { values: names } } } : {}),
                ...(tags.length > 0 ? { tags: { include: { values: tags } } } : {}),
              },
            }
          : undefined;

      const latestVersions = await ruleAssetsClient.fetchLatestVersions({ filter });
      const installableVersions = latestVersions
        .filter((rule) => !installedRuleIds.has(rule.rule_id))
        .slice(0, limit);
      const assets = await ruleAssetsClient.fetchAssetsByVersion(installableVersions);

      const rules = assets.map((asset) => {
        const rule = convertPrebuiltRuleAssetToRuleResponse(asset);
        return {
          rule_id: rule.rule_id,
          version: rule.version,
          name: rule.name,
          description: rule.description,
          severity: rule.severity,
          tags: rule.tags,
          mitre: rule.threat?.map((threat) => threat.tactic.name),
        };
      });

      return {
        results: [
          {
            type: ToolResultType.other,
            data: {
              total_candidates: rules.length,
              rules,
            },
          },
        ],
      };
    } catch (error) {
      logger.error(`review_prebuilt_rules_to_install failed: ${error.message}`, error);
      return {
        results: [
          {
            type: ToolResultType.error,
            data: {
              message: `Failed to review installable prebuilt rules: ${error.message}`,
            },
          },
        ],
      };
    }
  },
});
