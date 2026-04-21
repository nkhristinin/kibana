/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/* eslint-disable no-console */

import { ToolType } from '@kbn/agent-builder-common/tools';
import { ToolResultType } from '@kbn/agent-builder-common/tools/tool_result';
import { z } from '@kbn/zod/v4';
import { DETECTION_ENGINE_RULES_PREVIEW } from '../../../../../common/constants';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../../../plugin_contract';
import { getRuleById } from '../../../../lib/detection_engine/rule_management/logic/detection_rules_client/methods/get_rule_by_id';
import {
  ruleResponseToCreateProps,
  parseIntervalToMinutes,
  getKibanaBaseUrl,
  runPreview,
} from '../../fix_false_positive_alerts/inline_tools/common';

export const getValidateRuleFixTool = (core: SecuritySolutionPluginCoreSetupDependencies) => ({
  id: 'security.fix-rule-errors.validate-rule-fix',
  type: ToolType.builtin,
  description:
    'Validate a proposed rule fix by running the detection engine preview with the modified rule parameters. ' +
    'Merges the proposed changes onto the current rule and runs a preview to check if the rule executes without errors. ' +
    'Unlike compare-rule-fix (which compares alert counts), this tool focuses on whether the fixed rule runs successfully.',
  schema: z.object({
    ruleId: z
      .string()
      .describe('The detection rule saved-object ID (kibana.alert.rule.uuid) to validate'),
    proposedChanges: z
      .record(z.string(), z.unknown())
      .describe(
        'A map of rule fields to change. Only include fields that need to change. ' +
          'Examples: { "query": "corrected query" }, { "index": ["fixed-index-*"] }, ' +
          '{ "query": "fixed query", "language": "kuery" }'
      ),
    timeframeMinutes: z
      .number()
      .min(1)
      .max(60)
      .default(5)
      .describe(
        'How far back to preview, in minutes (1-60, default 5). A short window is sufficient to check for errors.'
      ),
  }),
  handler: async (
    {
      ruleId,
      proposedChanges,
      timeframeMinutes,
    }: { ruleId: string; proposedChanges: Record<string, unknown>; timeframeMinutes: number },
    context: {
      request: import('@kbn/core-http-server').KibanaRequest;
      esClient: import('@kbn/core-elasticsearch-server').IScopedClusterClient;
      spaceId: string;
    }
  ) => {
    try {
      console.log(`[validate-rule-fix] Validating fix for rule ${ruleId}`);
      console.log(
        `[validate-rule-fix] Proposed changes:`,
        JSON.stringify(proposedChanges, null, 2)
      );

      // 1. Get the current rule
      const [, startPlugins] = await core.getStartServices();
      const rulesClient = await startPlugins.alerting.getRulesClientWithRequest(context.request);
      const rule = await getRuleById({ rulesClient, id: String(ruleId) });

      if (!rule) {
        return {
          results: [
            {
              type: ToolResultType.error,
              data: { message: `Rule with ID "${ruleId}" not found.` },
            },
          ],
        };
      }

      console.log(`[validate-rule-fix] Found rule "${rule.name}" (type=${rule.type})`);

      // 2. Build the modified rule props
      const originalProps = ruleResponseToCreateProps(rule);
      const modifiedProps = { ...originalProps, ...proposedChanges };

      // 3. Calculate preview parameters
      const minutes = Number(timeframeMinutes);
      const timeframeEnd = new Date().toISOString();
      const ruleInterval = (rule as unknown as Record<string, unknown>).interval as string;
      const intervalMinutes = parseIntervalToMinutes(ruleInterval || '5m');
      const invocationCount = Math.max(1, Math.ceil(minutes / intervalMinutes));

      console.log(
        `[validate-rule-fix] Preview params: timeframeEnd=${timeframeEnd}, interval=${ruleInterval}, invocationCount=${invocationCount}`
      );

      // 4. Run the preview with the fixed rule
      const { baseUrl, serverBasePath } = await getKibanaBaseUrl(core);
      const previewUrl = `${serverBasePath}${DETECTION_ENGINE_RULES_PREVIEW}`;

      const previewResult = await runPreview({
        createProps: modifiedProps,
        invocationCount,
        timeframeEnd,
        request: context.request,
        esClient: context.esClient,
        spaceId: context.spaceId,
        baseUrl,
        previewUrl,
        label: 'validate-fix',
      });

      const hasErrors = previewResult.errors.length > 0;
      const success = !hasErrors && !previewResult.isAborted;

      let verdict: string;
      if (success) {
        verdict =
          `Validation passed: the fixed rule executed successfully and produced ${previewResult.alertCount} alert(s). ` +
          `The proposed changes resolve the execution errors. Safe to apply.`;
      } else if (previewResult.isAborted) {
        verdict =
          `Validation failed: the preview was aborted. The proposed changes may cause performance issues. ` +
          `Try simplifying the query or narrowing the scope.`;
      } else {
        verdict =
          `Validation failed: the fixed rule still produces errors: ${previewResult.errors.join('; ')}. ` +
          `The proposed changes do not fully resolve the issue. Try a different approach.`;
      }

      console.log(`[validate-rule-fix] Verdict: ${verdict}`);

      return {
        results: [
          {
            type: ToolResultType.other,
            data: {
              verdict,
              success,
              alertCount: previewResult.alertCount,
              previewErrors: previewResult.errors,
              isAborted: previewResult.isAborted,
              proposedChanges,
              ruleName: rule.name,
              ruleType: rule.type,
            },
          },
        ],
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.log(`[validate-rule-fix] CAUGHT ERROR: ${errorMessage}`);
      return {
        results: [
          {
            type: ToolResultType.error,
            data: {
              message: `Failed to validate rule fix for ${ruleId}: ${errorMessage}`,
            },
          },
        ],
      };
    }
  },
});
