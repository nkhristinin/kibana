/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/* eslint-disable no-console */

import type { Logger } from '@kbn/core/server';
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
} from './common';

export const getCompareRuleFixTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
) => ({
  id: 'security.fix-false-positive-alerts.compare-rule-fix',
  type: ToolType.builtin,
  description:
    'Compare a detection rule before and after a suggested query change. ' +
    'Runs the detection engine preview twice on the same time interval: once with the original rule and once with the modified query. ' +
    'Returns both alert counts and whether the suggested change reduces alert volume.',
  schema: z.object({
    ruleId: z.string().describe('The detection rule ID (saved object ID / kibana.alert.rule.uuid)'),
    suggestedQuery: z
      .string()
      .describe(
        'The suggested replacement query string (KQL or Lucene, matching the rule language) to test against the original'
      ),
    timeframeMinutes: z
      .number()
      .min(1)
      .max(1440)
      .default(10)
      .describe(
        'How far in the past to set the preview timeframeEnd, in minutes (1-1440, default 10). The preview runs one rule interval ending at now minus this value.'
      ),
  }),
  handler: async (
    {
      ruleId,
      suggestedQuery,
      timeframeMinutes,
    }: { ruleId: string; suggestedQuery: string; timeframeMinutes: number },
    context: {
      request: import('@kbn/core-http-server').KibanaRequest;
      esClient: import('@kbn/core-elasticsearch-server').IScopedClusterClient;
      spaceId: string;
    }
  ) => {
    try {
      console.log(`[compare-rule-fix] Starting comparison for rule ${ruleId}`);
      console.log(`[compare-rule-fix] Suggested query: ${suggestedQuery}`);
      console.log(`[compare-rule-fix] timeframeMinutes: ${timeframeMinutes}`);

      const [, startPlugins] = await core.getStartServices();
      const rulesClient = await startPlugins.alerting.getRulesClientWithRequest(context.request);
      console.log(`[compare-rule-fix] Got rulesClient`);

      const rule = await getRuleById({ rulesClient, id: String(ruleId) });
      console.log(
        `[compare-rule-fix] getRuleById result: ${
          rule ? `found "${rule.name}" (type=${rule.type})` : 'NOT FOUND'
        }`
      );

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

      const minutes = Number(timeframeMinutes);
      const timeframeEnd = new Date().toISOString();

      const ruleInterval = (rule as unknown as Record<string, unknown>).interval as string;
      const intervalMinutes = parseIntervalToMinutes(ruleInterval || '5m');
      const invocationCount = Math.max(1, Math.ceil(minutes / intervalMinutes));
      console.log(
        `[compare-rule-fix] timeframeEnd: ${timeframeEnd}, interval: ${ruleInterval}, intervalMinutes: ${intervalMinutes}, invocationCount: ${invocationCount}`
      );

      const { baseUrl, serverBasePath } = await getKibanaBaseUrl(core);
      const previewUrl = `${serverBasePath}${DETECTION_ENGINE_RULES_PREVIEW}`;

      const originalProps = ruleResponseToCreateProps(rule);
      const modifiedProps = { ...originalProps, query: String(suggestedQuery) };

      const sharedOpts = {
        invocationCount,
        timeframeEnd,
        request: context.request,
        esClient: context.esClient,
        spaceId: context.spaceId,
        baseUrl,
        previewUrl,
      };

      console.log(`[compare-rule-fix] === Running ORIGINAL rule preview ===`);
      const originalResult = await runPreview({
        ...sharedOpts,
        createProps: originalProps,
        label: 'compare-original',
      });

      console.log(`[compare-rule-fix] === Running MODIFIED rule preview ===`);
      const modifiedResult = await runPreview({
        ...sharedOpts,
        createProps: modifiedProps,
        label: 'compare-modified',
      });

      const diff = originalResult.alertCount - modifiedResult.alertCount;
      const isImproved = modifiedResult.alertCount < originalResult.alertCount;
      const isOverTuned = modifiedResult.alertCount === 0 && originalResult.alertCount > 0;

      let verdict: string;
      if (isOverTuned) {
        verdict =
          `The suggested query reduced alerts from ${originalResult.alertCount} to 0. ` +
          `This may be over-tuned — the query could be too aggressive and might miss true positives. Review carefully before applying.`;
      } else if (isImproved) {
        verdict =
          `Success: the suggested query reduced alerts from ${originalResult.alertCount} to ${modifiedResult.alertCount} ` +
          `(${diff} fewer alert(s), ${Math.round(
            (diff / originalResult.alertCount) * 100
          )}% reduction). ` +
          `The fix is effective — recommend applying the query change.`;
      } else if (diff === 0) {
        verdict =
          `No improvement: both the original and suggested query produced ${originalResult.alertCount} alert(s). ` +
          `The suggested query does not reduce noise — try a different approach.`;
      } else {
        verdict =
          `The suggested query produced MORE alerts (${modifiedResult.alertCount}) than the original (${originalResult.alertCount}). ` +
          `The change makes things worse — do not apply.`;
      }

      console.log(`[compare-rule-fix] Verdict: ${verdict}`);

      console.log(
        `[compare-rule-fix] Result: original=${originalResult.alertCount}, modified=${modifiedResult.alertCount}`
      );

      return {
        results: [
          {
            type: ToolResultType.other,
            data: {
              verdict,
              isImproved,
              isOverTuned,
              originalAlertCount: originalResult.alertCount,
              modifiedAlertCount: modifiedResult.alertCount,
              reduction: diff,
              reductionPercent:
                originalResult.alertCount > 0
                  ? Math.round((diff / originalResult.alertCount) * 100)
                  : 0,
              originalRuleName: rule.name,
              originalRuleType: rule.type,
              suggestedQuery,
              ...(originalResult.errors.length > 0 && {
                originalPreviewErrors: originalResult.errors,
              }),
              ...(modifiedResult.errors.length > 0 && {
                modifiedPreviewErrors: modifiedResult.errors,
              }),
              ...(originalResult.isAborted && {
                originalPreviewAborted: true,
              }),
              ...(modifiedResult.isAborted && {
                modifiedPreviewAborted: true,
              }),
            },
          },
        ],
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.log(`[compare-rule-fix] CAUGHT ERROR: ${errorMessage}`);
      console.log(`[compare-rule-fix] ERROR: ${errorMessage}`);
      return {
        results: [
          {
            type: ToolResultType.error,
            data: {
              message: `Failed to compare rule fix for ${ruleId}: ${errorMessage}`,
            },
          },
        ],
      };
    }
  },
});
