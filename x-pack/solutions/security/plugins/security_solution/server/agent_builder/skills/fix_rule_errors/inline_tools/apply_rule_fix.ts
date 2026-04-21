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
import { DETECTION_ENGINE_RULES_URL } from '../../../../../common/constants';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../../../plugin_contract';
import {
  buildKibanaApiHeaders,
  getKibanaBaseUrl,
} from '../../fix_false_positive_alerts/inline_tools/common';

export const getApplyRuleFixTool = (core: SecuritySolutionPluginCoreSetupDependencies) => ({
  id: 'security.fix-rule-errors.apply-rule-fix',
  type: ToolType.builtin,
  description:
    'Apply a validated fix to a live detection rule by patching it via the Kibana API. ' +
    'Only call this after validate-rule-fix has confirmed the proposed changes resolve the execution errors. ' +
    'Accepts arbitrary rule field changes (query, index, language, threshold, etc.).',
  schema: z.object({
    ruleId: z
      .string()
      .describe('The detection rule saved-object ID (kibana.alert.rule.uuid) to patch'),
    proposedChanges: z
      .record(z.string(), z.unknown())
      .describe(
        'A map of rule fields to change — must match the changes validated by validate-rule-fix. ' +
          'Examples: { "query": "corrected query" }, { "index": ["fixed-index-*"] }'
      ),
  }),
  handler: async (
    { ruleId, proposedChanges }: { ruleId: string; proposedChanges: Record<string, unknown> },
    context: { request: import('@kbn/core-http-server').KibanaRequest }
  ) => {
    try {
      console.log(`[apply-rule-fix] Applying fix for rule ${ruleId}`);
      console.log(
        `[apply-rule-fix] Proposed changes:`,
        JSON.stringify(proposedChanges, null, 2)
      );

      const { baseUrl, serverBasePath } = await getKibanaBaseUrl(core);
      const patchUrl = `${baseUrl}${serverBasePath}${DETECTION_ENGINE_RULES_URL}`;
      const headers = buildKibanaApiHeaders(context.request);

      const patchBody: Record<string, unknown> = {
        id: ruleId,
        ...proposedChanges,
      };

      console.log(`[apply-rule-fix] PATCH ${patchUrl}`, JSON.stringify(patchBody, null, 2));
      const patchResponse = await fetch(patchUrl, {
        method: 'PATCH',
        headers,
        body: JSON.stringify(patchBody),
      });
      console.log(`[apply-rule-fix] PATCH response status: ${patchResponse.status}`);

      if (!patchResponse.ok) {
        const errorText = await patchResponse.text();
        console.log(`[apply-rule-fix] PATCH error body: ${errorText}`);
        throw new Error(`Rule patch failed (HTTP ${patchResponse.status}): ${errorText}`);
      }

      const updatedRule = (await patchResponse.json()) as {
        name?: string;
        type?: string;
        query?: string;
        index?: string[];
      };

      const changedFields = Object.keys(proposedChanges).join(', ');
      const summary =
        `Successfully patched rule "${updatedRule.name ?? ruleId}" ` +
        `(type: ${updatedRule.type ?? 'unknown'}). ` +
        `Changed fields: ${changedFields}.`;

      console.log(`[apply-rule-fix] ${summary}`);

      return {
        results: [
          {
            type: ToolResultType.other,
            data: {
              summary,
              ruleId,
              ruleName: updatedRule.name,
              ruleType: updatedRule.type,
              appliedChanges: proposedChanges,
            },
          },
        ],
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.log(`[apply-rule-fix] CAUGHT ERROR: ${errorMessage}`);
      return {
        results: [
          {
            type: ToolResultType.error,
            data: {
              message: `Failed to apply rule fix for ${ruleId}: ${errorMessage}`,
            },
          },
        ],
      };
    }
  },
});
