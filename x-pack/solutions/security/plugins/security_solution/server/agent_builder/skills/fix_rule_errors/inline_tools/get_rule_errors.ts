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
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../../../plugin_contract';
import { getRuleById } from '../../../../lib/detection_engine/rule_management/logic/detection_rules_client/methods/get_rule_by_id';
import { classifyError, isFixableError } from './common';

const EVENT_LOG_INDEX = '.kibana-event-log-*';

export const getGetRuleErrorsTool = (core: SecuritySolutionPluginCoreSetupDependencies) => ({
  id: 'security.fix-rule-errors.get-rule-errors',
  type: ToolType.builtin,
  description:
    'Fetch a detection rule definition and its recent execution errors. ' +
    'Returns the full rule configuration, recent error messages, failure count, and an error classification ' +
    'to help diagnose and fix the issue.',
  schema: z.object({
    ruleId: z
      .string()
      .describe('The detection rule saved-object ID (kibana.alert.rule.uuid) to inspect'),
    timeRangeMinutes: z
      .number()
      .min(1)
      .max(1440)
      .default(60)
      .describe(
        'How far back to look for execution errors, in minutes (1-1440, default 60). ' +
          'The tool fetches execution results within this window.'
      ),
  }),
  handler: async (
    { ruleId, timeRangeMinutes }: { ruleId: string; timeRangeMinutes: number },
    context: {
      request: import('@kbn/core-http-server').KibanaRequest;
      esClient: import('@kbn/core-elasticsearch-server').IScopedClusterClient;
      spaceId: string;
    }
  ) => {
    try {
      console.log(`[get-rule-errors] Fetching errors for rule ${ruleId}`);

      // 1. Get the rule definition via rulesClient (direct, no HTTP)
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

      console.log(`[get-rule-errors] Found rule "${rule.name}" (type=${rule.type})`);

      // 2. Query the event log directly via ES client for failed executions
      const now = new Date();
      const from = new Date(now.getTime() - timeRangeMinutes * 60 * 1000);

      const eventLogQuery = {
        index: EVENT_LOG_INDEX,
        size: 10,
        query: {
          bool: {
            must: [
              {
                nested: {
                  path: 'kibana.saved_objects',
                  query: {
                    bool: {
                      must: [
                        { term: { 'kibana.saved_objects.rel': 'primary' } },
                        { term: { 'kibana.saved_objects.type': 'alert' } },
                        { term: { 'kibana.saved_objects.id': ruleId } },
                      ],
                    },
                  },
                },
              },
              { term: { 'event.provider': 'alerting' } },
              { term: { 'event.action': 'execute' } },
              { term: { 'event.outcome': 'failure' } },
              {
                range: {
                  '@timestamp': {
                    gte: from.toISOString(),
                    lte: now.toISOString(),
                  },
                },
              },
            ],
          },
        },
        sort: [{ 'event.start': { order: 'desc' as const } }],
        track_total_hits: true,
        _source: ['event.start', 'error.message', 'message', 'kibana.alert.rule.execution.uuid'],
        ignore_unavailable: true,
      };

      console.log(
        `[get-rule-errors] Event log query:`,
        JSON.stringify(eventLogQuery, null, 2)
      );

      const eventLogResult = await context.esClient.asInternalUser.search(eventLogQuery);

      const totalFailures =
        typeof eventLogResult.hits.total === 'number'
          ? eventLogResult.hits.total
          : eventLogResult.hits.total?.value ?? 0;

      console.log(`[get-rule-errors] Total failures: ${totalFailures}`);

      // 3. Extract error messages from event log hits
      const errorMessages = eventLogResult.hits.hits
        .map((hit) => {
          const source = hit._source as Record<string, unknown> | undefined;
          const errorObj = source?.error as Record<string, unknown> | undefined;
          return (errorObj?.message as string) ?? (source?.message as string) ?? null;
        })
        .filter((msg): msg is string => msg != null);

      const uniqueErrors = [...new Set(errorMessages)];
      const primaryError = uniqueErrors[0] ?? 'No error message available';
      const errorCategory = classifyError(primaryError);
      const fixable = isFixableError(errorCategory);

      // 4. Build a concise rule summary (exclude large fields)
      const ruleSummary = {
        id: rule.id,
        name: rule.name,
        type: rule.type,
        enabled: rule.enabled,
        query: (rule as unknown as Record<string, unknown>).query,
        language: (rule as unknown as Record<string, unknown>).language,
        index: (rule as unknown as Record<string, unknown>).index,
        data_view_id: (rule as unknown as Record<string, unknown>).data_view_id,
        filters: (rule as unknown as Record<string, unknown>).filters,
        interval: (rule as unknown as Record<string, unknown>).interval,
        from: (rule as unknown as Record<string, unknown>).from,
        to: (rule as unknown as Record<string, unknown>).to,
        threshold: (rule as unknown as Record<string, unknown>).threshold,
        machine_learning_job_id: (rule as unknown as Record<string, unknown>)
          .machine_learning_job_id,
        anomaly_threshold: (rule as unknown as Record<string, unknown>).anomaly_threshold,
        threat_index: (rule as unknown as Record<string, unknown>).threat_index,
        threat_query: (rule as unknown as Record<string, unknown>).threat_query,
        threat_mapping: (rule as unknown as Record<string, unknown>).threat_mapping,
        new_terms_fields: (rule as unknown as Record<string, unknown>).new_terms_fields,
      };

      const recentFailures = eventLogResult.hits.hits.slice(0, 5).map((hit) => {
        const source = hit._source as Record<string, unknown> | undefined;
        const eventObj = source?.event as Record<string, unknown> | undefined;
        const errorObj = source?.error as Record<string, unknown> | undefined;
        return {
          executionStart: eventObj?.start as string | undefined,
          message: (errorObj?.message as string) ?? (source?.message as string) ?? null,
        };
      });

      const assessment =
        `Rule "${rule.name}" (${rule.type}) has ${totalFailures} failure(s) in the last ${timeRangeMinutes} minutes. ` +
        `Error category: ${errorCategory}. ` +
        (fixable
          ? `This error type is potentially auto-fixable.`
          : `This error type is typically a system/infrastructure issue and may not be auto-fixable.`);

      console.log(`[get-rule-errors] Assessment: ${assessment}`);

      return {
        results: [
          {
            type: ToolResultType.other,
            data: {
              assessment,
              rule: ruleSummary,
              failureCount: totalFailures,
              errorCategory,
              isFixable: fixable,
              errors: uniqueErrors,
              recentFailures,
            },
          },
        ],
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.log(`[get-rule-errors] CAUGHT ERROR: ${errorMessage}`);
      return {
        results: [
          {
            type: ToolResultType.error,
            data: {
              message: `Failed to fetch rule errors for ${ruleId}: ${errorMessage}`,
            },
          },
        ],
      };
    }
  },
});
