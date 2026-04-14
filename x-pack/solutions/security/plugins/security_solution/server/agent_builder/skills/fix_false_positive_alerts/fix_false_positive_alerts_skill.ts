/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/* eslint-disable no-console */

import type { Logger } from '@kbn/core/server';
import type { IScopedClusterClient } from '@kbn/core-elasticsearch-server';
import type { KibanaRequest } from '@kbn/core-http-server';
import { ToolType } from '@kbn/agent-builder-common/tools';
import { ToolResultType } from '@kbn/agent-builder-common/tools/tool_result';
import { defineSkillType } from '@kbn/agent-builder-server/skills/type_definition';
import { z } from '@kbn/zod/v4';
import type { RuleResponse } from '../../../../common/api/detection_engine/model/rule_schema';
import {
  DEFAULT_ALERTS_INDEX,
  DEFAULT_PREVIEW_INDEX,
  DETECTION_ENGINE_RULES_PREVIEW,
} from '../../../../common/constants';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../../plugin_contract';
import { getRuleById } from '../../../lib/detection_engine/rule_management/logic/detection_rules_client/methods/get_rule_by_id';

const FALSE_POSITIVE_THRESHOLD = 10;

const RESPONSE_ONLY_FIELDS = [
  'id',
  'immutable',
  'rule_source',
  'updated_at',
  'updated_by',
  'created_at',
  'created_by',
  'revision',
  'execution_summary',
  'required_fields',
  'related_integrations',
  'setup',
  'output_index',
  'meta',
] as const;

const ruleResponseToCreateProps = (rule: RuleResponse): Record<string, unknown> => {
  const ruleObj = rule as unknown as Record<string, unknown>;
  const createProps: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(ruleObj)) {
    if (!(RESPONSE_ONLY_FIELDS as readonly string[]).includes(key) && value !== undefined) {
      createProps[key] = value;
    }
  }

  delete createProps.enabled;

  return createProps;
};

interface PreviewRunResult {
  previewId: string;
  alertCount: number;
  errors: string[];
  isAborted: boolean;
}

const runPreview = async ({
  createProps,
  timeframeEnd,
  request,
  esClient,
  spaceId,
  baseUrl,
  previewUrl,
  label,
  logger: log,
}: {
  createProps: Record<string, unknown>;
  timeframeEnd: string;
  request: KibanaRequest;
  esClient: IScopedClusterClient;
  spaceId: string;
  baseUrl: string;
  previewUrl: string;
  label: string;
  logger: Logger;
}): Promise<PreviewRunResult> => {
  const body = {
    ...createProps,
    invocationCount: 1,
    timeframeEnd,
  };
  console.log(`[${label}] Rule preview HTTP request body:`, JSON.stringify(body, null, 2));

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'kbn-xsrf': 'true',
    'elastic-api-version': '2023-10-31',
  };
  const rawHeaders = request.headers;
  if (rawHeaders.authorization) {
    headers.authorization = String(rawHeaders.authorization);
  }
  if (rawHeaders.cookie) {
    headers.cookie = String(rawHeaders.cookie);
  }

  console.log(`[${label}] Calling preview API: ${baseUrl}${previewUrl}`);
  const previewResponse = await fetch(`${baseUrl}${previewUrl}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  console.log(`[${label}] Preview API response status: ${previewResponse.status}`);

  if (!previewResponse.ok) {
    const errorText = await previewResponse.text();
    console.log(`[${label}] Preview API error body: ${errorText}`);
    console.log(
      `[${label}] ERROR: Rule preview API returned ${previewResponse.status}: ${errorText}`
    );
    throw new Error(`Rule preview failed (HTTP ${previewResponse.status}): ${errorText}`);
  }

  const previewResult = (await previewResponse.json()) as {
    previewId?: string;
    logs?: Array<{ errors: string[]; warnings: string[] }>;
    isAborted?: boolean;
  };
  console.log(`[${label}] Preview result:`, JSON.stringify(previewResult, null, 2));

  const errors = previewResult.logs?.flatMap((l) => l.errors).filter(Boolean) ?? [];

  if (!previewResult.previewId) {
    throw new Error(
      `Preview did not produce a previewId. Errors: ${
        errors.length > 0 ? errors.join('; ') : 'none'
      }`
    );
  }

  const previewIndex = `${DEFAULT_PREVIEW_INDEX}-${spaceId}`;
  const alertsQuery = {
    index: previewIndex,
    size: 1000,
    query: {
      bool: {
        filter: [{ term: { 'kibana.alert.rule.uuid': previewResult.previewId } }],
      },
    },
    track_total_hits: true,
    ignore_unavailable: true,
  };
  console.log(`[${label}] Alerts retrieval ES query:`, JSON.stringify(alertsQuery, null, 2));

  const alertsResult = await esClient.asCurrentUser.search(alertsQuery);

  const alertCount =
    typeof alertsResult.hits.total === 'number'
      ? alertsResult.hits.total
      : alertsResult.hits.total?.value ?? 0;

  console.log(`[${label}] Alert count: ${alertCount}`);

  return {
    previewId: previewResult.previewId,
    alertCount,
    errors,
    isAborted: previewResult.isAborted ?? false,
  };
};

export const createFixFalsePositiveAlertsSkill = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
) =>
  defineSkillType({
    id: 'fix-false-positive-alerts',
    name: 'fix-false-positive-alerts',
    basePath: 'skills/security/alerts/rules',
    description:
      'Detect and fix false positive security alerts: search alerts by rule ID, suggest query changes to reduce noise, ' +
      'and compare original vs modified rule preview to verify the fix reduces alert volume.',
    content: `# Fix False Positive Alerts

## When to Use This Skill

Use this skill when:
- You suspect a detection rule is generating false positive alerts
- You want to check whether a specific rule ID is producing too many alerts
- You need to identify noisy rules that require tuning
- You want to verify that a proposed rule query change actually reduces alert volume

## Workflow

### Step 1: Identify the Problem
Use 'security.fix-false-positive-alerts.search-alerts-by-rule' with the rule ID to check alert volume.
If the tool flags more than ${FALSE_POSITIVE_THRESHOLD} alerts, the rule is likely producing false positives.

### Step 2: Suggest Query Changes
Analyze the returned alerts to identify patterns (common hosts, users, processes, IPs).
Propose a modified rule query that filters out the false positive patterns — for example, adding exclusions for known-good processes or trusted hosts.

### Step 3: Compare Original vs Fixed Rule
Use 'security.fix-false-positive-alerts.compare-rule-fix' to test your suggested query.
The tool runs the detection engine preview TWICE on the same time interval:
1. First with the **original unchanged rule** to establish a baseline alert count
2. Then with the **modified query** to see how many alerts it would produce
It compares the two counts and tells you whether the fix is effective.

### Step 4: Evaluate Results
The comparison tool reports:
- **Success**: suggested query produces fewer alerts — recommend applying the change
- **No improvement**: alert count is the same or higher — suggest further refinements
- **Over-tuned**: alerts dropped to zero — warn that the query may be too aggressive

## Best Practices
- Always verify the flagged alerts manually before bulk-closing them
- Check if the alerts share common entities (hosts, users) that can be excluded
- Document any rule query changes for audit purposes
- Use the compare tool to validate changes before modifying the live rule
- After applying changes, monitor the rule for a few days to confirm the fix holds`,
    getInlineTools: () => [
      {
        id: 'security.fix-false-positive-alerts.search-alerts-by-rule',
        type: ToolType.builtin,
        description:
          'Search security alerts by detection rule ID and determine if the rule is generating false positives. ' +
          'Returns matching alerts and flags the rule as a false positive source if more than 10 alerts are found.',
        schema: z.object({
          ruleId: z
            .string()
            .describe('The detection rule ID (kibana.alert.rule.uuid) to search alerts for'),
          size: z
            .number()
            .min(1)
            .max(100)
            .default(20)
            .describe('Maximum number of alert documents to return (1-100, default 20)'),
        }),
        handler: async ({ ruleId, size }, context) => {
          try {
            const alertsIndex = `${DEFAULT_ALERTS_INDEX}-${context.spaceId}`;

            const searchQuery = {
              index: alertsIndex,
              size: Number(size),
              query: {
                bool: {
                  filter: [{ term: { 'kibana.alert.rule.uuid': String(ruleId) } }],
                },
              },
              sort: [{ '@timestamp': 'desc' }],
              track_total_hits: true,
              _source: [
                '@timestamp',
                'kibana.alert.rule.name',
                'kibana.alert.rule.uuid',
                'kibana.alert.severity',
                'kibana.alert.risk_score',
                'kibana.alert.workflow_status',
                'kibana.alert.reason',
                'host.name',
                'user.name',
                'source.ip',
                'destination.ip',
                'process.name',
                'message',
              ],
              ignore_unavailable: true,
            };
            console.log(`[search-alerts-by-rule] ES query:`, JSON.stringify(searchQuery, null, 2));

            const searchResult = await context.esClient.asCurrentUser.search(searchQuery);

            const total =
              typeof searchResult.hits.total === 'number'
                ? searchResult.hits.total
                : searchResult.hits.total?.value ?? 0;

            const hits = searchResult.hits.hits.map((hit) => ({
              _id: hit._id,
              ...(hit._source as Record<string, unknown>),
            }));

            const isFalsePositive = total > FALSE_POSITIVE_THRESHOLD;
            const ruleName =
              hits.length > 0
                ? ((hits[0] as Record<string, unknown>)['kibana.alert.rule.name'] as
                    | string
                    | undefined) ?? 'Unknown'
                : 'Unknown';

            const assessment = isFalsePositive
              ? `False Positive detected: Rule "${ruleName}" (${ruleId}) has generated ${total} alerts, exceeding the threshold of ${FALSE_POSITIVE_THRESHOLD}. This rule is likely producing false positives and should be tuned.`
              : `Rule "${ruleName}" (${ruleId}) has generated ${total} alert(s), which is within the normal threshold of ${FALSE_POSITIVE_THRESHOLD}. No false positive concern detected.`;

            return {
              results: [
                {
                  type: ToolResultType.other,
                  data: {
                    assessment,
                    isFalsePositive,
                    total,
                    threshold: FALSE_POSITIVE_THRESHOLD,
                    ruleId,
                    ruleName,
                    alerts: hits,
                  },
                },
              ],
            };
          } catch (error) {
            return {
              results: [
                {
                  type: ToolResultType.error,
                  data: {
                    message: `Failed to search alerts for rule ${ruleId}: ${
                      error instanceof Error ? error.message : String(error)
                    }`,
                  },
                },
              ],
            };
          }
        },
      },
      {
        id: 'security.fix-false-positive-alerts.compare-rule-fix',
        type: ToolType.builtin,
        description:
          'Compare a detection rule before and after a suggested query change. ' +
          'Runs the detection engine preview twice on the same time interval: once with the original rule and once with the modified query. ' +
          'Returns both alert counts and whether the suggested change reduces alert volume.',
        schema: z.object({
          ruleId: z
            .string()
            .describe('The detection rule ID (saved object ID / kibana.alert.rule.uuid)'),
          suggestedQuery: z
            .string()
            .describe(
              'The suggested replacement query string (KQL or Lucene, matching the rule language) to test against the original'
            ),
          timeframeMinutes: z
            .number()
            .min(1)
            .max(1440)
            .default(60)
            .describe(
              'How far in the past to set the preview timeframeEnd, in minutes (1-1440, default 10). The preview runs one rule interval ending at now minus this value.'
            ),
        }),
        handler: async ({ ruleId, suggestedQuery, timeframeMinutes }, context) => {
          try {
            console.log(`[compare-rule-fix] Starting comparison for rule ${ruleId}`);
            console.log(`[compare-rule-fix] Suggested query: ${suggestedQuery}`);
            console.log(`[compare-rule-fix] timeframeMinutes: ${timeframeMinutes}`);

            const [coreStart, startPlugins] = await core.getStartServices();
            const rulesClient = await startPlugins.alerting.getRulesClientWithRequest(
              context.request
            );
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

            const timeframeEnd = new Date(
              Date.now() - Number(timeframeMinutes) * 60 * 1000
            ).toISOString();
            console.log(`[compare-rule-fix] timeframeEnd: ${timeframeEnd}`);

            const { protocol, hostname, port } = coreStart.http.getServerInfo();
            const serverBasePath = coreStart.http.basePath.serverBasePath;
            const baseUrl = `${protocol}://${hostname}:${port}`;
            const previewUrl = `${serverBasePath}${DETECTION_ENGINE_RULES_PREVIEW}`;

            const originalProps = ruleResponseToCreateProps(rule);
            const modifiedProps = { ...originalProps, query: String(suggestedQuery) };

            const sharedOpts = {
              timeframeEnd,
              request: context.request,
              esClient: context.esClient,
              spaceId: context.spaceId,
              baseUrl,
              previewUrl,
              logger,
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
      },
    ],
  });
