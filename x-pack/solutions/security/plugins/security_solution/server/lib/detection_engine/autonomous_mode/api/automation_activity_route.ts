/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';
import { transformError } from '@kbn/securitysolution-es-utils';
import type { Logger } from '@kbn/core/server';
import { WORKFLOWS_EXECUTIONS_INDEX } from '@kbn/workflows-execution-engine/common';
import { WORKFLOWS_INDEX } from '@kbn/workflows-management-plugin/common';
import { INTERNAL_DETECTION_ENGINE_URL } from '../../../../../common/constants';
import type { SecuritySolutionPluginRouter } from '../../../../types';
import { buildSiemResponse } from '../../routes/utils';

export const INTERNAL_AUTOMATION_ACTIVITY_URL = `${INTERNAL_DETECTION_ENGINE_URL}/automation_activity` as const;

// Hardcoded for POC. Replace with user-facing setting later.
const AUTOMATION_ACTIVITY_TAG = 'detection-engine';

const querySchema = schema.object({
  statuses: schema.maybe(
    schema.oneOf([schema.string(), schema.arrayOf(schema.string())])
  ),
  size: schema.maybe(schema.number({ min: 1, max: 500, defaultValue: 100 })),
});

interface WorkflowHit {
  id?: string;
  name?: string;
  tags?: string[];
}

interface ExecutionHit {
  id?: string;
  workflowId?: string;
  status?: string;
  startedAt?: string;
  finishedAt?: string;
  createdAt?: string;
  createdBy?: string;
  executedBy?: string;
  context?: Record<string, unknown>;
}

const asArray = <T>(value: T | T[] | undefined): T[] =>
  value === undefined ? [] : Array.isArray(value) ? value : [value];

export const registerAutomationActivityRoute = (
  router: SecuritySolutionPluginRouter,
  logger: Logger
) => {
  router.versioned
    .get({
      path: INTERNAL_AUTOMATION_ACTIVITY_URL,
      access: 'internal',
      security: { authz: { requiredPrivileges: ['securitySolution'] } },
    })
    .addVersion(
      { version: '1', validate: { request: { query: querySchema } } },
      async (context, request, response) => {
        const siemResponse = buildSiemResponse(response);
        try {
          const core = await context.core;
          // Workflows indices (.workflows-*) are system-managed and require the
          // internal Kibana user to read. Tag/status filtering keeps results scoped.
          const esClient = core.elasticsearch.client.asInternalUser;
          const spaceId = core.savedObjects.client.getCurrentNamespace() ?? 'default';
          const statusFilter = asArray(request.query.statuses);
          const size = request.query.size ?? 100;

          // 1. One ES search: workflows with the hardcoded tag in this space -> IDs
          const workflowsRes = await esClient.search<WorkflowHit>({
            index: WORKFLOWS_INDEX,
            size: 500,
            _source: ['name', 'tags'],
            query: {
              bool: {
                filter: [
                  { term: { spaceId } },
                  { term: { tags: AUTOMATION_ACTIVITY_TAG } },
                ],
              },
            },
            ignore_unavailable: true,
          });

          const workflowIds = workflowsRes.hits.hits
            .map((h) => h._id)
            .filter((id): id is string => !!id);
          const idToName = new Map<string, string | undefined>(
            workflowsRes.hits.hits.map((h) => [h._id ?? '', h._source?.name])
          );

          logger.info(
            `[automation_activity] space=${spaceId} tag=${AUTOMATION_ACTIVITY_TAG} workflows=${workflowIds.length}`
          );

          if (workflowIds.length === 0) {
            return response.ok({ body: { results: [], total: 0 } });
          }

          // 2. One ES search: executions for those workflow IDs, sorted newest first
          const filters: Array<Record<string, unknown>> = [
            { term: { spaceId } },
            { terms: { workflowId: workflowIds } },
          ];
          if (statusFilter.length > 0) {
            filters.push({ terms: { status: statusFilter } });
          }

          const executionsRes = await esClient.search<ExecutionHit>({
            index: WORKFLOWS_EXECUTIONS_INDEX,
            size,
            sort: [{ createdAt: 'desc' }],
            track_total_hits: true,
            query: { bool: { filter: filters } },
            ignore_unavailable: true,
          });

          const total =
            typeof executionsRes.hits.total === 'number'
              ? executionsRes.hits.total
              : executionsRes.hits.total?.value ?? 0;

          const results = executionsRes.hits.hits.map((hit) => {
            const src = hit._source ?? {};
            const executionId = src.id ?? hit._id;
            const wfId = src.workflowId;
            return {
              executionId,
              workflowId: wfId,
              workflowName: wfId ? idToName.get(wfId) : undefined,
              status: src.status,
              startedAt: src.startedAt ?? src.createdAt,
              finishedAt: src.finishedAt,
              createdBy: src.createdBy ?? src.executedBy,
              ruleId: extractRuleId(src.context),
            };
          });

          return response.ok({ body: { results, total } });
        } catch (err) {
          const error = transformError(err);
          logger.error(`[automation_activity GET] ${error.message}`);
          return siemResponse.error({ statusCode: error.statusCode ?? 500, body: error.message });
        }
      }
    );
};

const extractRuleId = (ctx?: Record<string, unknown>): string | undefined => {
  if (!ctx) return undefined;
  const inputs = (ctx.inputs ?? {}) as Record<string, unknown>;
  const candidate = inputs.rule_id ?? (ctx as Record<string, unknown>).rule_id;
  return typeof candidate === 'string' ? candidate : undefined;
};
