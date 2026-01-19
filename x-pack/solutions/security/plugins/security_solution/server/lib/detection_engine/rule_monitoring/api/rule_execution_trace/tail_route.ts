/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { IKibanaResponse } from '@kbn/core/server';
import { buildRouteValidationWithZod } from '@kbn/zod-helpers';
import { RULES_API_READ } from '@kbn/security-solution-features/constants';
import { z } from '@kbn/zod';
import { transformError } from '@kbn/securitysolution-es-utils';

import type { SecuritySolutionPluginRouter } from '../../../../../types';
import {
  getTraceDataStreamName,
  searchTraceLogs,
  mapTraceDocToItem,
  getDefaultDateStart,
} from '../../logic/rule_execution_trace/search_utils';
import { buildSiemResponse } from '../../../routes/utils';

const TailRouteParams = z.object({
  ruleId: z.string(),
});

const TailRouteQuery = z.object({
  date_start: z.string().optional(),
  after_ts: z.string().optional(),
  after_seq: z.coerce.number().int().optional(),
  limit: z.coerce.number().int().min(1).max(500).default(200),
});

interface TailRouteResponseBody {
  rule_id: string;
  next_after_ts?: string;
  next_after_seq?: number;
  items: Array<{
    ts: string;
    seq: number;
    level: string;
    logger: string;
    execution_id: string;
    message_text: string;
    message?: unknown;
  }>;
}

export const tailRuleExecutionTraceRoute = (router: SecuritySolutionPluginRouter) => {
  router.versioned
    .get({
      access: 'internal',
      path: '/internal/detection_engine/rules/{ruleId}/execution/trace/tail',
      security: {
        authz: {
          requiredPrivileges: [RULES_API_READ],
        },
      },
    })
    .addVersion(
      {
        version: '1',
        validate: {
          request: {
            params: buildRouteValidationWithZod(TailRouteParams),
            query: buildRouteValidationWithZod(TailRouteQuery),
          },
        },
      },
      async (context, request, response): Promise<IKibanaResponse<TailRouteResponseBody>> => {
        const siemResponse = buildSiemResponse(response);
        try {
          const core = await context.core;
          const spaceId = (await context.securitySolution).getSpaceId();
          const { ruleId } = request.params;
          const { date_start: dateStart, after_ts: afterTs, after_seq: afterSeq, limit } =
            request.query;

          const index = getTraceDataStreamName(spaceId);
          const dateStartIso = dateStart ?? getDefaultDateStart();
          const searchAfter =
            afterTs && afterSeq !== undefined ? [afterTs, afterSeq] : undefined;

          const hits = await searchTraceLogs(
            core.elasticsearch.client.asInternalUser,
            index,
            { ruleId, dateStartIso, limit, searchAfter }
          );

          const items = hits
            .map((h) => h._source)
            .filter((s): s is NonNullable<typeof s> => Boolean(s))
            .map(mapTraceDocToItem);

          const lastHit = hits[hits.length - 1];
          const nextAfterTs = lastHit?.sort?.[0] as string | undefined;
          const nextAfterSeq = lastHit?.sort?.[1] as number | undefined;

          return response.ok({
            body: {
              rule_id: ruleId,
              ...(nextAfterTs ? { next_after_ts: nextAfterTs } : {}),
              ...(nextAfterSeq !== undefined ? { next_after_seq: nextAfterSeq } : {}),
              items,
            },
          });
        } catch (err) {
          const error = transformError(err);
          return siemResponse.error({
            body: error.message,
            statusCode: error.statusCode,
          });
        }
      }
    );
};
