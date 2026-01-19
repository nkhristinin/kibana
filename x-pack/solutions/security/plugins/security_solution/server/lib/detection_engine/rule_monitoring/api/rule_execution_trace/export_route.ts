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
import { streamFactory } from '@kbn/ml-response-stream/server';

import type { SecuritySolutionPluginRouter } from '../../../../../types';
import {
  getTraceDataStreamName,
  buildTraceSearchQuery,
  getDefaultDateStart,
} from '../../logic/rule_execution_trace/search_utils';
import type { RuleExecutionTraceLogDoc } from '../../logic/rule_execution_trace/types';
import { buildSiemResponse } from '../../../routes/utils';

const ExportRouteParams = z.object({
  ruleId: z.string(),
});

const ExportRouteQuery = z.object({
  date_start: z.string().datetime().optional(),
});

const EXPORT_PAGE_SIZE = 1000;

export const exportRuleExecutionTraceRoute = (router: SecuritySolutionPluginRouter) => {
  router.versioned
    .get({
      access: 'internal',
      path: '/internal/detection_engine/rules/{ruleId}/execution/trace/export',
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
            params: buildRouteValidationWithZod(ExportRouteParams),
            query: buildRouteValidationWithZod(ExportRouteQuery),
          },
        },
      },
      async (context, request, response): Promise<IKibanaResponse> => {
        const siemResponse = buildSiemResponse(response);
        try {
          const core = await context.core;
          const spaceId = (await context.securitySolution).getSpaceId();
          const logger = (await context.securitySolution).getLogger().get('ruleExecTraceExport');

          const { ruleId } = request.params;
          const { date_start: dateStart } = request.query;
          const index = getTraceDataStreamName(spaceId);
          const dateStartIso = dateStart ?? getDefaultDateStart();

          const headersWithGzip = { ...request.headers, 'accept-encoding': 'gzip' };
          const { push, end, responseWithHeaders } = streamFactory(headersWithGzip, logger);

          const esClient = core.elasticsearch.client.asInternalUser;

          const streamDocs = async () => {
            let searchAfter: unknown[] | undefined;
            try {
              while (true) {
                const res = await esClient.search<RuleExecutionTraceLogDoc>({
                  index,
                  ...buildTraceSearchQuery({
                    ruleId,
                    dateStartIso,
                    limit: EXPORT_PAGE_SIZE,
                    searchAfter,
                  }),
                });

                const hits = res.hits.hits ?? [];
                if (!hits.length) break;

                for (const hit of hits) {
                  if (hit._source) {
                    push(hit._source);
                  }
                }

                searchAfter = hits[hits.length - 1].sort as unknown[] | undefined;
                if (!searchAfter) break;
              }
            } catch (e) {
              // Data stream doesn't exist - end with empty results
              logger.debug(`Export search failed: ${e instanceof Error ? e.message : e}`);
            }
          };

          streamDocs().finally(() => end());

          return response.ok({
            body: responseWithHeaders.body,
            headers: {
              ...responseWithHeaders.headers,
              'content-type': 'application/gzip',
              'content-disposition': `attachment; filename="rule-${ruleId}.ndjson.gz"`,
              'x-content-type-options': 'nosniff',
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
