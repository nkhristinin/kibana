/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { IKibanaResponse } from '@kbn/core/server';
import { transformError } from '@kbn/securitysolution-es-utils';
import { buildRouteValidationWithZod } from '@kbn/zod-helpers';
import type { SecuritySolutionPluginRouter } from '../../../../types';
import { buildSiemResponse } from '../../routes/utils';

import type { GetRuleDebugLogByExecutionIdResponse } from '../../../../../common/api/detection_engine/rule_debug';
import {
  GetRuleDebugLogByExecutionIdRequestParams,
  GetRuleDebugLogByExecutionIdRequestQuery,
  GET_RULE_DEBUGE_LOG_BY_EXECUTION_ID,
} from '../../../../../common/api/detection_engine/rule_debug';

export const getRuleDebugLogByExecutionId = (router: SecuritySolutionPluginRouter) => {
  router.versioned
    .get({
      access: 'internal',
      path: GET_RULE_DEBUGE_LOG_BY_EXECUTION_ID,
      security: {
        authz: {
          requiredPrivileges: ['securitySolution'],
        },
      },
    })
    .addVersion(
      {
        version: '1',
        validate: {
          request: {
            params: buildRouteValidationWithZod(GetRuleDebugLogByExecutionIdRequestParams),
            query: buildRouteValidationWithZod(GetRuleDebugLogByExecutionIdRequestQuery),
          },
        },
      },
      async (
        context,
        request,
        response
      ): Promise<IKibanaResponse<GetRuleDebugLogByExecutionIdResponse>> => {
        const { ruleId, executionId } = request.params;
        const { page = 0, per_page = 10 } = request.query;
        const siemResponse = buildSiemResponse(response);

        try {
          const ctx = await context.resolve(['securitySolution']);
          const ruleDebugService = ctx.securitySolution.getRuleDebugService();
          const ruleDebugInfo = await ruleDebugService.getMessagesByExecutionId(
            ruleId,
            executionId,
            page,
            per_page
          );
          console.log(JSON.stringify(ruleDebugInfo));
          // const result = ruleDebugInfo.reduce((acc, item) => {
          //   acc[item.executionId] = item.log;
          //   return acc;
          // }, {} as Record<string, Array<{ message: string; '@timestamp': Date }>>);

          return response.ok({ body: ruleDebugInfo });
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
