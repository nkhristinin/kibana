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

import type { GetRuleExecutionsWithDebugLogResponse } from '../../../../../common/api/detection_engine/rule_debug';
import {
  GetRuleExecutionsWithDebugLogRequestParams,
  GET_RULE_EXECUTIONS_WITH_DEBUG_LOG,
} from '../../../../../common/api/detection_engine/rule_debug';

export const getRuleExecutionsWithDebugLog = (router: SecuritySolutionPluginRouter) => {
  router.versioned
    .get({
      access: 'internal',
      path: GET_RULE_EXECUTIONS_WITH_DEBUG_LOG,
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
            params: buildRouteValidationWithZod(GetRuleExecutionsWithDebugLogRequestParams),
          },
        },
      },
      async (
        context,
        request,
        response
      ): Promise<IKibanaResponse<GetRuleExecutionsWithDebugLogResponse>> => {
        const { ruleId } = request.params;
        const siemResponse = buildSiemResponse(response);

        try {
          const ctx = await context.resolve(['securitySolution']);
          const ruleDebugService = ctx.securitySolution.getRuleDebugService();
          const executionsIds = await ruleDebugService.getExecutionIdsByRuleId(ruleId);
          console.log(JSON.stringify(executionsIds));

          return response.ok({ body: executionsIds });
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
