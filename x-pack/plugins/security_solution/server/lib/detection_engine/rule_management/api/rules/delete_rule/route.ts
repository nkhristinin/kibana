/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { transformError } from '@kbn/securitysolution-es-utils';

import type { IKibanaResponse } from '@kbn/core/server';
import { DETECTION_ENGINE_RULES_URL } from '../../../../../../../common/constants';
import type { DeleteRuleResponse } from '../../../../../../../common/api/detection_engine/rule_management';
import {
  QueryRuleByIds,
  validateQueryRuleByIds,
} from '../../../../../../../common/api/detection_engine/rule_management';

import type { SecuritySolutionPluginRouter } from '../../../../../../types';
import { buildRouteValidation } from '../../../../../../utils/build_validation/route_validation';
import { buildSiemResponse } from '../../../../routes/utils';

import { deleteRules } from '../../../logic/crud/delete_rules';
import { readRules } from '../../../logic/crud/read_rules';
import { getIdError, transform } from '../../../utils/utils';

export const deleteRuleRoute = (router: SecuritySolutionPluginRouter) => {
  router.delete(
    {
      path: DETECTION_ENGINE_RULES_URL,
      validate: {
        query: buildRouteValidation(QueryRuleByIds),
      },
      options: {
        tags: ['access:securitySolution'],
      },
    },
    async (context, request, response): Promise<IKibanaResponse<DeleteRuleResponse>> => {
      const siemResponse = buildSiemResponse(response);
      const validationErrors = validateQueryRuleByIds(request.query);
      if (validationErrors.length) {
        return siemResponse.error({ statusCode: 400, body: validationErrors });
      }

      try {
        const { id, rule_id: ruleId } = request.query;

        const ctx = await context.resolve(['core', 'securitySolution', 'alerting']);
        const rulesClient = ctx.alerting.getRulesClient();

        const rule = await readRules({ rulesClient, id, ruleId });

        if (!rule) {
          const error = getIdError({ id, ruleId });
          return siemResponse.error({
            body: error.message,
            statusCode: error.statusCode,
          });
        }

        await deleteRules({
          ruleId: rule.id,
          rulesClient,
        });

        const transformed = transform(rule);
        if (transformed == null) {
          return siemResponse.error({ statusCode: 500, body: 'failed to transform alert' });
        } else {
          return response.ok({ body: transformed ?? {} });
        }
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
