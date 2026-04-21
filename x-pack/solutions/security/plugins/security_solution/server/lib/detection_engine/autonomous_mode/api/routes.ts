/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';
import { transformError } from '@kbn/securitysolution-es-utils';
import type { Logger } from '@kbn/core/server';
import { INTERNAL_AUTONOMOUS_MODE_URL } from '../../../../../common/constants';
import type { SecuritySolutionPluginRouter } from '../../../../types';
import { buildSiemResponse } from '../../routes/utils';
import { getAutonomousModeSettings, setAutonomousModeSettings } from '../saved_object';

const bodySchema = schema.object({
  mode: schema.maybe(schema.oneOf([schema.literal('auto'), schema.literal('suggest')])),
  monitoredWorkflowIds: schema.maybe(schema.arrayOf(schema.string())),
});

export const registerAutonomousModeRoutes = (
  router: SecuritySolutionPluginRouter,
  logger: Logger
) => {
  router.versioned
    .get({
      path: INTERNAL_AUTONOMOUS_MODE_URL,
      access: 'internal',
      security: { authz: { requiredPrivileges: ['securitySolution'] } },
    })
    .addVersion({ version: '1', validate: false }, async (context, request, response) => {
      const siemResponse = buildSiemResponse(response);
      try {
        const soClient = (await context.core).savedObjects.client;
        const settings = await getAutonomousModeSettings(soClient);
        return response.ok({ body: settings });
      } catch (err) {
        const error = transformError(err);
        logger.error(`[autonomous_mode GET] ${error.message}`);
        return siemResponse.error({ statusCode: error.statusCode ?? 500, body: error.message });
      }
    });

  router.versioned
    .put({
      path: INTERNAL_AUTONOMOUS_MODE_URL,
      access: 'internal',
      security: { authz: { requiredPrivileges: ['securitySolution'] } },
    })
    .addVersion(
      { version: '1', validate: { request: { body: bodySchema } } },
      async (context, request, response) => {
        const siemResponse = buildSiemResponse(response);
        try {
          const soClient = (await context.core).savedObjects.client;
          const settings = await setAutonomousModeSettings(soClient, request.body);
          return response.ok({ body: settings });
        } catch (err) {
          const error = transformError(err);
          logger.error(`[autonomous_mode PUT] ${error.message}`);
          return siemResponse.error({ statusCode: error.statusCode ?? 500, body: error.message });
        }
      }
    );
};
