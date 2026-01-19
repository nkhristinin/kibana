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
import { RuleExecutionTraceSessionStore } from '../../logic/rule_execution_trace/session_store';
import { buildSiemResponse } from '../../../routes/utils';

const ConnectRouteParams = z.object({
  ruleId: z.string(),
});

const ConnectRouteBody = z.object({
  ttl_ms: z.number().int().positive().optional(),
});

interface ConnectRouteResponseBody {
  session_id: string;
  expires_at: string;
}

const DEFAULT_TTL_MS = 30 * 60 * 1000;

export const connectRuleExecutionTraceRoute = (router: SecuritySolutionPluginRouter) => {
  router.versioned
    .post({
      access: 'internal',
      path: '/internal/detection_engine/rules/{ruleId}/execution/trace/connect',
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
            params: buildRouteValidationWithZod(ConnectRouteParams),
            body: buildRouteValidationWithZod(ConnectRouteBody),
          },
        },
      },
      async (context, request, response): Promise<IKibanaResponse<ConnectRouteResponseBody>> => {
        const siemResponse = buildSiemResponse(response);
        try {
          const core = await context.core;
          const logger = (await context.securitySolution).getLogger().get('ruleExecTraceConnect');

          const { ruleId } = request.params;
          const { ttl_ms: ttlMs } = request.body;

          // Note: We don't create the data stream here anymore.
          // The trace service installs templates at plugin start, and the writer
          // creates the per-space data stream on first write.
          // The session just marks that this rule should capture logs.

          const store = new RuleExecutionTraceSessionStore(core.savedObjects.client, logger);
          logger.info(`[CONNECT] Creating session for ruleId=${ruleId}`);
          const session = await store.upsertSession({
            ruleId,
            ttlMs: ttlMs ?? DEFAULT_TTL_MS,
          });
          logger.info(`[CONNECT] Session created: id=${session.id}, expires=${session.expiresAt}`);

          return response.ok({
            body: { session_id: session.id, expires_at: session.expiresAt },
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
