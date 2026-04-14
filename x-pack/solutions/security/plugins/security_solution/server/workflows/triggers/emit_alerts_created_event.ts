/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FakeRawRequest } from '@kbn/core-http-server';
import { kibanaRequestFactory } from '@kbn/core-http-server-utils';
import { addSpaceIdToPath } from '@kbn/spaces-plugin/server';
import type { HttpServiceSetup, Logger } from '@kbn/core/server';
import type { WorkflowsExtensionsServerPluginStart } from '@kbn/workflows-extensions/server';
import type { SecurityAlertsCreatedEvent } from '../../../common/workflows/triggers';
import { SECURITY_ALERTS_CREATED_TRIGGER_ID } from '../../../common/workflows/triggers';

export type EmitAlertsCreatedEvent = (params: {
  spaceId: string;
  event: SecurityAlertsCreatedEvent;
}) => Promise<void>;

export const createEmitAlertsCreatedEvent = ({
  getWorkflowsExtensionsStart,
  http,
  logger,
}: {
  getWorkflowsExtensionsStart: () => Promise<WorkflowsExtensionsServerPluginStart | undefined>;
  http: HttpServiceSetup;
  logger: Logger;
}): EmitAlertsCreatedEvent => {
  return async ({ spaceId, event }) => {
    try {
      const workflowsExtensions = await getWorkflowsExtensionsStart();
      if (!workflowsExtensions) {
        return;
      }

      const path = addSpaceIdToPath('/', spaceId);
      const fakeRawRequest: FakeRawRequest = {
        headers: {},
        path,
        url: new URL(`https://fake-request${path}`),
      };
      const fakeRequest = kibanaRequestFactory(fakeRawRequest);
      http.basePath.set(fakeRequest, path);

      await workflowsExtensions.emitEvent({
        triggerId: SECURITY_ALERTS_CREATED_TRIGGER_ID,
        spaceId,
        payload: event as unknown as Record<string, unknown>,
        request: fakeRequest,
      });
    } catch (err) {
      logger.warn(
        `Failed to emit ${SECURITY_ALERTS_CREATED_TRIGGER_ID} workflow event: ${
          err instanceof Error ? err.message : String(err)
        }`
      );
    }
  };
};
