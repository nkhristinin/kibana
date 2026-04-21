/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { CoreSetup } from '@kbn/core/server';
import { createServerStepDefinition } from '@kbn/workflows-extensions/server';
import { getAutonomousModeStepCommonDefinition } from '../../../common/workflows/steps';
import { getAutonomousMode } from '../../lib/detection_engine/autonomous_mode/saved_object';

export const getGetAutonomousModeStepDefinition = (getStartServices: CoreSetup['getStartServices']) =>
  createServerStepDefinition({
    ...getAutonomousModeStepCommonDefinition,
    handler: async (context) => {
      try {
        const [coreStart] = await getStartServices();
        const request = context.contextManager.getFakeRequest();
        const soClient = coreStart.savedObjects.getScopedClient(request);
        const mode = await getAutonomousMode(soClient);
        context.logger.info(`Autonomous mode read: ${mode}`);
        return { output: { mode } };
      } catch (error) {
        context.logger.error(
          'Failed to read autonomous mode',
          error instanceof Error ? error : new Error(String(error))
        );
        return {
          error: new Error(
            error instanceof Error ? error.message : 'Failed to read autonomous mode'
          ),
        };
      }
    },
  });
