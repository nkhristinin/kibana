/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export { healthRoute } from './health';
export { backgroundTaskUtilizationRoute } from './background_task_utilization';
export { metricsRoute } from './metrics';

export function queueRoute({router, getTaskStore}: {router: IRouter, getTaskStore: () => TaskStore}) {
  router.get(
    {
      path: '/api/task_manager/queue',
      validate: false,
      security: {
        authz: {
          enabled: false,
          // https://github.com/elastic/kibana/issues/136157
          reason:
            'This route is opted out from authorization. Authorization is planned but not implemented yet(breaking change).',
        },
      },
      options: {
        tags: ['access:taskManager'],
      },
    },
    async (context, request, response) => {
      try {
        const { docs } = await getTaskStore().fetch();
        return response.ok({
          body: {
            tasks: docs,
          },
        });
      } catch (err) {
        return response.customError({
          statusCode: 500,
          body: { message: err.message },
        });
      }
    }
  );
}
