/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { TypeOf } from '@kbn/config-schema';
import type { Logger, RequestHandler } from '@kbn/core/server';
import type { MetadataListResponse } from '../../../../common/endpoint/types';
import { errorHandler } from '../error_handler';
import type { SecuritySolutionRequestHandlerContext } from '../../../types';

import type { EndpointAppContext } from '../../types';
import type {
  GetMetadataListRequestQuery,
  GetMetadataRequestSchema,
} from '../../../../common/api/endpoint';
import {
  ENDPOINT_DEFAULT_PAGE,
  ENDPOINT_DEFAULT_PAGE_SIZE,
  METADATA_TRANSFORMS_PATTERN,
} from '../../../../common/endpoint/constants';

export const getLogger = (endpointAppContext: EndpointAppContext): Logger => {
  return endpointAppContext.logFactory.get('metadata');
};

export function getMetadataListRequestHandler(
  endpointAppContext: EndpointAppContext,
  logger: Logger
): RequestHandler<
  unknown,
  GetMetadataListRequestQuery,
  unknown,
  SecuritySolutionRequestHandlerContext
> {
  return async (context, request, response) => {
    const endpointMetadataService = endpointAppContext.service.getEndpointMetadataService();
    const fleetServices = endpointAppContext.service.getInternalFleetServices();
    const esClient = (await context.core).elasticsearch.client.asInternalUser;
    const soClient = (await context.core).savedObjects.client;

    try {
      const { data, total } = await endpointMetadataService.getHostMetadataList(
        esClient,
        soClient,
        fleetServices,
        request.query
      );

      const body: MetadataListResponse = {
        data,
        total,
        page: request.query.page || ENDPOINT_DEFAULT_PAGE,
        pageSize: request.query.pageSize || ENDPOINT_DEFAULT_PAGE_SIZE,
      };

      return response.ok({ body });
    } catch (error) {
      return errorHandler(logger, response, error);
    }
  };
}

export const getMetadataRequestHandler = function (
  endpointAppContext: EndpointAppContext,
  logger: Logger
): RequestHandler<
  TypeOf<typeof GetMetadataRequestSchema.params>,
  unknown,
  unknown,
  SecuritySolutionRequestHandlerContext
> {
  return async (context, request, response) => {
    const endpointMetadataService = endpointAppContext.service.getEndpointMetadataService();

    try {
      const esClient = (await context.core).elasticsearch.client;
      return response.ok({
        body: await endpointMetadataService.getEnrichedHostMetadata(
          esClient.asInternalUser,
          endpointAppContext.service.getInternalFleetServices(),
          request.params.id
        ),
      });
    } catch (error) {
      return errorHandler(logger, response, error);
    }
  };
};

export function getMetadataTransformStatsHandler(
  logger: Logger
): RequestHandler<unknown, unknown, unknown, SecuritySolutionRequestHandlerContext> {
  return async (context, _, response) => {
    const esClient = (await context.core).elasticsearch.client.asInternalUser;
    try {
      const transformStats = await esClient.transform.getTransformStats({
        transform_id: METADATA_TRANSFORMS_PATTERN,
        allow_no_match: true,
      });
      return response.ok({
        body: transformStats,
      });
    } catch (error) {
      return errorHandler(logger, response, error);
    }
  };
}
