/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
import type { estypes } from '@elastic/elasticsearch';
import type { ESSearchResponse } from '@kbn/es-types';
import { performance } from 'perf_hooks';
import type {
  AlertInstanceContext,
  AlertInstanceState,
  RuleExecutorServices,
} from '@kbn/alerting-plugin/server';
import type { SignalSource, LoggedRequestsConfig } from '../types';
import { createErrorsFromShard, makeFloatString } from './utils';
import { withSecuritySpan } from '../../../../utils/with_security_span';
import type { IRuleExecutionLogForExecutors } from '../../rule_monitoring';
import type { RulePreviewLoggedRequest } from '../../../../../common/api/detection_engine/rule_preview/rule_preview.gen';
import { logSearchRequest } from './logged_requests';

export interface SingleSearchAfterParams<TSearchRequest> {
  searchRequest: TSearchRequest;
  services: RuleExecutorServices<AlertInstanceState, AlertInstanceContext, 'default'>;
  ruleExecutionLogger: IRuleExecutionLogForExecutors;
  loggedRequestsConfig?: LoggedRequestsConfig;
}

// utilize search_after for paging results into bulk.
export const singleSearchAfter = async <
  TSearchRequest extends estypes.SearchRequest = estypes.SearchRequest
>({
  searchRequest,
  services,
  ruleExecutionLogger,
  loggedRequestsConfig,
}: SingleSearchAfterParams<TSearchRequest>): Promise<{
  searchResult: ESSearchResponse<SignalSource, TSearchRequest>;
  searchDuration: string;
  searchErrors: string[];
  loggedRequests?: RulePreviewLoggedRequest[];
}> => {
  return withSecuritySpan('singleSearchAfter', async () => {
    const loggedRequests: RulePreviewLoggedRequest[] = [];

    // Log the ES request to trace (trace-only, not console)
    ruleExecutionLogger.traceOnly('[ES Search] Executing search request', {
      index: searchRequest.index,
      size: searchRequest.size,
      from: (searchRequest.body as Record<string, unknown>)?.query
        ? 'has query'
        : 'no query',
      search_after: searchRequest.search_after,
    });

    try {
      const start = performance.now();
      const nextSearchAfterResult = (await services.scopedClusterClient.asCurrentUser.search(
        searchRequest
      )) as ESSearchResponse<SignalSource, TSearchRequest>;

      const end = performance.now();
      const durationMs = Math.round(end - start);

      const searchErrors = createErrorsFromShard({
        errors: nextSearchAfterResult._shards.failures ?? [],
      });

      // Log the ES request/response to trace
      ruleExecutionLogger.traceEsRequest({
        description: loggedRequestsConfig?.description ?? 'Search for matching events',
        request: searchRequest,
        response: nextSearchAfterResult as unknown as Record<string, unknown>,
        durationMs,
      });

      if (loggedRequestsConfig) {
        loggedRequests.push({
          request: loggedRequestsConfig.skipRequestQuery
            ? undefined
            : logSearchRequest(searchRequest),
          description: loggedRequestsConfig.description,
          request_type: loggedRequestsConfig.type,
          duration: durationMs,
        });
      }

      return {
        searchResult: nextSearchAfterResult,
        searchDuration: makeFloatString(end - start),
        searchErrors,
        loggedRequests,
      };
    } catch (exc) {
      // Log the error to trace with full details
      ruleExecutionLogger.traceEsRequest({
        description: loggedRequestsConfig?.description ?? 'Search for matching events',
        request: searchRequest,
        error: exc instanceof Error ? exc : new Error(String(exc)),
      });
      ruleExecutionLogger.error(`Searching events operation failed: ${exc}`);
      throw exc;
    }
  });
};
