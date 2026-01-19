/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { omitBy, isUndefined } from 'lodash';
import dateMath from '@kbn/datemath';

import { KibanaServices } from '../../../common/lib/kibana';

import type {
  ConnectRuleExecutionTraceResponse,
  GetRuleExecutionEventsResponse,
  GetRuleExecutionResultsResponse,
  TailRuleExecutionTraceResponse,
} from '../../../../common/api/detection_engine/rule_monitoring';
import {
  getRuleExecutionTraceConnectUrl,
  getRuleExecutionTraceExportUrl,
  getRuleExecutionTraceTailUrl,
  getRuleExecutionEventsUrl,
  getRuleExecutionResultsUrl,
  SETUP_HEALTH_URL,
} from '../../../../common/api/detection_engine/rule_monitoring';

import type {
  ConnectRuleExecutionTraceArgs,
  FetchRuleExecutionEventsArgs,
  FetchRuleExecutionResultsArgs,
  IRuleMonitoringApiClient,
  TailRuleExecutionTraceArgs,
} from './api_client_interface';

export const api: IRuleMonitoringApiClient = {
  setupDetectionEngineHealthApi: async (): Promise<void> => {
    await http().fetch(SETUP_HEALTH_URL, {
      version: '1',
      method: 'POST',
    });
  },

  fetchRuleExecutionEvents: (
    args: FetchRuleExecutionEventsArgs
  ): Promise<GetRuleExecutionEventsResponse> => {
    const {
      ruleId,
      searchTerm,
      eventTypes,
      logLevels,
      dateRange,
      sortOrder,
      page,
      perPage,
      signal,
    } = args;

    const url = getRuleExecutionEventsUrl(ruleId);
    const startDate = dateMath.parse(dateRange?.start ?? '')?.toISOString();
    const endDate = dateMath.parse(dateRange?.end ?? '', { roundUp: true })?.toISOString();

    return http().fetch<GetRuleExecutionEventsResponse>(url, {
      method: 'GET',
      version: '1',
      query: omitBy(
        {
          search_term: searchTerm?.length ? searchTerm : undefined,
          event_types: eventTypes?.length ? eventTypes.join(',') : undefined,
          log_levels: logLevels?.length ? logLevels.join(',') : undefined,
          date_start: startDate,
          date_end: endDate,
          sort_order: sortOrder,
          page,
          per_page: perPage,
        },
        isUndefined
      ),
      signal,
    });
  },

  fetchRuleExecutionResults: (
    args: FetchRuleExecutionResultsArgs
  ): Promise<GetRuleExecutionResultsResponse> => {
    const {
      ruleId,
      start,
      end,
      queryText,
      statusFilters,
      page,
      perPage,
      sortField,
      sortOrder,
      signal,
      runTypeFilters,
    } = args;

    const url = getRuleExecutionResultsUrl(ruleId);
    const startDate = dateMath.parse(start);
    const endDate = dateMath.parse(end, { roundUp: true });

    return http().fetch<GetRuleExecutionResultsResponse>(url, {
      method: 'GET',
      version: '1',
      query: {
        start: startDate?.utc().toISOString(),
        end: endDate?.utc().toISOString(),
        query_text: queryText,
        status_filters: statusFilters?.sort()?.join(','),
        sort_field: sortField,
        sort_order: sortOrder,
        page,
        per_page: perPage,
        run_type_filters: runTypeFilters?.sort()?.join(','),
      },
      signal,
    });
  },

  connectRuleExecutionTrace: (
    args: ConnectRuleExecutionTraceArgs
  ): Promise<ConnectRuleExecutionTraceResponse> => {
    const { ruleId, ttlMs, signal } = args;
    const url = getRuleExecutionTraceConnectUrl(ruleId);

    return http().fetch<ConnectRuleExecutionTraceResponse>(url, {
      method: 'POST',
      version: '1',
      body: JSON.stringify({
        ...(ttlMs !== undefined ? { ttl_ms: ttlMs } : {}),
      }),
      signal,
    });
  },

  tailRuleExecutionTrace: (
    args: TailRuleExecutionTraceArgs
  ): Promise<TailRuleExecutionTraceResponse> => {
    const { ruleId, dateStart, afterTs, afterSeq, limit, signal } = args;
    const url = getRuleExecutionTraceTailUrl(ruleId);
    return http().fetch<TailRuleExecutionTraceResponse>(url, {
      method: 'GET',
      version: '1',
      query: omitBy(
        {
          date_start: dateStart,
          after_ts: afterTs,
          after_seq: afterSeq,
          limit,
        },
        isUndefined
      ),
      signal,
    });
  },

  getRuleExecutionTraceExportUrl: (ruleId: string): string => {
    return http().basePath.prepend(getRuleExecutionTraceExportUrl(ruleId));
  },

  downloadRuleExecutionTrace: async (args: {
    ruleId: string;
    dateStart?: string;
  }): Promise<void> => {
    const { ruleId, dateStart } = args;
    const defaultStart = new Date(Date.now() - 5 * 60 * 1000).toISOString();

    // Build URL with apiVersion query param (Kibana's versioned route pattern for direct downloads)
    const baseUrl = http().basePath.prepend(getRuleExecutionTraceExportUrl(ruleId));
    const queryParams = new URLSearchParams({
      date_start: dateStart ?? defaultStart,
      apiVersion: '1', // Required for versioned routes when using direct fetch
    });
    const downloadUrl = `${baseUrl}?${queryParams.toString()}`;

    // Use anchor tag for direct download (handles auth via browser cookies)
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = `rule-${ruleId}.ndjson.gz`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  },
};

const http = () => KibanaServices.get().http;
