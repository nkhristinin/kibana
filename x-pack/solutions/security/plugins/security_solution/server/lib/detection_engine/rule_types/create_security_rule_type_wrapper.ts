/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { isEmpty, partition } from 'lodash';
import agent from 'elastic-apm-node';

import type { estypes } from '@elastic/elasticsearch';
import { IndexPatternsFetcher } from '@kbn/data-views-plugin/server';
import { TIMESTAMP } from '@kbn/rule-data-utils';
import { createPersistenceRuleTypeWrapper } from '@kbn/rule-registry-plugin/server';
import { buildExceptionFilter } from '@kbn/lists-plugin/server/services/exception_lists';
import { technicalRuleFieldMap } from '@kbn/rule-registry-plugin/common/assets/field_maps/technical_rule_field_map';
import type { FieldMap } from '@kbn/alerts-as-data-utils';
import { parseScheduleDates } from '@kbn/securitysolution-io-ts-utils';
import { getIndexListFromEsqlQuery } from '@kbn/securitysolution-utils';
import type { FormatAlert } from '@kbn/alerting-plugin/server/types';
import { SavedObjectsErrorHelpers } from '@kbn/core/server';
import {
  checkPrivilegesFromEsClient,
  getExceptions,
  getRuleRangeTuples,
  hasReadIndexPrivileges,
  hasTimestampFields,
  isMachineLearningParams,
  isEsqlParams,
  getDisabledActionsWarningText,
  checkForFrozenIndices,
} from './utils/utils';
import { DEFAULT_MAX_SIGNALS, DEFAULT_SEARCH_AFTER_PAGE_SIZE } from '../../../../common/constants';
import type { CreateSecurityRuleTypeWrapper } from './types';
import { getListClient } from './utils/get_list_client';
// eslint-disable-next-line no-restricted-imports
import { getNotificationResultsLink } from '../rule_actions_legacy';
// eslint-disable-next-line no-restricted-imports
import { formatAlertForNotificationActions } from '../rule_actions_legacy/logic/notifications/schedule_notification_actions';
import { createResultObject } from './utils';
import { RuleExecutionStatusEnum } from '../../../../common/api/detection_engine/rule_monitoring';
import { truncateList } from '../rule_monitoring';
import aadFieldConversion from '../routes/index/signal_aad_mapping.json';
import { extractReferences, injectReferences } from './saved_object_references';
import { withSecuritySpan } from '../../../utils/with_security_span';
import {
  analyzeIndices,
  analyzeFields,
  extractFieldsFromQuery,
  extractFieldsFromFilters,
  checkFieldCardinality,
} from '../rule_monitoring/logic/rule_execution_trace/field_analyzer';
import { getInputIndex } from './utils/get_input_output_index';
import { TIMESTAMP_RUNTIME_FIELD } from './constants';
import { buildTimestampRuntimeMapping } from './utils/build_timestamp_runtime_mapping';
import { alertsFieldMap, rulesFieldMap } from '../../../../common/field_maps';
import { sendAlertSuppressionTelemetryEvent } from './utils/telemetry/send_alert_suppression_telemetry_event';
import { sendGapDetectedTelemetryEvent } from './utils/telemetry/send_gap_detected_telemetry_event';
import type { RuleParams } from '../rule_schema';
import {
  SECURITY_FROM,
  SECURITY_IMMUTABLE,
  SECURITY_INPUT_INDEX,
  SECURITY_MAX_SIGNALS,
  SECURITY_MERGE_STRATEGY,
  SECURITY_NUM_ALERTS_CREATED,
  SECURITY_NUM_IGNORE_FIELDS_REGEX,
  SECURITY_NUM_IGNORE_FIELDS_STANDARD,
  SECURITY_NUM_RANGE_TUPLES,
  SECURITY_PARAMS,
  SECURITY_RULE_ID,
  SECURITY_TO,
} from './utils/apm_field_names';
import { checkErrorDetails } from './utils/check_error_details';

const aliasesFieldMap: FieldMap = {};

// Helper to format bytes for trace logging
const formatBytesForTrace = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
};

Object.entries(aadFieldConversion).forEach(([key, value]) => {
  aliasesFieldMap[key] = {
    type: 'alias',
    required: false,
    path: value,
  };
});

const addApmLabelsFromParams = (params: RuleParams) => {
  agent.addLabels(
    {
      [SECURITY_FROM]: params.from,
      [SECURITY_IMMUTABLE]: params.immutable,
      [SECURITY_MAX_SIGNALS]: params.maxSignals,
      [SECURITY_RULE_ID]: params.ruleId,
      [SECURITY_TO]: params.to,
    },
    false
  );
};

export const securityRuleTypeFieldMap = {
  ...technicalRuleFieldMap,
  ...alertsFieldMap,
  ...rulesFieldMap,
  ...aliasesFieldMap,
};

/* eslint-disable complexity */
export const createSecurityRuleTypeWrapper: CreateSecurityRuleTypeWrapper =
  ({
    lists,
    actions,
    docLinks,
    logger,
    config,
    publicBaseUrl,
    ruleDataClient,
    ruleExecutionLoggerFactory,
    version,
    isPreview,
    isServerless,
    experimentalFeatures,
    alerting,
    analytics,
    eventsTelemetry,
    licensing,
    scheduleNotificationResponseActionsService,
  }) =>
  (type) => {
    const { alertIgnoreFields: ignoreFields, alertMergeStrategy: mergeStrategy } = config;
    const persistenceRuleType = createPersistenceRuleTypeWrapper({
      ruleDataClient,
      logger,
      formatAlert: formatAlertForNotificationActions,
    });

    return persistenceRuleType({
      ...type,
      cancelAlertsOnRuleTimeout: false,
      useSavedObjectReferences: {
        extractReferences: (params) => extractReferences({ logger, params }),
        injectReferences: (params, savedObjectReferences) =>
          injectReferences({ logger, params, savedObjectReferences }),
      },
      autoRecoverAlerts: false,
      getViewInAppRelativeUrl: ({ rule, start, end }) => {
        let startTime = null;
        let endTime = null;

        if (start && end) {
          startTime = new Date(start).toISOString();
          endTime = new Date(end).toISOString();
        } else if (rule.schedule?.interval) {
          startTime = `now-${rule.schedule?.interval}`;
          endTime = 'now';
        }
        if (!startTime || !endTime) {
          return '';
        }

        const fromInMs = parseScheduleDates(startTime)?.format('x');
        const toInMs = parseScheduleDates(endTime)?.format('x');

        return getNotificationResultsLink({
          from: fromInMs,
          to: toInMs,
          id: rule.id,
        });
      },
      async executor(options) {
        agent.setTransactionName(`${options.rule.ruleTypeId} execution`);
        return withSecuritySpan('securityRuleTypeExecutor', async () => {
          const {
            executionId,
            params,
            previousStartedAt,
            startedAt,
            startedAtOverridden,
            services,
            spaceId,
            state,
            rule,
          } = options;
          addApmLabelsFromParams(params);
          agent.setCustomContext({ [SECURITY_MERGE_STRATEGY]: mergeStrategy });
          agent.setCustomContext({ [SECURITY_PARAMS]: params });
          let runState = state;
          let inputIndex: string[] = [];
          let runtimeMappings: estypes.MappingRuntimeFields | undefined;
          const { from, maxSignals, timestampOverride, timestampOverrideFallbackDisabled, to } =
            params;
          const {
            savedObjectsClient,
            scopedClusterClient,
            uiSettingsClient,
            ruleMonitoringService,
            ruleResultService,
          } = services;
          const searchAfterSize = Math.min(maxSignals, DEFAULT_SEARCH_AFTER_PAGE_SIZE);

          const esClient = scopedClusterClient.asCurrentUser;

          const ruleExecutionLogger = await ruleExecutionLoggerFactory({
            savedObjectsClient,
            ruleMonitoringService,
            ruleResultService,
            context: {
              executionId,
              ruleId: rule.id,
              ruleUuid: params.ruleId,
              ruleName: rule.name,
              ruleRevision: rule.revision,
              ruleType: rule.ruleTypeId,
              spaceId,
            },
          });

          const completeRule = {
            ruleConfig: rule,
            ruleParams: params,
            alertId: rule.id,
          };

          const {
            schedule: { interval },
          } = completeRule.ruleConfig;

          const refresh = isPreview ? false : true;

          // Log comprehensive rule execution start (trace-only)
          ruleExecutionLogger.traceOnly('[Rule Execution] Starting execution', {
            ruleId: rule.id,
            ruleUuid: params.ruleId,
            ruleName: rule.name,
            ruleType: rule.ruleTypeId,
            ruleRevision: rule.revision,
            interval,
            spaceId,
            executionId,
            isPreview,
            previousStartedAt: previousStartedAt?.toISOString(),
            startedAt: startedAt.toISOString(),
            startedAtOverridden,
            from,
            to,
            maxSignals,
            timestampOverride,
            timestampOverrideFallbackDisabled,
          });

          ruleExecutionLogger.debug(`Starting Security Rule execution (interval: ${interval})`);

          await ruleExecutionLogger.logStatusChange({
            newStatus: RuleExecutionStatusEnum.running,
          });

          let result = createResultObject(state);

          let frozenIndicesQueriedCount = 0;
          const wrapperWarnings = [];
          const wrapperErrors = [];

          const primaryTimestamp = timestampOverride ?? TIMESTAMP;
          const secondaryTimestamp =
            primaryTimestamp !== TIMESTAMP && !timestampOverrideFallbackDisabled
              ? TIMESTAMP
              : undefined;

          // If we have a timestampOverride, we'll compute a runtime field that emits the override for each document if it exists,
          // otherwise it emits @timestamp. If we don't have a timestamp override we don't want to pay the cost of using a
          // runtime field, so we just use @timestamp directly.
          const { aggregatableTimestampField, timestampRuntimeMappings } =
            secondaryTimestamp && timestampOverride
              ? {
                  aggregatableTimestampField: TIMESTAMP_RUNTIME_FIELD,
                  timestampRuntimeMappings: buildTimestampRuntimeMapping({
                    timestampOverride,
                  }),
                }
              : {
                  aggregatableTimestampField: primaryTimestamp,
                  timestampRuntimeMappings: undefined,
                };

          /**
           * Data Views Logic
           * Use of data views is supported for all rules other than ML and Esql.
           * Rules can define both a data view and index pattern, but on execution:
           *  - Data view is used if it is defined
           *    - Rule exits early if data view defined is not found (ie: it's been deleted)
           *  - If no data view defined, falls to using existing index logic
           * Esql rules has index in query, which can be retrieved
           */
          if (isEsqlParams(params)) {
            inputIndex = getIndexListFromEsqlQuery(params.query);
          } else if (!isMachineLearningParams(params)) {
            try {
              const { index, runtimeMappings: dataViewRuntimeMappings } = await getInputIndex({
                index: params.index,
                services,
                version,
                logger,
                ruleId: params.ruleId,
                dataViewId: params.dataViewId,
              });

              inputIndex = index ?? [];
              runtimeMappings = dataViewRuntimeMappings;
            } catch (exc) {
              if (SavedObjectsErrorHelpers.isNotFoundError(exc)) {
                await ruleExecutionLogger.logStatusChange({
                  newStatus: RuleExecutionStatusEnum.failed,
                  message: `Data View not found ${exc}`,
                  userError: true,
                });
              } else {
                await ruleExecutionLogger.logStatusChange({
                  newStatus: RuleExecutionStatusEnum.failed,
                  message: `Check for indices to search failed ${exc}`,
                });
              }

              return { state: result.state };
            }
          }

          // Make a copy of `inputIndex` or else the APM agent reports it as [Circular] for most rule types because it's the same object
          // as `index`
          agent.setCustomContext({ [SECURITY_INPUT_INDEX]: [...inputIndex] });

          // check if rule has permissions to access given index pattern
          // move this collection of lines into a function in utils
          // so that we can use it in create rules route, bulk, etc.
          let skipExecution: boolean = false;

          if (!isMachineLearningParams(params)) {
            try {
              const indexPatterns = new IndexPatternsFetcher(scopedClusterClient.asInternalUser);
              const existingIndices = await indexPatterns.getExistingIndices(inputIndex);

              if (existingIndices.length > 0) {
                const privileges = await checkPrivilegesFromEsClient(esClient, existingIndices);
                const readIndexWarningMessage = await hasReadIndexPrivileges({
                  privileges,
                  ruleExecutionLogger,
                  uiSettingsClient,
                  docLinks,
                });

                if (readIndexWarningMessage != null) {
                  wrapperWarnings.push(readIndexWarningMessage);
                }
              }
            } catch (exc) {
              wrapperWarnings.push(`Check privileges failed to execute ${exc}`);
            }

            try {
              const timestampFieldCaps = await withSecuritySpan('fieldCaps', () =>
                services.scopedClusterClient.asCurrentUser.fieldCaps(
                  {
                    index: inputIndex,
                    fields: secondaryTimestamp
                      ? [primaryTimestamp, secondaryTimestamp]
                      : [primaryTimestamp],
                    include_unmapped: true,
                    runtime_mappings: runtimeMappings,
                    ignore_unavailable: true,
                  },
                  { meta: true }
                )
              );

              const { foundNoIndices, warningMessage: warningMissingTimestampFieldsMessage } =
                await hasTimestampFields({
                  timestampField: primaryTimestamp,
                  timestampFieldCapsResponse: timestampFieldCaps,
                  inputIndices: inputIndex,
                  ruleExecutionLogger,
                });
              if (warningMissingTimestampFieldsMessage != null) {
                wrapperWarnings.push(warningMissingTimestampFieldsMessage);
              }
              skipExecution = foundNoIndices;
            } catch (exc) {
              wrapperWarnings.push(`Timestamp fields check failed to execute ${exc}`);
            }

            if (!isServerless) {
              try {
                const frozenIndices = await checkForFrozenIndices({
                  inputIndices: inputIndex,
                  internalEsClient: services.scopedClusterClient.asInternalUser,
                  currentUserEsClient: services.scopedClusterClient.asCurrentUser,
                  to: params.to,
                  from: params.from,
                  primaryTimestamp,
                  secondaryTimestamp,
                });

                if (frozenIndices.length > 0) {
                  frozenIndicesQueriedCount = frozenIndices.length;
                }
              } catch (exc) {
                wrapperWarnings.push(`Frozen indices check failed to execute ${exc}`);
              }
            }
          }

          const {
            tuples,
            remainingGap,
            warningStatusMessage: rangeTuplesWarningMessage,
            gap,
            originalFrom,
            originalTo,
          } = await getRuleRangeTuples({
            startedAt,
            previousStartedAt,
            from,
            to,
            interval,
            maxSignals: maxSignals ?? DEFAULT_MAX_SIGNALS,
            ruleExecutionLogger,
            alerting,
          });
          if (rangeTuplesWarningMessage != null) {
            wrapperWarnings.push(rangeTuplesWarningMessage);
          }

          agent.setCustomContext({ [SECURITY_NUM_RANGE_TUPLES]: tuples.length });

          if (remainingGap.asMilliseconds() > 0) {
            const gapDuration = `${remainingGap.humanize()} (${remainingGap.asMilliseconds()}ms)`;
            const gapErrorMessage = `${gapDuration} were not queried between this rule execution and the last execution, so signals may have been missed. Consider increasing your look behind time or adding more Kibana instances`;
            if (analytics) {
              sendGapDetectedTelemetryEvent({
                analytics,
                interval,
                gapDuration: remainingGap,
                originalFrom,
                originalTo,
                ruleParams: params,
              });
            }
            wrapperErrors.push(gapErrorMessage);
            await ruleExecutionLogger.logStatusChange({
              newStatus: RuleExecutionStatusEnum.failed,
              message: gapErrorMessage,
              metrics: {
                executionGap: remainingGap,
                gapRange: experimentalFeatures.storeGapsInEventLogEnabled ? gap : undefined,
              },
            });
          }

          try {
            const { listClient, exceptionsClient } = getListClient({
              esClient: services.scopedClusterClient.asCurrentUser,
              updatedByUser: rule.updatedBy,
              spaceId,
              lists,
              savedObjectClient: options.services.savedObjectsClient,
            });

            const exceptionItems = await getExceptions({
              client: exceptionsClient,
              lists: params.exceptionsList,
              shouldFilterOutEndpointExceptions:
                experimentalFeatures.endpointExceptionsMovedUnderManagement,
            });

            // Log full rule definition (trace-only) for AI analysis
            ruleExecutionLogger.traceOnly('[Rule Definition] Full rule configuration', {
              ruleId: rule.id,
              ruleName: rule.name,
              ruleType: params.type,
              enabled: rule.enabled,
              // Query/language
              query: params.query,
              language: params.language,
              savedId: params.savedId,
              // Index patterns
              index: params.index,
              dataViewId: params.dataViewId,
              // Filters
              filters: params.filters,
              // Time settings
              from: params.from,
              to: params.to,
              // Threshold settings (if applicable)
              threshold: params.threshold,
              // Alert suppression
              alertSuppression: params.alertSuppression,
              // Exception lists (references)
              exceptionsList: params.exceptionsList?.map((ex) => ({
                id: ex.id,
                listId: ex.list_id,
                type: ex.type,
                namespaceType: ex.namespace_type,
              })),
              // Risk and severity
              riskScore: params.riskScore,
              severity: params.severity,
              // Tags and metadata
              tags: rule.tags,
              author: params.author,
              // Building block
              buildingBlockType: params.buildingBlockType,
              // Timeline reference
              timelineId: params.timelineId,
              timelineTitle: params.timelineTitle,
            });

            // Log exception items details (trace-only) for AI analysis
            if (exceptionItems.length > 0) {
              ruleExecutionLogger.traceOnly('[Exception Items] Active exceptions for this rule', {
                totalExceptionItems: exceptionItems.length,
                // Include first 10 exception items with their conditions
                exceptionItems: exceptionItems.slice(0, 10).map((item) => ({
                  id: item.id,
                  name: item.name,
                  listId: item.list_id,
                  type: item.type,
                  // Include the actual exception conditions
                  entries: item.entries?.map((entry) => ({
                    field: entry.field,
                    operator: entry.operator,
                    type: entry.type,
                    // For match/match_any, include the value(s)
                    value: 'value' in entry ? entry.value : undefined,
                    // For list type, include list reference
                    list: 'list' in entry ? entry.list : undefined,
                  })),
                  osTypes: item.os_types,
                  tags: item.tags,
                })),
                // If more than 10, indicate truncation
                truncated: exceptionItems.length > 10,
              });
            } else {
              ruleExecutionLogger.traceOnly('[Exception Items] No exception items configured', {
                exceptionListsConfigured: params.exceptionsList?.length ?? 0,
              });
            }

            // Index Pattern Analysis (trace-only)
            // Analyze which indices have data and which are empty
            // Note: We use a simple console-based logger for analysis since this runs in the executor context
            const analysisLogger = {
              debug: (msg: string) => {
                // Silent - analysis is best-effort and shouldn't pollute logs
              },
            } as { debug: (msg: string) => void };

            if (inputIndex.length > 0) {
              try {
                // Get time range from tuples to match the actual query time range
                // This ensures we only show indices that would actually be queried
                const queryTimeRange =
                  tuples.length > 0
                    ? {
                        from: tuples[0].from.toISOString(),
                        to: tuples[tuples.length - 1].to.toISOString(),
                      }
                    : undefined;

                const indexAnalysis = await analyzeIndices({
                  esClient: services.scopedClusterClient.asCurrentUser,
                  indexPatterns: inputIndex,
                  logger: analysisLogger as unknown as Parameters<typeof analyzeIndices>[0]['logger'],
                  timeRange: queryTimeRange,
                });

                const emptyIndices = indexAnalysis.filter((i) => i.status === 'empty');
                const activeIndices = indexAnalysis.filter((i) => i.status === 'active');
                const frozenIndices = indexAnalysis.filter((i) => i.is_frozen);
                const dataStreamIndices = indexAnalysis.filter((i) => i.is_data_stream);

                // Calculate total size
                const totalSizeBytes = indexAnalysis.reduce((sum, i) => sum + (i.size_bytes || 0), 0);

                // Build suggestions
                const suggestions: string[] = [];
                if (emptyIndices.length > 0) {
                  suggestions.push(
                    `${emptyIndices.length} index pattern(s) matched no documents: ${emptyIndices
                      .slice(0, 5)
                      .map((i) => i.index_name)
                      .join(', ')}. Consider removing unused patterns.`
                  );
                }
                if (frozenIndices.length > 0) {
                  suggestions.push(
                    `${frozenIndices.length} frozen index(es) detected: ${frozenIndices
                      .slice(0, 3)
                      .map((i) => i.index_name)
                      .join(', ')}. Frozen indices have slower search performance.`
                  );
                }

                ruleExecutionLogger.traceOnly('[Index Analysis] Index pattern breakdown', {
                  patterns_configured: inputIndex,
                  // Time range used for analysis (same as actual query time range)
                  time_range: queryTimeRange
                    ? {
                        from: queryTimeRange.from,
                        to: queryTimeRange.to,
                        note: 'Only indices with data in this time range are shown',
                      }
                    : { note: 'No time range filter applied (showing all matching indices)' },
                  total_indices_resolved: indexAnalysis.length,
                  active_indices: activeIndices.length,
                  empty_indices: emptyIndices.length,
                  frozen_indices: frozenIndices.length,
                  data_stream_indices: dataStreamIndices.length,
                  total_size_bytes: totalSizeBytes,
                  total_size_human: formatBytesForTrace(totalSizeBytes),
                  indices: indexAnalysis.slice(0, 20).map((i) => ({
                    name: i.index_name,
                    docs: i.doc_count,
                    size: i.size_human,
                    size_bytes: i.size_bytes,
                    health: i.health,
                    is_frozen: i.is_frozen,
                    is_searchable_snapshot: i.is_searchable_snapshot,
                    is_data_stream: i.is_data_stream,
                    data_stream: i.data_stream_name,
                    shards: i.primary_shards,
                    replicas: i.replica_shards,
                    created: i.creation_date,
                  })),
                  suggestions,
                });
              } catch (analysisError) {
                // Non-blocking - trace analysis should never break rule execution
                analysisLogger.debug(`Index analysis failed: ${analysisError}`);
              }

              // Field Mapping Analysis (trace-only)
              try {
                const queryFields = extractFieldsFromQuery(params.query, params.language || 'kuery');
                const filterFields = extractFieldsFromFilters(params.filters);
                const suppressionFields = params.alertSuppression?.groupBy || [];

                if (queryFields.length > 0 || filterFields.length > 0 || suppressionFields.length > 0) {
                  const fieldAnalysis = await analyzeFields({
                    esClient: services.scopedClusterClient.asCurrentUser,
                    indexPatterns: inputIndex,
                    queryFields,
                    filterFields,
                    suppressionFields,
                    logger: analysisLogger,
                  });

                  const fieldsWithIssues = fieldAnalysis.filter((f) => f.suggestions.length > 0);

                  ruleExecutionLogger.traceOnly('[Field Analysis] Query field mappings', {
                    total_fields_analyzed: fieldAnalysis.length,
                    query_fields: queryFields,
                    filter_fields: filterFields,
                    suppression_fields: suppressionFields,
                    fields: fieldAnalysis.map((f) => ({
                      name: f.field_name,
                      type: f.field_type,
                      aggregatable: f.is_aggregatable,
                      has_keyword: f.has_keyword_subfield,
                      used_in: f.used_in,
                    })),
                    fields_with_issues: fieldsWithIssues.map((f) => f.field_name),
                    suggestions: fieldsWithIssues.flatMap((f) => f.suggestions),
                  });

                  // Check cardinality for suppression fields
                  if (suppressionFields.length > 0 && tuples.length > 0) {
                    const tuple = tuples[0];
                    for (const suppressionField of suppressionFields.slice(0, 3)) {
                      const { cardinality, isHighCardinality } = await checkFieldCardinality({
                        esClient: services.scopedClusterClient.asCurrentUser,
                        indexPatterns: inputIndex,
                        field: suppressionField,
                        timeRange: {
                          from: tuple.from.toISOString(),
                          to: tuple.to.toISOString(),
                        },
                        logger: analysisLogger,
                      });

                      if (isHighCardinality) {
                        ruleExecutionLogger.traceOnly('[Field Analysis] High cardinality warning', {
                          field: suppressionField,
                          cardinality,
                          warning: `Field '${suppressionField}' has high cardinality (${cardinality.toLocaleString()}+). Alert suppression may be slow.`,
                        });
                      }
                    }
                  }
                }
              } catch (fieldError) {
                // Non-blocking
                analysisLogger.debug(`Field analysis failed: ${fieldError}`);
              }
            }

            const alertTimestampOverride = isPreview ? startedAt : undefined;

            const legacySignalFields: string[] = Object.keys(aadFieldConversion);
            const [ignoreFieldsRegexes, ignoreFieldsStandard] = partition(
              [...ignoreFields, ...legacySignalFields],
              (field: string) => field.startsWith('/') && field.endsWith('/')
            );
            const ignoreFieldsObject: Record<string, boolean> = {};
            ignoreFieldsStandard.forEach((field) => {
              ignoreFieldsObject[field] = true;
            });

            agent.setCustomContext({
              [SECURITY_NUM_IGNORE_FIELDS_STANDARD]: ignoreFieldsStandard.length,
              [SECURITY_NUM_IGNORE_FIELDS_REGEX]: ignoreFieldsRegexes.length,
            });

            const intendedTimestamp = startedAtOverridden ? startedAt : undefined;

            const { filter: exceptionFilter, unprocessedExceptions } = await buildExceptionFilter({
              startedAt,
              alias: null,
              excludeExceptions: true,
              chunkSize: 10,
              lists: exceptionItems,
              listClient,
            });

            if (!skipExecution) {
              // Log execution setup details (trace-only)
              ruleExecutionLogger.traceOnly('[Rule Execution] Setup complete, starting executor loop', {
                inputIndex,
                tuplesCount: tuples.length,
                exceptionItemsCount: exceptionItems.length,
                unprocessedExceptionsCount: unprocessedExceptions.length,
                hasExceptionFilter: !!exceptionFilter,
                primaryTimestamp,
                secondaryTimestamp,
                searchAfterSize,
                runtimeMappingsKeys: Object.keys(runtimeMappings ?? {}),
              });

              for (const tuple of tuples) {
                // Log each tuple execution (trace-only)
                ruleExecutionLogger.traceOnly('[Rule Execution] Starting tuple execution', {
                  tupleFrom: tuple.from.toISOString(),
                  tupleTo: tuple.to.toISOString(),
                  maxSignals: tuple.maxSignals,
                });

                const runResult = await type.executor({
                  ...options,
                  services,
                  state: runState,
                  sharedParams: {
                    completeRule,
                    inputIndex,
                    exceptionFilter,
                    unprocessedExceptions,
                    runtimeMappings: {
                      ...runtimeMappings,
                      ...timestampRuntimeMappings,
                    },
                    searchAfterSize,
                    tuple,
                    listClient,
                    ruleDataClient,
                    mergeStrategy,
                    primaryTimestamp,
                    secondaryTimestamp,
                    ruleExecutionLogger,
                    aggregatableTimestampField,
                    alertTimestampOverride,
                    refreshOnIndexingAlerts: refresh,
                    publicBaseUrl,
                    experimentalFeatures,
                    intendedTimestamp,
                    spaceId,
                    ignoreFields: ignoreFieldsObject,
                    ignoreFieldsRegexes,
                    eventsTelemetry,
                    licensing,
                    scheduleNotificationResponseActionsService,
                  },
                });

                const createdSignals = result.createdSignals.concat(runResult.createdSignals);
                const warningMessages = result.warningMessages.concat(runResult.warningMessages);
                result = {
                  bulkCreateTimes: result.bulkCreateTimes.concat(runResult.bulkCreateTimes),
                  enrichmentTimes: result.enrichmentTimes.concat(runResult.enrichmentTimes),
                  createdSignals,
                  createdSignalsCount: createdSignals.length,
                  suppressedAlertsCount: runResult.suppressedAlertsCount,
                  errors: result.errors.concat(runResult.errors),
                  searchAfterTimes: result.searchAfterTimes.concat(runResult.searchAfterTimes),
                  state: runResult.state,
                  success: result.success && runResult.success,
                  warning: warningMessages.length > 0,
                  warningMessages,
                  userError: runResult.userError,
                  ...(runResult.loggedRequests ? { loggedRequests: runResult.loggedRequests } : {}),
                };
                runState = runResult.state;
              }
            } else {
              result = {
                bulkCreateTimes: [],
                enrichmentTimes: [],
                createdSignals: [],
                createdSignalsCount: 0,
                suppressedAlertsCount: 0,
                errors: [],
                searchAfterTimes: [],
                state,
                success: true,
                warning: false,
                warningMessages: [],
              };
            }

            const disabledActions = rule.actions.filter(
              (action) => !actions.isActionTypeEnabled(action.actionTypeId)
            );

            const createdSignalsCount = result.createdSignals.length;

            agent.setCustomContext({ [SECURITY_NUM_ALERTS_CREATED]: createdSignalsCount });

            if (disabledActions.length > 0) {
              const disabledActionsWarning = getDisabledActionsWarningText({
                alertsCreated: createdSignalsCount > 0,
                disabledActions,
              });
              wrapperWarnings.push(disabledActionsWarning);
            }

            if (result.warningMessages.length > 0 || wrapperWarnings.length > 0) {
              // write warning messages first because if we have still have an error to write
              // we want to write the error messages last, so that the errors are set
              // as the current status of the rule.
              await ruleExecutionLogger.logStatusChange({
                newStatus: RuleExecutionStatusEnum['partial failure'],
                message: truncateList(result.warningMessages.concat(wrapperWarnings)).join('\n\n'),
                metrics: {
                  searchDurations: result.searchAfterTimes,
                  indexingDurations: result.bulkCreateTimes,
                  enrichmentDurations: result.enrichmentTimes,
                  frozenIndicesQueriedCount,
                },
              });
            }
            if (wrapperErrors.length > 0 || result.errors.length > 0) {
              await ruleExecutionLogger.logStatusChange({
                newStatus: RuleExecutionStatusEnum.failed,
                message: truncateList(result.errors.concat(wrapperErrors)).join(', '),
                metrics: {
                  searchDurations: result.searchAfterTimes,
                  indexingDurations: result.bulkCreateTimes,
                  enrichmentDurations: result.enrichmentTimes,
                  executionGap: remainingGap,
                  gapRange: experimentalFeatures.storeGapsInEventLogEnabled ? gap : undefined,
                  frozenIndicesQueriedCount,
                },
                userError:
                  result.userError ||
                  result.errors.every((err) => checkErrorDetails(err).isUserError),
              });
            } else if (!(result.warningMessages.length > 0) && !(wrapperWarnings.length > 0)) {
              ruleExecutionLogger.debug('Security Rule execution completed');
              ruleExecutionLogger.debug(
                `Finished indexing ${createdSignalsCount} alerts into ${ruleDataClient.indexNameWithNamespace(
                  spaceId
                )} ${
                  !isEmpty(tuples)
                    ? `searched between date ranges ${JSON.stringify(tuples, null, 2)}`
                    : ''
                }`
              );
              await ruleExecutionLogger.logStatusChange({
                newStatus: RuleExecutionStatusEnum.succeeded,
                message: 'Rule execution completed successfully',
                metrics: {
                  searchDurations: result.searchAfterTimes,
                  indexingDurations: result.bulkCreateTimes,
                  enrichmentDurations: result.enrichmentTimes,
                  frozenIndicesQueriedCount,
                },
              });
            }
          } catch (error) {
            const errorMessage = error.message ?? '(no error message given)';

            await ruleExecutionLogger.logStatusChange({
              newStatus: RuleExecutionStatusEnum.failed,
              message: `An error occurred during rule execution: message: "${errorMessage}"`,
              userError: checkErrorDetails(errorMessage).isUserError,
              metrics: {
                searchDurations: result.searchAfterTimes,
                indexingDurations: result.bulkCreateTimes,
                enrichmentDurations: result.enrichmentTimes,
                frozenIndicesQueriedCount,
              },
            });
          }

          if (!isPreview && analytics) {
            sendAlertSuppressionTelemetryEvent({
              analytics,
              suppressedAlertsCount: result.suppressedAlertsCount ?? 0,
              createdAlertsCount: result.createdSignalsCount,
              ruleAttributes: rule,
              ruleParams: params,
            });
          }

          return {
            state: result.state,
            ...(result.loggedRequests ? { loggedRequests: result.loggedRequests } : {}),
          };
        });
      },
      alerts: {
        context: 'security',
        mappings: {
          dynamic: false,
          fieldMap: securityRuleTypeFieldMap,
        },
        useEcs: true,
        useLegacyAlerts: true,
        isSpaceAware: true,
        secondaryAlias: config.signalsIndex,
        formatAlert: formatAlertForNotificationActions as unknown as FormatAlert<never>,
      },
    });
  };
