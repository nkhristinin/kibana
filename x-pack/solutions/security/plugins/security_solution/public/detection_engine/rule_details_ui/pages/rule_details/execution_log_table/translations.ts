/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { i18n } from '@kbn/i18n';

export const TABLE_TITLE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.tableTitle',
  {
    defaultMessage: 'Execution log',
  }
);

export const TABLE_SUBTITLE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.tableSubtitle',
  {
    defaultMessage: 'A log of rule execution results',
  }
);

export const SHOWING_EXECUTIONS = (totalItems: number) =>
  i18n.translate(
    'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.totalExecutionsLabel',
    {
      values: { totalItems },
      defaultMessage:
        'Showing {totalItems} {totalItems, plural, =1 {rule execution} other {rule executions}}',
    }
  );

export const RULE_EXECUTION_LOG_SEARCH_LIMIT_EXCEEDED = (totalItems: number, maxItems: number) =>
  i18n.translate(
    'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.searchLimitExceededLabel',
    {
      values: { totalItems, maxItems },
      defaultMessage:
        "More than {totalItems} rule executions match filters provided. Showing first {maxItems} by most recent '@timestamp'. Constrain filters further to view additional execution events.",
    }
  );

export const RULE_EXECUTION_LOG_SEARCH_PLACEHOLDER = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.searchPlaceholder',
  {
    defaultMessage: 'duration > 100 and gapDuration > 10',
  }
);

export const RULE_EXECUTION_LOG_SHOW_METRIC_COLUMNS_SWITCH = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.showMetricColumnsSwitchTitle',
  {
    defaultMessage: 'Show metrics columns',
  }
);

export const RULE_EXECUTION_LOG_SHOW_SOURCE_EVENT_TIME_RANGE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.showSourceEventTimeRangeSwitchTitle',
  {
    defaultMessage: 'Show source event time range',
  }
);

export const COLUMN_STATUS = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.statusColumn',
  {
    defaultMessage: 'Status',
  }
);

export const COLUMN_STATUS_TOOLTIP = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.statusColumnTooltip',
  {
    defaultMessage: 'Overall status of execution.',
  }
);

export const COLUMN_TYPE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.type',
  {
    defaultMessage: 'Type',
  }
);

export const COLUMN_SOURCE_EVENT_TIME_RANGE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.sourceEventTimeRange',
  {
    defaultMessage: 'Source event time range',
  }
);

export const COLUMN_SOURCE_EVENT_TIME_RANGE_TOOLTIP = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.sourceEventTimeRangeTooltip',
  {
    defaultMessage:
      "Only applies to manual rule executions. If the rule has look-back time, it's included in the logged time range.",
  }
);

export const COLUMN_TIMESTAMP = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.timestampColumn',
  {
    defaultMessage: 'Timestamp',
  }
);

export const COLUMN_TIMESTAMP_TOOLTIP = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.timestampColumnTooltip',
  {
    defaultMessage: 'Datetime rule execution initiated.',
  }
);

export const COLUMN_DURATION = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.durationColumn',
  {
    defaultMessage: 'Duration',
  }
);

export const COLUMN_DURATION_TOOLTIP = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.durationColumnTooltip',
  {
    defaultMessage: 'The length of time it took for the rule to run (hh:mm:ss:SSS).',
  }
);

export const COLUMN_MESSAGE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.messageColumn',
  {
    defaultMessage: 'Message',
  }
);

export const COLUMN_MESSAGE_TOOLTIP = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.messageColumnTooltip',
  {
    defaultMessage: 'Relevant message from execution outcome.',
  }
);

export const COLUMN_GAP_DURATION = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.gapDurationColumn',
  {
    defaultMessage: 'Gap Duration',
  }
);

export const COLUMN_GAP_TOOLTIP_SEE_DOCUMENTATION = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.gapTooltipSeeDocsDescription',
  {
    defaultMessage: 'see documentation',
  }
);

export const COLUMN_INDEX_DURATION = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.indexDurationColumn',
  {
    defaultMessage: 'Index Duration',
  }
);

export const COLUMN_INDEX_DURATION_TOOLTIP = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.indexDurationColumnTooltip',
  {
    defaultMessage: 'The length of time it took to index detected alerts (hh:mm:ss:SSS).',
  }
);

export const COLUMN_SEARCH_DURATION = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.searchDurationColumn',
  {
    defaultMessage: 'Search Duration',
  }
);

export const COLUMN_SEARCH_DURATION_TOOLTIP = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.searchDurationColumnTooltip',
  {
    defaultMessage: 'The length of time it took to search for alerts (hh:mm:ss:SSS).',
  }
);

export const COLUMN_SCHEDULING_DELAY = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.schedulingDelayColumn',
  {
    defaultMessage: 'Scheduling Delay',
  }
);

export const COLUMN_SCHEDULING_DELAY_TOOLTIP = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.schedulingDelayColumnTooltip',
  {
    defaultMessage: 'The length of time from rule scheduled till rule executed (hh:mm:ss:SSS).',
  }
);

export const COLUMN_ACTIONS = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.actionsColumn',
  {
    defaultMessage: 'Actions',
  }
);

export const COLUMN_ACTIONS_TOOLTIP = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.actionsColumnTooltip',
  {
    defaultMessage: 'Filter alerts by rule execution ID.',
  }
);

export const ACTION_VIEW_EXECUTION_TRACE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.actionViewExecutionTrace',
  {
    defaultMessage: 'View execution trace',
  }
);

export const ACTION_VIEW_EXECUTION_TRACE_TOOLTIP = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.actionViewExecutionTraceTooltip',
  {
    defaultMessage: 'Connect to a live stream of rule execution log lines.',
  }
);

export const CONNECT_TO_LIVE_LOG = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.connectButton',
  {
    defaultMessage: 'Connect to live log',
  }
);

export const DISCONNECT_FROM_LIVE_LOG = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.disconnectButton',
  {
    defaultMessage: 'Disconnect from live log',
  }
);

export const EXECUTION_TRACE_FLYOUT_TITLE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.flyoutTitle',
  {
    defaultMessage: 'Execution trace',
  }
);

export const EXECUTION_TRACE_EXECUTION_ID = (executionId: string) =>
  i18n.translate('xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.executionId', {
    defaultMessage: 'Execution: {executionId}',
    values: { executionId },
  });

export const EXECUTION_TRACE_RULE_ID = (ruleId: string) =>
  i18n.translate('xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.ruleId', {
    defaultMessage: 'Rule: {ruleId}',
    values: { ruleId },
  });

export const EXECUTION_TRACE_CONNECTING = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.connecting',
  { defaultMessage: 'Connecting…' }
);

export const EXECUTION_TRACE_CONNECTED = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.connected',
  { defaultMessage: 'Connected' }
);

export const EXECUTION_TRACE_ERROR = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.error',
  { defaultMessage: 'Error' }
);

export const EXECUTION_TRACE_DOWNLOAD = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.download',
  { defaultMessage: 'Download log' }
);

export const EXECUTION_TRACE_PAUSE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.pause',
  { defaultMessage: 'Pause' }
);

export const EXECUTION_TRACE_RESUME = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.resume',
  { defaultMessage: 'Resume' }
);

export const EXECUTION_TRACE_LEVEL_FILTER = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.levelFilter',
  { defaultMessage: 'Level filter' }
);

export const EXECUTION_TRACE_LEVEL_ALL = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.levelAll',
  { defaultMessage: 'All levels' }
);

export const EXECUTION_TRACE_NO_LOGS_YET = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.noLogsYet',
  { defaultMessage: 'No trace logs yet.' }
);

export const ACTIONS_SEARCH_FILTERS_HAVE_BEEN_UPDATED_TITLE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.actionSearchFiltersUpdatedTitle',
  {
    defaultMessage: 'Global search filters have been updated',
  }
);

export const ACTIONS_SEARCH_FILTERS_HAVE_BEEN_UPDATED_DESCRIPTION = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.actionSearchFiltersUpdatedDescription',
  {
    defaultMessage: 'Search filters have been updated to show alerts from selected rule execution',
  }
);

export const ACTIONS_SEARCH_FILTERS_HAVE_BEEN_UPDATED_RESTORE_BUTTON = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.actionSearchFiltersUpdatedRestoreButtonTitle',
  {
    defaultMessage: 'Restore previous filters',
  }
);

export const ACTIONS_FIELD_NOT_FOUND_ERROR_TITLE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.actionFieldNotFoundErrorTitle',
  {
    defaultMessage: 'Unable to filter alerts',
  }
);

export const ACTIONS_FIELD_NOT_FOUND_ERROR = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.actionFieldNotFoundErrorDescription',
  {
    defaultMessage: "Cannot find field 'kibana.alert.rule.execution.uuid' in alerts index.",
  }
);

export const DURATION_NOT_AVAILABLE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.durationNotAvailableDescription',
  {
    defaultMessage: 'N/A',
  }
);

export const GREATER_THAN_YEAR = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.durationGreaterThanYearDescription',
  {
    defaultMessage: '> 1 Year',
  }
);

export const ROW_DETAILS_MESSAGE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.fullMessage',
  {
    defaultMessage: 'Full message',
  }
);

export const EXPAND_ROW = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.expandRow',
  {
    defaultMessage: 'Expand rows',
  }
);

export const EXPAND = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.expand',
  {
    defaultMessage: 'Expand',
  }
);

export const COLLAPSE = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.ruleExecutionLog.collapse',
  {
    defaultMessage: 'Collapse',
  }
);

export const ASK_AI_BUTTON = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.askAiButton',
  {
    defaultMessage: 'Ask AI',
  }
);

export const ASK_AI_TOOLTIP_DISABLED = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.askAiTooltipDisabled',
  {
    defaultMessage: 'AI Assistant requires Enterprise license',
  }
);

export const STATS_DURATION = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.statsDuration',
  {
    defaultMessage: 'Duration',
  }
);

export const STATS_SEARCH_TIME = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.statsSearchTime',
  {
    defaultMessage: 'Search Time',
  }
);

export const STATS_EVENTS = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.statsEvents',
  {
    defaultMessage: 'Events',
  }
);

export const STATS_ALERTS = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.statsAlerts',
  {
    defaultMessage: 'Alerts',
  }
);

export const STATS_SUPPRESSED = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.statsSuppressed',
  {
    defaultMessage: 'Suppressed',
  }
);

export const STATS_ERRORS = i18n.translate(
  'xpack.securitySolution.detectionEngine.ruleDetails.executionTrace.statsErrors',
  {
    defaultMessage: 'Errors',
  }
);
