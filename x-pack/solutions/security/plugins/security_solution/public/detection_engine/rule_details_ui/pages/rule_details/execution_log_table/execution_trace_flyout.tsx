/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import {
  EuiBadge,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiFieldSearch,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPortal,
  EuiToolTip,
  useEuiTheme,
} from '@elastic/eui';
import { css } from '@emotion/css';

import type { TailRuleExecutionTraceItem } from '../../../../../../common/api/detection_engine/rule_monitoring';
import { api } from '../../../../rule_monitoring';
import { useKibana } from '../../../../../common/lib/kibana';
import * as i18n from './translations';
import { IndexAnalysisPanel } from './index_analysis_panel';
import { FieldAnalysisPanel } from './field_analysis_panel';

// Group logs by execution_id
interface ExecutionGroup {
  executionId: string;
  startTime: string;
  logs: TailRuleExecutionTraceItem[];
}

// Stats computed from execution trace logs
interface ExecutionStats {
  totalDurationMs: number | null;
  searchDurationMs: number;
  searchCount: number;
  eventsMatched: number;
  alertsCreated: number;
  alertsSuppressed: number;
  errorCount: number;
  warningCount: number;
}

// Compute stats from trace items
const computeExecutionStats = (logs: TailRuleExecutionTraceItem[]): ExecutionStats => {
  const stats: ExecutionStats = {
    totalDurationMs: null,
    searchDurationMs: 0,
    searchCount: 0,
    eventsMatched: 0,
    alertsCreated: 0,
    alertsSuppressed: 0,
    errorCount: 0,
    warningCount: 0,
  };

  if (logs.length === 0) return stats;

  // Calculate total duration from first to last log
  const firstTs = new Date(logs[0].ts).getTime();
  const lastTs = new Date(logs[logs.length - 1].ts).getTime();
  stats.totalDurationMs = lastTs - firstTs;

  for (const log of logs) {
    // Count errors and warnings
    if (log.level === 'error') stats.errorCount++;
    if (log.level === 'warn') stats.warningCount++;

    // Parse message payload for detailed stats
    if (log.message && typeof log.message === 'object') {
      const msg = log.message as Record<string, unknown>;

      // ES search stats
      if (msg.response && typeof msg.response === 'object') {
        const response = msg.response as Record<string, unknown>;
        if (typeof response.took === 'number') {
          stats.searchDurationMs += response.took;
          stats.searchCount++;
        }
        if (response.hits && typeof response.hits === 'object') {
          const hits = response.hits as Record<string, unknown>;
          if (typeof hits.total === 'number') {
            stats.eventsMatched = Math.max(stats.eventsMatched, hits.total);
          }
        }
      }

      // Bulk create stats
      if (typeof msg.createdAlerts === 'number') {
        stats.alertsCreated += msg.createdAlerts;
      }
      if (typeof msg.suppressedAlerts === 'number' || typeof msg.alertsSuppressed === 'number') {
        stats.alertsSuppressed +=
          (msg.suppressedAlerts as number) || (msg.alertsSuppressed as number) || 0;
      }
    }

    // Also check message_text for patterns (fallback)
    const text = log.message_text.toLowerCase();

    // Match "X hits" patterns
    const hitsMatch = log.message_text.match(/→\s*(\d+)\s*hits/i);
    if (hitsMatch) {
      stats.eventsMatched = Math.max(stats.eventsMatched, parseInt(hitsMatch[1], 10));
    }

    // Match "took Xms" patterns
    const tookMatch = log.message_text.match(/(\d+)ms/);
    if (tookMatch && text.includes('search')) {
      stats.searchDurationMs += parseInt(tookMatch[1], 10);
      stats.searchCount++;
    }

    // Match "Created X alerts" patterns
    const alertsMatch = log.message_text.match(/created\s+(\d+)\s+alerts?/i);
    if (alertsMatch) {
      stats.alertsCreated = Math.max(stats.alertsCreated, parseInt(alertsMatch[1], 10));
    }
  }

  return stats;
};

// Theme-aware color palette using EUI theme tokens
interface TerminalColors {
  background: string;
  backgroundSecondary: string;
  border: string;
  text: string;
  textMuted: string;
  textDim: string;
  accent: string;
  accentSecondary: string;
  success: string;
  warning: string;
  error: string;
  info: string;
  code: string;
  hoverBg: string;
  selectedBg: string;
}

// Helper to create colors from EUI theme
const createTerminalColorsFromTheme = (
  euiTheme: ReturnType<typeof useEuiTheme>['euiTheme'],
  colorMode: string
): TerminalColors => {
  const isDark = colorMode === 'DARK';

  return {
    // Main terminal area - white in light mode, dark in dark mode
    background: isDark ? '#1a1c1e' : euiTheme.colors.emptyShade,
    // Sidebar & header - clean white in light mode, dark in dark mode
    backgroundSecondary: isDark ? '#25272a' : euiTheme.colors.emptyShade,
    border: euiTheme.colors.lightShade,
    text: euiTheme.colors.text,
    textMuted: euiTheme.colors.subduedText,
    textDim: euiTheme.colors.disabledText,
    accent: euiTheme.colors.primary,
    accentSecondary: euiTheme.colors.accent,
    success: euiTheme.colors.success,
    warning: euiTheme.colors.warning,
    error: euiTheme.colors.danger,
    info: euiTheme.colors.primary,
    code: isDark ? '#8abeb7' : euiTheme.colors.success,
    hoverBg: isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.04)',
    selectedBg: `${euiTheme.colors.primary}15`, // 8% opacity
  };
};

// Style generators that take colors as parameter
const createOverlayStyles = (colors: TerminalColors) => css`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 999; /* Lower than EUI flyout (1000+) so AI Assistant can appear on top */
  display: flex;
  flex-direction: column;
  background: ${colors.backgroundSecondary};
`;

const createHeaderStyles = (colors: TerminalColors) => css`
  background: ${colors.backgroundSecondary};
  border-bottom: 1px solid ${colors.border};
  padding: 12px 20px;
  flex-shrink: 0;
`;

const contentStyles = css`
  display: flex;
  flex: 1;
  overflow: hidden;
`;

const createSidebarStyles = (colors: TerminalColors) => css`
  width: 280px;
  background: ${colors.backgroundSecondary};
  border-right: 1px solid ${colors.border};
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
`;

const createSidebarHeaderStyles = (colors: TerminalColors) => css`
  padding: 12px 16px;
  border-bottom: 1px solid ${colors.border};
  color: ${colors.textMuted};
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
`;

const executionListStyles = css`
  flex: 1;
  overflow-y: auto;
`;

const createExecutionItemStyles = (colors: TerminalColors, isSelected: boolean) => css`
  padding: 12px 16px;
  cursor: pointer;
  border-bottom: 1px solid ${colors.border};
  background: ${isSelected ? colors.selectedBg : 'transparent'};
  border-left: 3px solid ${isSelected ? colors.accent : 'transparent'};
  transition: background 0.15s;

  &:hover {
    background: ${isSelected ? colors.selectedBg : colors.hoverBg};
  }
`;

const createExecutionIdLabelStyles = (colors: TerminalColors) => css`
  font-family: 'SF Mono', 'Monaco', 'Inconsolata', monospace;
  font-size: 12px;
  color: ${colors.accentSecondary};
  margin-bottom: 4px;
`;

const createExecutionTimeStyles = (colors: TerminalColors) => css`
  font-size: 11px;
  color: ${colors.textMuted};
`;

const createExecutionLogCountStyles = (colors: TerminalColors) => css`
  font-size: 10px;
  color: ${colors.textDim};
  margin-top: 4px;
`;

const createTerminalStyles = (colors: TerminalColors) => css`
  background: ${colors.background};
  color: ${colors.text};
  font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', 'Source Code Pro', monospace;
  font-size: 13px;
  line-height: 1.6;
  padding: 16px 20px;
  flex: 1;
  overflow-y: auto;
`;

const createLogLineStyles = (colors: TerminalColors) => css`
  margin: 0;
  padding: 4px 0;
  border-bottom: 1px solid ${colors.border}40;

  &:hover {
    background: ${colors.hoverBg};
  }
`;

const logLineHeaderStyles = css`
  display: flex;
  align-items: flex-start;
  gap: 8px;
  cursor: pointer;
`;

const logMessageStyles = css`
  flex: 1;
  white-space: pre-wrap;
  word-break: break-word;
`;

const createExpandButtonStyles = (colors: TerminalColors) => css`
  color: ${colors.textDim};
  font-size: 10px;
  padding: 2px 6px;
  border-radius: 3px;
  background: ${colors.hoverBg};
  border: none;
  cursor: pointer;
  flex-shrink: 0;

  &:hover {
    background: ${colors.border}40;
    color: ${colors.textMuted};
  }
`;

const createPayloadStyles = (colors: TerminalColors) => css`
  margin-top: 8px;
  padding: 12px;
  background: ${colors.backgroundSecondary};
  border-radius: 4px;
  font-size: 11px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
  color: ${colors.code};
  max-height: 300px;
  overflow-y: auto;
  position: relative;
  border: 1px solid ${colors.border};
`;

const createCopyButtonStyles = (colors: TerminalColors) => css`
  position: absolute;
  top: 8px;
  right: 8px;
  color: ${colors.textDim};
  font-size: 10px;
  padding: 4px 8px;
  border-radius: 3px;
  background: ${colors.hoverBg};
  border: 1px solid ${colors.border};
  cursor: pointer;

  &:hover {
    background: ${colors.border}40;
    color: ${colors.text};
  }
`;

const createTimestampStyles = (colors: TerminalColors) => css`
  color: ${colors.textMuted};
`;

const createLevelStyles = (colors: TerminalColors) => ({
  error: css`
    color: ${colors.error};
    font-weight: 600;
  `,
  warn: css`
    color: ${colors.warning};
  `,
  info: css`
    color: ${colors.info};
  `,
  debug: css`
    color: ${colors.textMuted};
  `,
  trace: css`
    color: ${colors.textDim};
  `,
});

const createStatusDotStyles = (colors: TerminalColors, connected: boolean) => css`
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: ${connected ? colors.success : colors.error};
  display: inline-block;
  animation: ${connected ? 'pulse 2s infinite' : 'none'};

  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }
`;

const createTitleStyles = (colors: TerminalColors) => css`
  color: ${colors.text};
  font-size: 14px;
  font-weight: 500;
  font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
`;

const createSubtitleStyles = (colors: TerminalColors) => css`
  color: ${colors.textDim};
  font-size: 12px;
  margin-left: 12px;
`;

const createButtonStyles = (colors: TerminalColors) => css`
  color: ${colors.textMuted} !important;
  &:hover {
    color: ${colors.text} !important;
    background: ${colors.hoverBg} !important;
  }
`;

const createIconButtonStyles = (colors: TerminalColors) => css`
  color: ${colors.textMuted} !important;
  &:hover {
    color: ${colors.text} !important;
    background: ${colors.border}40 !important;
  }
`;

const createEmptyStateStyles = (colors: TerminalColors) => css`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: ${colors.textDim};
  text-align: center;
  padding: 40px;
`;

const createExecutionHeaderStyles = (colors: TerminalColors) => css`
  background: ${colors.selectedBg};
  border-bottom: 1px solid ${colors.border};
  padding: 12px 20px;
  display: flex;
  align-items: center;
  gap: 12px;
`;

const createToolbarStyles = (colors: TerminalColors) => css`
  background: ${colors.backgroundSecondary};
  border-bottom: 1px solid ${colors.border};
  padding: 8px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
`;

const createSearchInputStyles = (colors: TerminalColors) => css`
  max-width: 240px;

  .euiFieldSearch {
    background: ${colors.background} !important;
    border-color: ${colors.border} !important;
    color: ${colors.text} !important;

    &::placeholder {
      color: ${colors.textDim} !important;
    }

    &:focus {
      border-color: ${colors.accent} !important;
    }
  }
`;

const createLevelPillStyles = (
  colors: TerminalColors,
  isActive: boolean,
  levelColor: string
) => css`
  cursor: pointer;
  background: ${isActive ? levelColor : 'transparent'} !important;
  border: 1px solid ${levelColor} !important;
  color: ${isActive ? colors.background : levelColor} !important;
  font-size: 11px !important;
  padding: 2px 8px !important;

  &:hover {
    background: ${isActive ? levelColor : `${levelColor}22`} !important;
  }
`;

const createMatchCountStyles = (colors: TerminalColors) => css`
  color: ${colors.textDim};
  font-size: 11px;
  margin-left: auto;
`;

const createStatsPanelStyles = (colors: TerminalColors) => css`
  background: ${colors.backgroundSecondary};
  border-bottom: 1px solid ${colors.border};
  padding: 12px 20px;
  display: flex;
  align-items: center;
  gap: 24px;
  flex-shrink: 0;
`;

const createStatItemStyles = (colors: TerminalColors) => css`
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  min-width: 80px;
`;

const createStatLabelStyles = (colors: TerminalColors) => css`
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: ${colors.textDim};
  margin-bottom: 2px;
`;

const createStatValueStyles = (colors: TerminalColors) => css`
  font-size: 16px;
  font-weight: 600;
  font-family: 'SF Mono', 'Monaco', monospace;
  color: ${colors.text};
`;

const createStatValueAccentStyles = (colors: TerminalColors, color: string) => css`
  font-size: 16px;
  font-weight: 600;
  font-family: 'SF Mono', 'Monaco', monospace;
  color: ${color};
`;

// Individual log line component with expand/collapse
const LogLine = ({
  item,
  formatTimestamp,
  getLevelStyle,
  getLevelLabel,
  copyToClipboard,
  colors,
}: {
  item: TailRuleExecutionTraceItem;
  formatTimestamp: (ts: string) => string;
  getLevelStyle: (level: string) => string;
  getLevelLabel: (level: string) => string;
  copyToClipboard: (text: string) => void;
  colors: TerminalColors;
}) => {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  // Check if this log has a payload (data after the | separator or in message field)
  const hasPayload = item.message !== undefined || item.message_text.includes(' | {');

  // Extract the display message (without payload) and the payload
  const pipeIndex = item.message_text.indexOf(' | {');
  const displayMessage = pipeIndex > -1 ? item.message_text.slice(0, pipeIndex) : item.message_text;
  const inlinePayload = pipeIndex > -1 ? item.message_text.slice(pipeIndex + 3) : null;
  let payload = item.message;
  if (!payload && inlinePayload) {
    try {
      payload = JSON.parse(inlinePayload);
    } catch {
      payload = null;
    }
  }

  const handleCopy = () => {
    const fullData = {
      timestamp: item.ts,
      level: item.level,
      execution_id: item.execution_id,
      message: displayMessage,
      ...(payload ? { data: payload } : {}),
    };
    copyToClipboard(JSON.stringify(fullData, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={createLogLineStyles(colors)}>
      <div className={logLineHeaderStyles} onClick={() => hasPayload && setExpanded(!expanded)}>
        <span className={createTimestampStyles(colors)}>{formatTimestamp(item.ts)}</span>
        <span className={getLevelStyle(item.level)}>{getLevelLabel(item.level)}</span>
        <span className={logMessageStyles} style={{ color: colors.text }}>
          {displayMessage}
        </span>
        {hasPayload && (
          <button
            className={createExpandButtonStyles(colors)}
            onClick={(e) => {
              e.stopPropagation();
              setExpanded(!expanded);
            }}
          >
            {expanded ? '▼ Hide' : '▶ Data'}
          </button>
        )}
      </div>
      {expanded && payload && (
        <div className={createPayloadStyles(colors)}>
          <button className={createCopyButtonStyles(colors)} onClick={handleCopy}>
            {copied ? '✓ Copied!' : 'Copy'}
          </button>
          {JSON.stringify(payload, null, 2)}
        </div>
      )}
    </div>
  );
};

export const ExecutionTraceFlyout = ({
  ruleId,
  ruleName,
  onClose,
}: {
  ruleId: string;
  ruleName?: string;
  onClose: () => void;
}) => {
  // Get theme colors from EUI
  const { euiTheme, colorMode } = useEuiTheme();
  const colors = useMemo(
    () => createTerminalColorsFromTheme(euiTheme, colorMode),
    [euiTheme, colorMode]
  );
  const levelStyles = useMemo(() => createLevelStyles(colors), [colors]);

  const [connected, setConnected] = useState(false);
  const [items, setItems] = useState<TailRuleExecutionTraceItem[]>([]);
  const [selectedExecutionId, setSelectedExecutionId] = useState<string | null>(null);
  const [isDownloading, setIsDownloading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [levelFilter, setLevelFilter] = useState<string | null>(null);
  const [showAnalysis, setShowAnalysis] = useState(false);
  const afterRef = useRef<{ ts?: string; seq?: number }>({});
  const inFlightRef = useRef(false);
  const terminalRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef(true);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const setSearchInputRef = useCallback((el: HTMLInputElement | null) => {
    searchInputRef.current = el;
  }, []);

  const dateStartIso = useMemo(() => new Date(Date.now() - 5 * 60 * 1000).toISOString(), []);

  // Group items by execution_id
  const executionGroups = useMemo(() => {
    // eslint-disable-next-line no-console
    console.log('[TRACE UI] grouping items, count:', items.length);

    const groups = new Map<string, ExecutionGroup>();

    for (const item of items) {
      const existing = groups.get(item.execution_id);
      if (existing) {
        existing.logs.push(item);
      } else {
        groups.set(item.execution_id, {
          executionId: item.execution_id,
          startTime: item.ts,
          logs: [item],
        });
      }
    }

    // Sort by start time descending (newest first)
    const sorted = Array.from(groups.values()).sort(
      (a, b) => new Date(b.startTime).getTime() - new Date(a.startTime).getTime()
    );

    // eslint-disable-next-line no-console
    console.log(
      '[TRACE UI] execution groups:',
      sorted.length,
      sorted.map((g) => g.executionId)
    );

    return sorted;
  }, [items]);

  // Auto-select newest execution when it arrives
  useEffect(() => {
    if (executionGroups.length > 0 && !selectedExecutionId) {
      setSelectedExecutionId(executionGroups[0].executionId);
    }
  }, [executionGroups, selectedExecutionId]);

  // Get logs for selected execution
  const selectedLogs = useMemo(() => {
    if (!selectedExecutionId) return [];
    const group = executionGroups.find((g) => g.executionId === selectedExecutionId);
    return group?.logs ?? [];
  }, [executionGroups, selectedExecutionId]);

  // Filter logs by search term and level
  const filteredLogs = useMemo(() => {
    let logs = selectedLogs;

    // Filter by level
    if (levelFilter) {
      logs = logs.filter((log) => log.level === levelFilter);
    }

    // Filter by search term
    if (searchTerm.trim()) {
      const term = searchTerm.toLowerCase();
      logs = logs.filter((log) => log.message_text.toLowerCase().includes(term));
    }

    return logs;
  }, [selectedLogs, levelFilter, searchTerm]);

  // Count logs by level for the pills
  const levelCounts = useMemo(() => {
    const counts: Record<string, number> = { error: 0, warn: 0, info: 0, debug: 0, trace: 0 };
    for (const log of selectedLogs) {
      if (counts[log.level] !== undefined) {
        counts[log.level]++;
      }
    }
    return counts;
  }, [selectedLogs]);

  // Compute execution stats from trace logs
  const executionStats = useMemo(() => computeExecutionStats(selectedLogs), [selectedLogs]);

  // Agent Builder integration
  const { agentBuilder } = useKibana().services;

  // Build AI prompt based on execution state
  const buildAiPrompt = useCallback(() => {
    const contextNote = `\n\nThe attached context includes: rule definition (query, filters, index patterns), exception list items, and execution logs.`;

    if (executionStats.errorCount > 0) {
      return `I have errors in this Security Detection Rule execution (Rule: ${
        ruleName || ruleId
      }). Please analyze the rule definition and error messages to explain: 1) What caused each error, 2) How to fix it, 3) Any related issues I should check.${contextNote}`;
    }
    if (executionStats.alertsCreated === 0 && executionStats.eventsMatched > 0) {
      return `This rule "${
        ruleName || ruleId
      }" matched ${executionStats.eventsMatched.toLocaleString()} events but created 0 alerts. Please check the attached exception list items and alert suppression settings to explain why alerts weren't created.${contextNote}`;
    }
    if (executionStats.alertsCreated === 0 && executionStats.eventsMatched === 0) {
      return `This rule "${
        ruleName || ruleId
      }" matched 0 events and created 0 alerts. Please analyze the rule query, index patterns, and time range in the attached context to explain why no events matched.${contextNote}`;
    }
    if (executionStats.searchDurationMs > 5000) {
      return `This rule "${ruleName || ruleId}" took ${
        executionStats.searchDurationMs
      }ms for Elasticsearch searches, which seems slow. Please analyze the rule query and filters in the attached context and suggest optimizations.${contextNote}`;
    }
    return `Analyze the execution of rule "${ruleName || ruleId}": Duration ${
      executionStats.totalDurationMs
    }ms, ${executionStats.eventsMatched} events matched, ${
      executionStats.alertsCreated
    } alerts created. Review the attached rule definition, exception items, and logs for any issues or optimizations.${contextNote}`;
  }, [ruleId, ruleName, executionStats]);

  // Build context attachment for Agent Builder with structured data for AI analysis
  const buildTraceContext = useCallback(() => {
    // Extract rule definition from trace logs
    const ruleDefLog = selectedLogs.find((l) => l.message_text.includes('[Rule Definition]'));
    const ruleDefinition: Record<string, unknown> | undefined =
      ruleDefLog?.message && typeof ruleDefLog.message === 'object'
        ? (ruleDefLog.message as Record<string, unknown>)
        : undefined;

    // Extract exception items from trace logs
    const exceptionLog = selectedLogs.find((l) => l.message_text.includes('[Exception Items]'));
    const exceptionItems: Record<string, unknown> | undefined =
      exceptionLog?.message && typeof exceptionLog.message === 'object'
        ? (exceptionLog.message as Record<string, unknown>)
        : undefined;

    // Extract ES requests with full query bodies (critical for debugging)
    const esRequests: Array<{
      description: string;
      request: unknown;
      response_summary: {
        took_ms: number;
        total_hits: number;
        sample_hits?: unknown[];
      };
    }> = [];

    for (const log of selectedLogs) {
      if (log.message_text.includes('[ES Request]') && log.message) {
        const msg = log.message as Record<string, unknown>;
        if (msg.request || msg.response) {
          const response = msg.response as Record<string, unknown> | undefined;
          const hits = response?.hits as Record<string, unknown> | undefined;
          esRequests.push({
            description: (msg.description as string) || 'ES Search',
            request: msg.request, // Full request body for AI to analyze
            response_summary: {
              took_ms: (response?.took as number) || 0,
              total_hits: (hits?.total as number) || 0,
              sample_hits: hits?.sample_hits as unknown[] | undefined, // Already extracted key fields
            },
          });
        }
      }
    }

    // Extract filtering funnel data
    interface FilteringStep {
      stage: string;
      events_before: number;
      events_after: number;
      events_filtered: number;
    }
    const filteringFunnel: FilteringStep[] = [];

    // Exception list filtering
    const exceptionFilterLog = selectedLogs.find((l) =>
      l.message_text.includes('[Exception list filtering]')
    );
    if (exceptionFilterLog?.message) {
      const msg = exceptionFilterLog.message as Record<string, unknown>;
      filteringFunnel.push({
        stage: 'exception_list',
        events_before: (msg.originalCount as number) || 0,
        events_after: (msg.includedCount as number) || 0,
        events_filtered: (msg.excludedCount as number) || 0,
      });
    }

    // Alert suppression grouping
    const suppressionLog = selectedLogs.find((l) =>
      l.message_text.includes('[Alert Suppression] Grouping')
    );
    if (suppressionLog?.message) {
      const msg = suppressionLog.message as Record<string, unknown>;
      filteringFunnel.push({
        stage: 'alert_suppression_grouping',
        events_before: (msg.totalEventsMatched as number) || 0,
        events_after: (msg.eventsToBeAlerts as number) || 0,
        events_filtered: (msg.eventsSuppressedByGrouping as number) || 0,
      });
    }

    // Alert suppression by time window
    const timeSuppressionLog = selectedLogs.find((l) =>
      l.message_text.includes('[Alert Suppression] Time-based')
    );
    if (timeSuppressionLog?.message) {
      const msg = timeSuppressionLog.message as Record<string, unknown>;
      filteringFunnel.push({
        stage: 'alert_suppression_time_window',
        events_before: (msg.inputAlerts as number) || 0,
        events_after: (msg.createdAlerts as number) || 0,
        events_filtered: (msg.suppressedByTimeWindow as number) || 0,
      });
    }

    // Extract errors and warnings with full context
    const errors = selectedLogs
      .filter((l) => l.level === 'error')
      .slice(0, 10)
      .map((l) => ({
        timestamp: l.ts,
        message: l.message_text,
        data: l.message,
      }));

    const warnings = selectedLogs
      .filter((l) => l.level === 'warn')
      .slice(0, 10)
      .map((l) => ({
        timestamp: l.ts,
        message: l.message_text,
        data: l.message,
      }));

    // Include ALL logs with their payloads (AI can analyze the full flow)
    // Filter out logs that are already extracted separately to reduce duplication
    const executionLogs = selectedLogs
      .filter(
        (l) =>
          !l.message_text.includes('[Rule Definition]') &&
          !l.message_text.includes('[Exception Items]') &&
          !l.message_text.includes('[Index Analysis]') &&
          !l.message_text.includes('[Field Analysis]')
      )
      .map((log) => ({
        ts: log.ts,
        level: log.level,
        message: log.message_text,
        // Include payload for logs that have structured data
        data: log.message && typeof log.message === 'object' ? log.message : undefined,
      }));

    return JSON.stringify(
      {
        // Execution identification
        rule_id: ruleId,
        rule_name: ruleName,
        execution_id: selectedExecutionId,

        // Execution summary (quick overview)
        summary: {
          duration_ms: executionStats.totalDurationMs,
          search_time_ms: executionStats.searchDurationMs,
          search_count: executionStats.searchCount,
          events_matched: executionStats.eventsMatched,
          alerts_created: executionStats.alertsCreated,
          alerts_suppressed: executionStats.alertsSuppressed,
          errors: executionStats.errorCount,
          warnings: executionStats.warningCount,
          status:
            executionStats.errorCount > 0
              ? 'failed'
              : executionStats.warningCount > 0
              ? 'partial_failure'
              : 'succeeded',
        },

        // Rule configuration (full - critical for understanding what the rule does)
        rule_definition: ruleDefinition,

        // Exception items (full - critical for understanding why events were filtered)
        exception_items: exceptionItems,

        // ES queries sent (full request bodies - critical for debugging query issues)
        elasticsearch_queries: esRequests.length > 0 ? esRequests : undefined,

        // Filtering funnel (shows how events were filtered at each stage)
        filtering_funnel: filteringFunnel.length > 0 ? filteringFunnel : undefined,

        // Errors and warnings with full context
        errors: errors.length > 0 ? errors : undefined,
        warnings: warnings.length > 0 ? warnings : undefined,

        // Full execution log (complete story of what happened)
        execution_logs: executionLogs,
      },
      null,
      2
    );
  }, [ruleId, ruleName, selectedExecutionId, executionStats, selectedLogs]);

  // Open Agent Builder with context
  const handleAskAI = useCallback(() => {
    if (!agentBuilder) return;

    agentBuilder.openConversationFlyout({
      newConversation: true,
      sessionTag: 'security-rule-trace',
      initialMessage: buildAiPrompt(),
      autoSendInitialMessage: false, // Let user review before sending
      attachments: [
        {
          id: 'rule-execution-trace',
          type: 'text',
          data: {
            content: buildTraceContext(),
          },
        },
      ],
    });
  }, [agentBuilder, buildAiPrompt, buildTraceContext]);

  const handleDownload = useCallback(async () => {
    setIsDownloading(true);
    try {
      await api.downloadRuleExecutionTrace({ ruleId, dateStart: dateStartIso });
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('Download failed:', e);
    } finally {
      setIsDownloading(false);
    }
  }, [ruleId, dateStartIso]);

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // ESC to close (unless in search input)
      if (e.key === 'Escape') {
        if (document.activeElement === searchInputRef.current) {
          searchInputRef.current?.blur();
          setSearchTerm('');
        } else {
          onClose();
        }
      }
      // Cmd+K or Ctrl+K to focus search
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
      // Cmd+L or Ctrl+L to clear filters
      if ((e.metaKey || e.ctrlKey) && e.key === 'l') {
        e.preventDefault();
        setSearchTerm('');
        setLevelFilter(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  // Connect on mount
  useEffect(() => {
    const abort = new AbortController();

    api
      .connectRuleExecutionTrace({ ruleId, ttlMs: 30 * 60 * 1000, signal: abort.signal })
      .then(() => setConnected(true))
      .catch(() => {
        if (!abort.signal.aborted) setConnected(false);
      });

    return () => abort.abort();
  }, [ruleId]);

  // Poll for new logs
  useEffect(() => {
    let stopped = false;

    const tick = async () => {
      if (stopped || inFlightRef.current) return;
      inFlightRef.current = true;

      try {
        const res = await api.tailRuleExecutionTrace({
          ruleId,
          dateStart: dateStartIso,
          afterTs: afterRef.current.ts,
          afterSeq: afterRef.current.seq,
          limit: 200,
        });

        // eslint-disable-next-line no-console
        console.log('[TRACE UI] tail response:', {
          itemCount: res.items.length,
          nextTs: res.next_after_ts,
          nextSeq: res.next_after_seq,
          firstItem: res.items[0],
        });

        if (res.items.length > 0) {
          afterRef.current = { ts: res.next_after_ts, seq: res.next_after_seq };
          setItems((prev) => {
            const next = [...prev, ...res.items];
            // eslint-disable-next-line no-console
            console.log('[TRACE UI] total items now:', next.length);
            return next.length > 10000 ? next.slice(next.length - 10000) : next;
          });
        }
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error('[TRACE UI] tail error:', err);
      } finally {
        inFlightRef.current = false;
      }
    };

    void tick();
    const interval = window.setInterval(() => void tick(), 1000);

    return () => {
      stopped = true;
      window.clearInterval(interval);
    };
  }, [ruleId, dateStartIso]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScrollRef.current && terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [selectedLogs]);

  const handleScroll = () => {
    if (!terminalRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = terminalRef.current;
    autoScrollRef.current = scrollHeight - scrollTop - clientHeight < 50;
  };

  const formatTimestamp = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalSecondDigits: 3,
      });
    } catch {
      return ts;
    }
  };

  const formatExecutionTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      });
    } catch {
      return ts;
    }
  };

  const getLevelStyle = useCallback(
    (level: string) => {
      return levelStyles[level as keyof typeof levelStyles] || levelStyles.debug;
    },
    [levelStyles]
  );

  const getLevelLabel = (level: string) => {
    return level.toUpperCase().padEnd(5);
  };

  const copyToClipboard = useCallback((text: string) => {
    navigator.clipboard.writeText(text).catch(() => {
      // Fallback for older browsers
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    });
  }, []);

  const selectedGroup = executionGroups.find((g) => g.executionId === selectedExecutionId);

  return (
    <EuiPortal>
      <div className={createOverlayStyles(colors)} data-test-subj="executionTraceFullScreen">
        {/* Header */}
        <div className={createHeaderStyles(colors)}>
          <EuiFlexGroup alignItems="center" gutterSize="m" responsive={false}>
            <EuiFlexItem grow={false}>
              <span className={createStatusDotStyles(colors, connected)} />
            </EuiFlexItem>
            <EuiFlexItem>
              <span className={createTitleStyles(colors)}>
                {ruleName || `Rule ${ruleId.slice(0, 8)}...`}
              </span>
              <span className={createSubtitleStyles(colors)}>
                {connected ? 'Live' : 'Connecting...'}
                {executionGroups.length > 0 && ` • ${executionGroups.length} executions`}
              </span>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiFlexGroup gutterSize="s" responsive={false} alignItems="center">
                <EuiFlexItem grow={false}>
                  <EuiToolTip content="Download all logs">
                    <EuiButtonIcon
                      iconType={isDownloading ? 'loading' : 'download'}
                      aria-label={i18n.EXECUTION_TRACE_DOWNLOAD}
                      onClick={handleDownload}
                      isDisabled={isDownloading}
                      className={createIconButtonStyles(colors)}
                      size="m"
                    />
                  </EuiToolTip>
                </EuiFlexItem>
                <EuiFlexItem grow={false} style={{ marginLeft: '8px' }}>
                  <EuiButtonEmpty size="s" onClick={onClose} className={createButtonStyles(colors)}>
                    Close (ESC)
                  </EuiButtonEmpty>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
          </EuiFlexGroup>
        </div>

        {/* Content */}
        <div className={contentStyles}>
          {/* Sidebar - Execution List */}
          <div className={createSidebarStyles(colors)}>
            <div className={createSidebarHeaderStyles(colors)}>Executions</div>
            <div className={executionListStyles}>
              {!connected && (
                <div style={{ padding: '20px', color: colors.textMuted, textAlign: 'center' }}>
                  <EuiLoadingSpinner size="s" />
                  <div style={{ marginTop: '8px' }}>Connecting...</div>
                </div>
              )}

              {connected && executionGroups.length === 0 && (
                <div
                  style={{
                    padding: '20px',
                    color: colors.textDim,
                    textAlign: 'center',
                    fontSize: '12px',
                  }}
                >
                  No executions yet.
                  <br />
                  Run the rule to see logs.
                </div>
              )}

              {executionGroups.map((group) => (
                <div
                  key={group.executionId}
                  className={createExecutionItemStyles(
                    colors,
                    group.executionId === selectedExecutionId
                  )}
                  onClick={() => setSelectedExecutionId(group.executionId)}
                >
                  <div className={createExecutionIdLabelStyles(colors)}>
                    {group.executionId.slice(0, 12)}...
                  </div>
                  <div className={createExecutionTimeStyles(colors)}>
                    {formatExecutionTime(group.startTime)}
                  </div>
                  <div className={createExecutionLogCountStyles(colors)}>
                    {group.logs.length} log lines
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Main Terminal Area */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            {/* Stats Dashboard Panel */}
            {selectedGroup && selectedLogs.length > 0 && (
              <div className={createStatsPanelStyles(colors)}>
                <div className={createStatItemStyles(colors)}>
                  <span className={createStatLabelStyles(colors)}>Duration</span>
                  <span className={createStatValueStyles(colors)}>
                    {executionStats.totalDurationMs !== null
                      ? executionStats.totalDurationMs < 1000
                        ? `${executionStats.totalDurationMs}ms`
                        : `${(executionStats.totalDurationMs / 1000).toFixed(1)}s`
                      : '—'}
                  </span>
                </div>
                <div className={createStatItemStyles(colors)}>
                  <span className={createStatLabelStyles(colors)}>Search Time</span>
                  <span className={createStatValueStyles(colors)}>
                    {executionStats.searchDurationMs > 0
                      ? `${executionStats.searchDurationMs}ms`
                      : '—'}
                  </span>
                </div>
                <div className={createStatItemStyles(colors)}>
                  <span className={createStatLabelStyles(colors)}>Events</span>
                  <span className={createStatValueStyles(colors)}>
                    {executionStats.eventsMatched > 0
                      ? executionStats.eventsMatched.toLocaleString()
                      : '—'}
                  </span>
                </div>
                <div className={createStatItemStyles(colors)}>
                  <span className={createStatLabelStyles(colors)}>Alerts</span>
                  <span
                    className={createStatValueAccentStyles(
                      colors,
                      executionStats.alertsCreated > 0 ? colors.success : colors.textMuted
                    )}
                  >
                    {executionStats.alertsCreated}
                  </span>
                </div>
                {executionStats.alertsSuppressed > 0 && (
                  <div className={createStatItemStyles(colors)}>
                    <span className={createStatLabelStyles(colors)}>Suppressed</span>
                    <span className={createStatValueStyles(colors)}>
                      {executionStats.alertsSuppressed}
                    </span>
                  </div>
                )}
                {executionStats.errorCount > 0 && (
                  <div className={createStatItemStyles(colors)}>
                    <span className={createStatLabelStyles(colors)}>Errors</span>
                    <span className={createStatValueAccentStyles(colors, colors.error)}>
                      {executionStats.errorCount}
                    </span>
                  </div>
                )}

                {/* AI Agent Button */}
                {agentBuilder && (
                  <EuiButtonEmpty
                    size="s"
                    iconType="sparkles"
                    onClick={handleAskAI}
                    data-test-subj="askAiButton"
                  >
                    {'Ask AI'}
                  </EuiButtonEmpty>
                )}

                {/* Analysis Toggle Button */}
                <EuiToolTip
                  content={
                    showAnalysis ? 'Hide index & field analysis' : 'Show index & field analysis'
                  }
                >
                  <EuiButtonIcon
                    iconType={showAnalysis ? 'arrowUp' : 'arrowDown'}
                    aria-label="Toggle analysis panels"
                    onClick={() => setShowAnalysis(!showAnalysis)}
                    size="s"
                    color="text"
                    style={{ marginLeft: 8 }}
                  />
                </EuiToolTip>
              </div>
            )}

            {/* Index & Field Analysis Panels (collapsible) */}
            {showAnalysis && selectedLogs.length > 0 && (
              <div
                style={{
                  padding: '12px 20px',
                  background: colors.backgroundSecondary,
                  borderBottom: `1px solid ${colors.border}`,
                  display: 'flex',
                  gap: 16,
                  overflowX: 'auto',
                }}
              >
                <div style={{ flex: 1, minWidth: 300 }}>
                  <IndexAnalysisPanel logs={selectedLogs} />
                </div>
                <div style={{ flex: 1, minWidth: 300 }}>
                  <FieldAnalysisPanel logs={selectedLogs} />
                </div>
              </div>
            )}

            {/* Execution Header (when no stats) */}
            {selectedGroup && selectedLogs.length === 0 && (
              <div className={createExecutionHeaderStyles(colors)}>
                <span
                  style={{
                    color: colors.accentSecondary,
                    fontFamily: 'monospace',
                    fontSize: '13px',
                  }}
                >
                  {selectedGroup.executionId}
                </span>
                <span style={{ color: colors.textDim, fontSize: '12px' }}>
                  Started {formatExecutionTime(selectedGroup.startTime)}
                </span>
                <span style={{ color: colors.textMuted, fontSize: '11px', marginLeft: 'auto' }}>
                  Waiting for logs...
                </span>
              </div>
            )}

            {/* Search & Filter Toolbar */}
            {selectedExecutionId && selectedLogs.length > 0 && (
              <div className={createToolbarStyles(colors)}>
                <div className={createSearchInputStyles(colors)}>
                  <EuiFieldSearch
                    inputRef={setSearchInputRef}
                    placeholder="Search logs... (⌘K)"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    isClearable
                    compressed
                  />
                </div>

                <EuiFlexGroup gutterSize="xs" responsive={false} alignItems="center">
                  {levelCounts.error > 0 && (
                    <EuiFlexItem grow={false}>
                      <EuiBadge
                        className={createLevelPillStyles(
                          colors,
                          levelFilter === 'error',
                          colors.error
                        )}
                        onClick={() => setLevelFilter(levelFilter === 'error' ? null : 'error')}
                        onClickAriaLabel="Filter errors"
                      >
                        ERR {levelCounts.error}
                      </EuiBadge>
                    </EuiFlexItem>
                  )}
                  {levelCounts.warn > 0 && (
                    <EuiFlexItem grow={false}>
                      <EuiBadge
                        className={createLevelPillStyles(
                          colors,
                          levelFilter === 'warn',
                          colors.warning
                        )}
                        onClick={() => setLevelFilter(levelFilter === 'warn' ? null : 'warn')}
                        onClickAriaLabel="Filter warnings"
                      >
                        WARN {levelCounts.warn}
                      </EuiBadge>
                    </EuiFlexItem>
                  )}
                  {levelCounts.info > 0 && (
                    <EuiFlexItem grow={false}>
                      <EuiBadge
                        className={createLevelPillStyles(
                          colors,
                          levelFilter === 'info',
                          colors.info
                        )}
                        onClick={() => setLevelFilter(levelFilter === 'info' ? null : 'info')}
                        onClickAriaLabel="Filter info"
                      >
                        INFO {levelCounts.info}
                      </EuiBadge>
                    </EuiFlexItem>
                  )}
                  {levelCounts.debug > 0 && (
                    <EuiFlexItem grow={false}>
                      <EuiBadge
                        className={createLevelPillStyles(
                          colors,
                          levelFilter === 'debug',
                          colors.textMuted
                        )}
                        onClick={() => setLevelFilter(levelFilter === 'debug' ? null : 'debug')}
                        onClickAriaLabel="Filter debug"
                      >
                        DEBUG {levelCounts.debug}
                      </EuiBadge>
                    </EuiFlexItem>
                  )}
                  {levelCounts.trace > 0 && (
                    <EuiFlexItem grow={false}>
                      <EuiBadge
                        className={createLevelPillStyles(
                          colors,
                          levelFilter === 'trace',
                          colors.textDim
                        )}
                        onClick={() => setLevelFilter(levelFilter === 'trace' ? null : 'trace')}
                        onClickAriaLabel="Filter trace"
                      >
                        TRACE {levelCounts.trace}
                      </EuiBadge>
                    </EuiFlexItem>
                  )}
                </EuiFlexGroup>

                {(searchTerm || levelFilter) && (
                  <span className={createMatchCountStyles(colors)}>
                    {filteredLogs.length} of {selectedLogs.length} logs
                  </span>
                )}
              </div>
            )}

            <div ref={terminalRef} className={createTerminalStyles(colors)} onScroll={handleScroll}>
              {!selectedExecutionId && connected && executionGroups.length === 0 && (
                <div className={createEmptyStateStyles(colors)}>
                  <div style={{ color: colors.success, marginBottom: '12px', fontSize: '20px' }}>
                    ●
                  </div>
                  <div style={{ fontSize: '14px', marginBottom: '8px' }}>Connected & Waiting</div>
                  <div style={{ fontSize: '12px' }}>
                    Run the rule to see execution logs here.
                    <br />
                    Logs from the last 5 minutes will appear automatically.
                  </div>
                </div>
              )}

              {filteredLogs.map((item, idx) => (
                <LogLine
                  key={`${item.execution_id}-${item.seq}-${idx}`}
                  item={item}
                  formatTimestamp={formatTimestamp}
                  getLevelStyle={getLevelStyle}
                  getLevelLabel={getLevelLabel}
                  copyToClipboard={copyToClipboard}
                  colors={colors}
                />
              ))}

              {filteredLogs.length === 0 && selectedLogs.length > 0 && (
                <div className={createEmptyStateStyles(colors)}>
                  <div style={{ fontSize: '14px', marginBottom: '8px' }}>No matching logs</div>
                  <div style={{ fontSize: '12px' }}>
                    Try adjusting your search or filter.
                    <br />
                    <button
                      style={{
                        color: colors.accent,
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        marginTop: '8px',
                      }}
                      onClick={() => {
                        setSearchTerm('');
                        setLevelFilter(null);
                      }}
                    >
                      Clear filters (⌘L)
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </EuiPortal>
  );
};

/**
 * Small badge component to show on the rule page when trace is active
 * Note: This is a placeholder - we need a separate "check session" API
 * to avoid creating/overwriting sessions just to check status.
 * For now, this badge is disabled.
 */
export const TraceStatusBadge = ({ ruleId, onClick }: { ruleId: string; onClick?: () => void }) => {
  // Disabled for now - the connect API overwrites existing sessions
  // TODO: Add a separate GET endpoint to check session status
  return null;
};
