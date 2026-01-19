/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from 'react';
import {
  EuiPanel,
  EuiTitle,
  EuiSpacer,
  EuiBasicTable,
  EuiCallOut,
  EuiBadge,
  EuiFlexGroup,
  EuiFlexItem,
  EuiToolTip,
  EuiIcon,
  useEuiTheme,
  type EuiBasicTableColumn,
} from '@elastic/eui';
import { css } from '@emotion/css';
import type { TailRuleExecutionTraceItem } from '../../../../../../common/api/detection_engine/rule_monitoring';

interface FieldInfo {
  name: string;
  type: string;
  aggregatable: boolean;
  has_keyword: boolean;
  used_in: 'query' | 'filter' | 'suppression';
}

interface FieldAnalysisData {
  total_fields_analyzed: number;
  query_fields: string[];
  filter_fields: string[];
  suppression_fields: string[];
  fields: FieldInfo[];
  fields_with_issues: string[];
  suggestions: string[];
}

interface CardinalityWarning {
  field: string;
  cardinality: number;
  warning: string;
}

interface FieldAnalysisPanelProps {
  logs: TailRuleExecutionTraceItem[];
}

const TYPE_COLORS: Record<string, string> = {
  keyword: 'primary',
  text: 'warning',
  date: 'accent',
  long: 'success',
  integer: 'success',
  boolean: 'success',
  ip: 'primary',
  unknown: 'danger',
};

export const FieldAnalysisPanel: React.FC<FieldAnalysisPanelProps> = ({ logs }) => {
  const { euiTheme } = useEuiTheme();

  const analysis = useMemo((): FieldAnalysisData | null => {
    const log = logs.find((l) => l.message_text.includes('[Field Analysis] Query field mappings'));
    if (!log?.message || typeof log.message !== 'object') return null;
    return log.message as FieldAnalysisData;
  }, [logs]);

  const cardinalityWarnings = useMemo((): CardinalityWarning[] => {
    return logs
      .filter((l) => l.message_text.includes('[Field Analysis] High cardinality'))
      .filter((l) => l.message && typeof l.message === 'object')
      .map((l) => l.message as CardinalityWarning);
  }, [logs]);

  const columns: Array<EuiBasicTableColumn<FieldInfo>> = useMemo(
    () => [
      {
        field: 'name',
        name: 'Field',
        truncateText: true,
        width: '35%',
        render: (name: string, item: FieldInfo) => {
          const hasIssue = analysis?.fields_with_issues.includes(name);
          return (
            <EuiFlexGroup alignItems="center" gutterSize="xs">
              <EuiFlexItem grow={false}>
                <code>{name}</code>
              </EuiFlexItem>
              {hasIssue && (
                <EuiFlexItem grow={false}>
                  <EuiToolTip content="This field has optimization suggestions">
                    <EuiIcon type="warning" color="warning" size="s" />
                  </EuiToolTip>
                </EuiFlexItem>
              )}
            </EuiFlexGroup>
          );
        },
      },
      {
        field: 'type',
        name: 'Type',
        width: '15%',
        render: (type: string) => (
          <EuiBadge color={TYPE_COLORS[type] || 'default'}>{type}</EuiBadge>
        ),
      },
      {
        field: 'used_in',
        name: 'Used In',
        width: '15%',
        render: (usedIn: string) => {
          const colors: Record<string, string> = {
            query: 'primary',
            filter: 'accent',
            suppression: 'success',
          };
          return <EuiBadge color={colors[usedIn] || 'default'}>{usedIn}</EuiBadge>;
        },
      },
      {
        field: 'aggregatable',
        name: 'Aggregatable',
        width: '15%',
        render: (aggregatable: boolean) =>
          aggregatable ? (
            <EuiIcon type="check" color="success" />
          ) : (
            <EuiIcon type="cross" color="subdued" />
          ),
      },
      {
        field: 'has_keyword',
        name: '.keyword',
        width: '10%',
        render: (hasKeyword: boolean, item: FieldInfo) =>
          item.type === 'text' ? (
            hasKeyword ? (
              <EuiIcon type="check" color="success" />
            ) : (
              <EuiToolTip content="Text field without .keyword subfield - exact matching will be slow">
                <EuiIcon type="warning" color="warning" />
              </EuiToolTip>
            )
          ) : (
            <span>-</span>
          ),
      },
      {
        name: 'Status',
        width: '10%',
        render: (item: FieldInfo) => {
          const hasIssue = analysis?.fields_with_issues.includes(item.name);
          return hasIssue ? (
            <EuiBadge color="warning">Optimize</EuiBadge>
          ) : (
            <EuiBadge color="success">OK</EuiBadge>
          );
        },
      },
    ],
    [analysis]
  );

  if (!analysis) {
    return null;
  }

  const hasIssues = analysis.suggestions.length > 0 || cardinalityWarnings.length > 0;

  return (
    <EuiPanel
      paddingSize="m"
      hasShadow={false}
      hasBorder
      className={css`
        background: ${euiTheme.colors.backgroundBasePlain};
      `}
    >
      <EuiFlexGroup alignItems="center" gutterSize="s">
        <EuiFlexItem grow={false}>
          <EuiTitle size="xs">
            <h4>Field Mapping Analysis</h4>
          </EuiTitle>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiBadge color="hollow">{analysis.total_fields_analyzed} fields</EuiBadge>
        </EuiFlexItem>
        {analysis.fields_with_issues.length > 0 && (
          <EuiFlexItem grow={false}>
            <EuiBadge color="warning">{analysis.fields_with_issues.length} issues</EuiBadge>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>

      {hasIssues && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut
            announceOnMount
            title="Field Optimization Suggestions"
            color="warning"
            size="s"
            iconType="bulb"
          >
            <ul style={{ margin: 0, paddingLeft: 16 }}>
              {analysis.suggestions.map((suggestion, i) => (
                <li key={i}>{suggestion}</li>
              ))}
              {cardinalityWarnings.map((warning, i) => (
                <li key={`card-${i}`}>{warning.warning}</li>
              ))}
            </ul>
          </EuiCallOut>
        </>
      )}

      <EuiSpacer size="s" />

      <EuiBasicTable items={analysis.fields} columns={columns} tableLayout="fixed" compressed />
    </EuiPanel>
  );
};
