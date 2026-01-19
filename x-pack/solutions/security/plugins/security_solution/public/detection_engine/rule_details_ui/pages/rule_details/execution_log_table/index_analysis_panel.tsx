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
  EuiFlexGroup,
  EuiFlexItem,
  EuiText,
  EuiBadge,
  useEuiTheme,
  type EuiBasicTableColumn,
} from '@elastic/eui';
import { css } from '@emotion/css';
import type { TailRuleExecutionTraceItem } from '../../../../../../common/api/detection_engine/rule_monitoring';

interface IndexInfo {
  name: string;
  docs: number;
  size?: string;
  size_bytes?: number;
  health?: string;
  is_frozen?: boolean;
  is_data_stream?: boolean;
  data_stream?: string;
  shards?: number;
  replicas?: number;
  created?: string;
}

interface IndexAnalysisData {
  patterns_configured: string[];
  total_indices_resolved: number;
  active_indices: number;
  empty_indices: number;
  frozen_indices?: number;
  data_stream_indices?: number;
  total_size_bytes?: number;
  total_size_human?: string;
  indices: IndexInfo[];
  suggestions: string[];
}

interface IndexAnalysisPanelProps {
  logs: TailRuleExecutionTraceItem[];
}

export const IndexAnalysisPanel: React.FC<IndexAnalysisPanelProps> = ({ logs }) => {
  const { euiTheme } = useEuiTheme();

  const analysis = useMemo((): IndexAnalysisData | null => {
    const log = logs.find((l) => l.message_text.includes('[Index Analysis]'));
    if (!log?.message || typeof log.message !== 'object') return null;
    return log.message as IndexAnalysisData;
  }, [logs]);

  const columns: Array<EuiBasicTableColumn<IndexInfo>> = useMemo(
    () => [
      {
        field: 'name',
        name: 'Index',
        truncateText: true,
        width: '60%',
        render: (name: string, item: IndexInfo) => (
          <EuiFlexGroup gutterSize="xs" alignItems="center" responsive={false}>
            <EuiFlexItem grow={false}>
              <span style={{ fontFamily: 'monospace', fontSize: '12px' }}>{name}</span>
            </EuiFlexItem>
            {item.is_frozen && (
              <EuiFlexItem grow={false}>
                <EuiBadge color="primary" iconType="snowflake">
                  {'Frozen'}
                </EuiBadge>
              </EuiFlexItem>
            )}
            {item.is_data_stream && (
              <EuiFlexItem grow={false}>
                <EuiBadge color="hollow">{'DS'}</EuiBadge>
              </EuiFlexItem>
            )}
          </EuiFlexGroup>
        ),
      },
      {
        field: 'docs',
        name: 'Documents',
        render: (docs: number) => (docs >= 0 ? docs.toLocaleString() : 'N/A'),
        width: '20%',
      },
      {
        field: 'size',
        name: 'Size',
        render: (size: string | undefined) => size || '-',
        width: '20%',
      },
    ],
    []
  );

  if (!analysis) {
    return null;
  }

  const hasEmptyIndices = analysis.empty_indices > 0;
  const hasFrozenIndices = (analysis.frozen_indices ?? 0) > 0;

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
            <h4>{'Index Pattern Analysis'}</h4>
          </EuiTitle>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiBadge color="hollow">
            {analysis.total_indices_resolved} {'indices'}
          </EuiBadge>
        </EuiFlexItem>
        {analysis.total_size_human && (
          <EuiFlexItem grow={false}>
            <EuiBadge color="hollow">{analysis.total_size_human}</EuiBadge>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>

      <EuiSpacer size="s" />

      <EuiFlexGroup gutterSize="m" wrap>
        <EuiFlexItem grow={false}>
          <EuiText size="s" color="success">
            <strong>{analysis.active_indices}</strong> {'active'}
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiText size="s" color={hasEmptyIndices ? 'warning' : 'subdued'}>
            <strong>{analysis.empty_indices}</strong> {'empty'}
          </EuiText>
        </EuiFlexItem>
        {hasFrozenIndices && (
          <EuiFlexItem grow={false}>
            <EuiText size="s" color="primary">
              <strong>{analysis.frozen_indices}</strong> {'frozen'}
            </EuiText>
          </EuiFlexItem>
        )}
        {(analysis.data_stream_indices ?? 0) > 0 && (
          <EuiFlexItem grow={false}>
            <EuiText size="s" color="subdued">
              <strong>{analysis.data_stream_indices}</strong> {'data streams'}
            </EuiText>
          </EuiFlexItem>
        )}
      </EuiFlexGroup>

      {analysis.suggestions.length > 0 && (
        <>
          <EuiSpacer size="s" />
          <EuiCallOut
            announceOnMount
            title={'Optimization Opportunity'}
            color={hasFrozenIndices ? 'primary' : 'warning'}
            size="s"
            iconType={hasFrozenIndices ? 'snowflake' : 'bulb'}
          >
            {analysis.suggestions.map((suggestion, i) => (
              <p key={i}>{suggestion}</p>
            ))}
          </EuiCallOut>
        </>
      )}

      <EuiSpacer size="s" />

      <EuiBasicTable items={analysis.indices} columns={columns} tableLayout="fixed" compressed />

      {analysis.indices.length >= 20 && (
        <EuiText size="xs" color="subdued" textAlign="center">
          Showing first 20 indices
        </EuiText>
      )}
    </EuiPanel>
  );
};
