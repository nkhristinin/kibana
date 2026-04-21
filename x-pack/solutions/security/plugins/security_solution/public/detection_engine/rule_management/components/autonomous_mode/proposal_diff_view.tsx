/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from 'react';
import {
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPanel,
  EuiText,
} from '@elastic/eui';
import { DiffView } from '../rule_details/json_diff/diff_view';
import { useFetchRuleByIdQuery } from '../../api/hooks/use_fetch_rule_by_id_query';

interface Props {
  ruleId: string;
  proposedChanges: Record<string, unknown>;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

interface FallbackProps {
  oldSource: string;
  newSource: string;
}

/**
 * Class-based error boundary — falls back to plain side-by-side JSON panels
 * when the underlying react-diff-view library throws (it does so on certain
 * edge cases such as one-sided empty diffs).
 */
class DiffErrorBoundary extends React.Component<
  React.PropsWithChildren<FallbackProps>,
  { hasError: boolean }
> {
  constructor(props: React.PropsWithChildren<FallbackProps>) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch() {
    // swallow — the fallback UI explains what happened
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    const preStyle: React.CSSProperties = {
      whiteSpace: 'pre-wrap',
      fontSize: 12,
      margin: 0,
      overflow: 'auto',
      maxHeight: 240,
    };

    return (
      <EuiFlexGroup gutterSize="s">
        <EuiFlexItem>
          <EuiText size="xs">
            <strong>Current</strong>
          </EuiText>
          <EuiPanel paddingSize="s" hasBorder color="subdued">
            <pre style={preStyle}>{this.props.oldSource}</pre>
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiText size="xs">
            <strong>Proposed</strong>
          </EuiText>
          <EuiPanel paddingSize="s" hasBorder color="subdued">
            <pre style={preStyle}>{this.props.newSource}</pre>
          </EuiPanel>
        </EuiFlexItem>
      </EuiFlexGroup>
    );
  }
}

export const ProposalDiffView: React.FC<Props> = ({ ruleId, proposedChanges }) => {
  const { data: rule, isLoading, error } = useFetchRuleByIdQuery(ruleId);

  const { oldSource, newSource } = useMemo(() => {
    if (!rule) return { oldSource: '', newSource: '' };

    // Diff only the fields the proposal touches — keeps output focused.
    const changedKeys = Object.keys(proposedChanges);
    const original: Record<string, unknown> = {};
    const patched: Record<string, unknown> = {};
    for (const key of changedKeys) {
      original[key] = (rule as unknown as Record<string, unknown>)[key];
      patched[key] = proposedChanges[key];
    }

    // For nested objects (e.g. threshold), keep the base values so only the
    // overridden inner fields show as changes.
    for (const key of changedKeys) {
      const base = original[key];
      const next = patched[key];
      if (isObject(base) && isObject(next)) {
        patched[key] = { ...base, ...next };
      }
    }

    return {
      oldSource: JSON.stringify(original, null, 2),
      newSource: JSON.stringify(patched, null, 2),
    };
  }, [rule, proposedChanges]);

  if (isLoading) return <EuiLoadingSpinner size="m" />;
  if (error)
    return (
      <EuiCallOut color="danger" title="Failed to load current rule">
        {error instanceof Error ? error.message : 'Unknown error'}
      </EuiCallOut>
    );
  if (!rule)
    return (
      <EuiText size="s" color="subdued">
        Rule not found.
      </EuiText>
    );
  if (Object.keys(proposedChanges).length === 0)
    return (
      <EuiText size="s" color="subdued">
        No field changes in the proposal.
      </EuiText>
    );
  if (oldSource === newSource)
    return (
      <EuiText size="s" color="subdued">
        Proposed values are identical to the current rule — no effective change.
      </EuiText>
    );

  return (
    <DiffErrorBoundary oldSource={oldSource} newSource={newSource}>
      <DiffView
        oldSource={oldSource}
        newSource={newSource}
        viewType="split"
        data-test-subj="proposal-diff"
      />
    </DiffErrorBoundary>
  );
};
