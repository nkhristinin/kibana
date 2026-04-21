/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useCallback, useState } from 'react';
import {
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiLink,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import type { EuiBasicTableColumn } from '@elastic/eui';
import { useKibana } from '../../../../common/lib/kibana';
import { ExecutionDetailsView } from './execution_details_view';
import { usePendingApprovals } from './use_pending_approvals';
import type { PendingApproval, ExecutionDetails } from './use_pending_approvals';

const workflowsUrlFor = (
  basePath: { prepend: (p: string) => string },
  workflowId: string,
  executionId: string
): string =>
  basePath.prepend(
    `/app/workflows/${encodeURIComponent(workflowId)}?executionId=${encodeURIComponent(
      executionId
    )}&tab=executions`
  );


export const PendingApprovalsPanel: React.FC = () => {
  const { approvals, isLoading, error, resume, fetchDetails } = usePendingApprovals();
  const { http } = useKibana().services;

  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [expandedMap, setExpandedMap] = useState<
    Record<string, React.ReactNode>
  >({});
  const [detailsCache, setDetailsCache] = useState<
    Record<string, ExecutionDetails | 'loading' | Error>
  >({});

  const toggleExpand = useCallback(
    async (row: PendingApproval) => {
      const id = row.executionId;
      setExpandedMap((prev) => {
        if (prev[id]) {
          const next = { ...prev };
          delete next[id];
          return next;
        }
        return {
          ...prev,
          [id]: (
            <ExecutionDetailsView ruleId={row.ruleId} details={detailsCache[id] ?? 'loading'} />
          ),
        };
      });

      if (expandedMap[id]) return; // collapsing

      if (!detailsCache[id]) {
        setDetailsCache((prev) => ({ ...prev, [id]: 'loading' }));
        try {
          const details = await fetchDetails(id);
          setDetailsCache((prev) => ({ ...prev, [id]: details }));
          setExpandedMap((prev) =>
            prev[id]
              ? { ...prev, [id]: <ExecutionDetailsView ruleId={row.ruleId} details={details} /> }
              : prev
          );
        } catch (err) {
          const e = err instanceof Error ? err : new Error(String(err));
          setDetailsCache((prev) => ({ ...prev, [id]: e }));
          setExpandedMap((prev) =>
            prev[id]
              ? { ...prev, [id]: <ExecutionDetailsView ruleId={row.ruleId} details={e} /> }
              : prev
          );
        }
      }
    },
    [detailsCache, expandedMap, fetchDetails]
  );

  const handle = async (executionId: string, approved: boolean) => {
    setPendingAction(`${executionId}:${approved ? 'approve' : 'reject'}`);
    try {
      await resume(executionId, approved);
    } finally {
      setPendingAction(null);
    }
  };

  const columns: Array<EuiBasicTableColumn<PendingApproval>> = [
    {
      align: 'left',
      width: '40px',
      isExpander: true,
      name: '',
      render: (row: PendingApproval) => (
        <EuiButtonIcon
          aria-label={expandedMap[row.executionId] ? 'Collapse' : 'Expand'}
          iconType={expandedMap[row.executionId] ? 'arrowDown' : 'arrowRight'}
          onClick={() => toggleExpand(row)}
          data-test-subj={`expand-${row.executionId}`}
        />
      ),
    },
    {
      field: 'ruleId',
      name: 'Rule',
      render: (ruleId?: string) => ruleId ?? '—',
    },
    {
      field: 'workflowName',
      name: 'Workflow',
      render: (workflowName: string | undefined, row: PendingApproval) => (
        <EuiLink
          href={workflowsUrlFor(http.basePath, row.workflowId, row.executionId)}
          target="_blank"
          external
        >
          {workflowName ?? row.workflowId}
        </EuiLink>
      ),
    },
    {
      field: 'startedAt',
      name: 'Started',
      render: (startedAt: string) => new Date(startedAt).toLocaleString(),
    },
    {
      name: 'Actions',
      actions: [
        {
          render: (row: PendingApproval) => (
            <EuiButton
              size="s"
              color="primary"
              fill
              isLoading={pendingAction === `${row.executionId}:approve`}
              onClick={() => handle(row.executionId, true)}
              data-test-subj={`approve-${row.executionId}`}
            >
              Approve
            </EuiButton>
          ),
        },
        {
          render: (row: PendingApproval) => (
            <EuiButtonEmpty
              size="s"
              color="danger"
              isLoading={pendingAction === `${row.executionId}:reject`}
              onClick={() => handle(row.executionId, false)}
              data-test-subj={`reject-${row.executionId}`}
            >
              Reject
            </EuiButtonEmpty>
          ),
        },
      ],
    },
  ];

  return (
    <>
      <EuiPanel paddingSize="m" hasBorder data-test-subj="pending-approvals-panel">
        <EuiTitle size="xs">
          <h3>Pending automation approvals</h3>
        </EuiTitle>
        <EuiText size="xs" color="subdued">
          <p>Workflow executions waiting for input from monitored automation workflows.</p>
        </EuiText>
        <EuiSpacer size="s" />
        {error && (
          <>
            <EuiCallOut color="danger" title="Failed to load pending approvals">
              {error.message}
            </EuiCallOut>
            <EuiSpacer size="s" />
          </>
        )}
        {isLoading ? (
          <EuiLoadingSpinner size="m" />
        ) : approvals.length === 0 ? (
          <EuiText size="s" color="subdued">
            No pending approvals.
          </EuiText>
        ) : (
          <EuiBasicTable<PendingApproval>
            items={approvals}
            columns={columns}
            itemId="executionId"
            itemIdToExpandedRowMap={expandedMap}
            tableLayout="auto"
          />
        )}
      </EuiPanel>
      <EuiSpacer size="m" />
    </>
  );
};
