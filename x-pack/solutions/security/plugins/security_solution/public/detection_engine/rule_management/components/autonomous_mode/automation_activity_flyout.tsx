/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useCallback, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonIcon,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiLink,
  EuiLoadingSpinner,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import type { EuiBasicTableColumn } from '@elastic/eui';
import { useKibana } from '../../../../common/lib/kibana';
import { ExecutionDetailsView } from './execution_details_view';
import { useAutomationActivity } from './use_automation_activity';
import type { ActivityItem } from './use_automation_activity';
import { usePendingApprovals } from './use_pending_approvals';
import type { ExecutionDetails } from './use_pending_approvals';

const STATUS_COLOR: Record<string, 'success' | 'danger' | 'warning' | 'default'> = {
  completed: 'success',
  failed: 'danger',
  cancelled: 'danger',
  timed_out: 'danger',
  waiting_for_input: 'warning',
  waiting: 'warning',
  running: 'default',
  pending: 'default',
  skipped: 'default',
};

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


interface Props {
  onClose: () => void;
}

export const AutomationActivityFlyout: React.FC<Props> = ({ onClose }) => {
  const { items, total, isLoading, error, refresh } = useAutomationActivity(true);
  // Reuse the details fetcher from usePendingApprovals — it knows how to parse
  // the ai_propose step output. It doesn't care about workflowIds for details.
  const { fetchDetails } = usePendingApprovals([]);
  const { http } = useKibana().services;

  const [expandedMap, setExpandedMap] = useState<Record<string, React.ReactNode>>({});
  const [detailsCache, setDetailsCache] = useState<
    Record<string, ExecutionDetails | 'loading' | Error>
  >({});

  const toggleExpand = useCallback(
    async (row: ActivityItem) => {
      const id = row.executionId;
      setExpandedMap((prev) => {
        if (prev[id]) {
          const next = { ...prev };
          delete next[id];
          return next;
        }
        return { ...prev, [id]: <ExecutionDetailsView ruleId={row.ruleId} details={detailsCache[id] ?? 'loading'} /> };
      });

      if (expandedMap[id]) return;

      if (!detailsCache[id]) {
        setDetailsCache((prev) => ({ ...prev, [id]: 'loading' }));
        try {
          const details = await fetchDetails(id);
          setDetailsCache((prev) => ({ ...prev, [id]: details }));
          setExpandedMap((prev) =>
            prev[id] ? { ...prev, [id]: <ExecutionDetailsView ruleId={row.ruleId} details={details} /> } : prev
          );
        } catch (err) {
          const e = err instanceof Error ? err : new Error(String(err));
          setDetailsCache((prev) => ({ ...prev, [id]: e }));
          setExpandedMap((prev) =>
            prev[id] ? { ...prev, [id]: <ExecutionDetailsView ruleId={row.ruleId} details={e} /> } : prev
          );
        }
      }
    },
    [detailsCache, expandedMap, fetchDetails]
  );

  const columns: Array<EuiBasicTableColumn<ActivityItem>> = [
    {
      align: 'left',
      width: '36px',
      isExpander: true,
      name: '',
      render: (row: ActivityItem) => (
        <EuiButtonIcon
          aria-label={expandedMap[row.executionId] ? 'Collapse' : 'Expand'}
          iconType={expandedMap[row.executionId] ? 'arrowDown' : 'arrowRight'}
          onClick={() => toggleExpand(row)}
        />
      ),
    },
    {
      field: 'status',
      name: 'Status',
      width: '140px',
      render: (status?: string) => {
        const s = (status ?? 'unknown').toLowerCase();
        return <EuiBadge color={STATUS_COLOR[s] ?? 'default'}>{s.replace(/_/g, ' ')}</EuiBadge>;
      },
    },
    {
      field: 'ruleId',
      name: 'Rule',
      render: (ruleId?: string) => ruleId ?? '—',
    },
    {
      field: 'workflowName',
      name: 'Workflow',
      render: (workflowName: string | undefined, row: ActivityItem) =>
        row.workflowId ? (
          <EuiLink
            href={workflowsUrlFor(http.basePath, row.workflowId, row.executionId)}
            target="_blank"
            external
          >
            {workflowName ?? row.workflowId}
          </EuiLink>
        ) : (
          workflowName ?? '—'
        ),
    },
    {
      field: 'startedAt',
      name: 'Started',
      render: (startedAt?: string) => (startedAt ? new Date(startedAt).toLocaleString() : '—'),
    },
  ];

  return (
    <EuiFlyout onClose={onClose} size="l" data-test-subj="automation-activity-flyout">
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="m">
          <h2>Automation activity</h2>
        </EuiTitle>
        <EuiText size="xs" color="subdued">
          <p>
            Recent executions across workflows tagged <code>detection-engine</code>.
          </p>
        </EuiText>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        {error && (
          <>
            <EuiCallOut color="danger" title="Failed to load activity">
              {error.message}
            </EuiCallOut>
            <EuiSpacer size="s" />
          </>
        )}
        {isLoading && items.length === 0 ? (
          <EuiLoadingSpinner size="m" />
        ) : items.length === 0 ? (
          <EuiText size="s" color="subdued">
            No executions yet for the <code>detection-engine</code> tag.
          </EuiText>
        ) : (
          <>
            <EuiText size="xs" color="subdued">
              <p>{total} total execution(s). Showing latest {items.length}.</p>
            </EuiText>
            <EuiSpacer size="xs" />
            <EuiBasicTable<ActivityItem>
              items={items}
              columns={columns}
              itemId="executionId"
              itemIdToExpandedRowMap={expandedMap}
              tableLayout="auto"
            />
          </>
        )}
      </EuiFlyoutBody>
      <EuiFlyoutFooter>
        <EuiFlexGroup justifyContent="spaceBetween" alignItems="center">
          <EuiFlexItem grow={false}>
            <EuiButton iconType="refresh" onClick={refresh} isLoading={isLoading}>
              Refresh
            </EuiButton>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton onClick={onClose} fill>
              Close
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
};
