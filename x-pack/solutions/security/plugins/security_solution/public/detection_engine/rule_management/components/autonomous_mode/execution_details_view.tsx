/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import {
  EuiAccordion,
  EuiAvatar,
  EuiBadge,
  EuiCallOut,
  EuiCodeBlock,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTimeline,
  EuiTimelineItem,
} from '@elastic/eui';
import type { EuiTimelineItemProps, IconType } from '@elastic/eui';
import { ProposalDiffView } from './proposal_diff_view';
import type { ExecutionDetails, ExecutionSection } from './use_pending_approvals';

interface Props {
  ruleId?: string;
  details: ExecutionDetails | 'loading' | Error;
}

const iconFor = (
  kind: ExecutionSection['kind'] | 'rejected'
): { type: IconType; iconColor: string } => {
  switch (kind) {
    case 'agent_reasoning':
      return { type: 'discuss', iconColor: 'subdued' };
    case 'proposed_changes':
      return { type: 'documentEdit', iconColor: 'primary' };
    case 'approval':
      return { type: 'check', iconColor: 'success' };
    case 'rejected':
      return { type: 'cross', iconColor: 'danger' };
    case 'applied_changes':
      return { type: 'checkInCircleFilled', iconColor: 'success' };
    case 'failure':
      return { type: 'alert', iconColor: 'danger' };
    default:
      return { type: 'dot', iconColor: 'subdued' };
  }
};

const avatarFor = (
  kind: ExecutionSection['kind'] | 'rejected'
): EuiTimelineItemProps['icon'] => {
  const { type, iconColor } = iconFor(kind);
  // All avatars use the same "plain" style — identical pale background and
  // size. Only the icon glyph + its color varies per section.
  return <EuiAvatar name={kind} iconType={type} color="plain" iconColor={iconColor} size="m" />;
};

const SectionAgentReasoning: React.FC<{
  section: Extract<ExecutionSection, { kind: 'agent_reasoning' }>;
}> = ({ section }) => (
  <EuiAccordion
    id={`reasoning-${section.stepId}`}
    buttonContent={
      <EuiText size="s">
        <strong>Agent reasoning</strong>
      </EuiText>
    }
    paddingSize="s"
    initialIsOpen={false}
  >
    <EuiCodeBlock
      language="markdown"
      fontSize="s"
      paddingSize="s"
      isCopyable
      overflowHeight={240}
      transparentBackground
    >
      {section.reasoning}
    </EuiCodeBlock>
  </EuiAccordion>
);

const SectionProposedChanges: React.FC<{
  section: Extract<ExecutionSection, { kind: 'proposed_changes' }>;
  ruleId?: string;
  renderDiff: boolean;
}> = ({ section, ruleId, renderDiff }) => (
  <EuiFlexGroup direction="column" gutterSize="xs">
    <EuiFlexItem>
      <EuiText size="s">
        <strong>Proposed changes</strong>
      </EuiText>
      {section.summary && (
        <EuiText size="xs" color="subdued">
          {section.summary}
        </EuiText>
      )}
    </EuiFlexItem>
    <EuiFlexItem>
      <EuiPanel paddingSize="s" hasBorder hasShadow={false}>
        {renderDiff && ruleId ? (
          <ProposalDiffView ruleId={ruleId} proposedChanges={section.proposedChanges} />
        ) : (
          <EuiCodeBlock
            language="json"
            fontSize="s"
            paddingSize="none"
            isCopyable
            overflowHeight={240}
            transparentBackground
          >
            {JSON.stringify(section.proposedChanges, null, 2)}
          </EuiCodeBlock>
        )}
      </EuiPanel>
    </EuiFlexItem>
  </EuiFlexGroup>
);

const SectionAppliedChanges: React.FC<{
  section: Extract<ExecutionSection, { kind: 'applied_changes' }>;
}> = ({ section }) => (
  <EuiFlexGroup direction="column" gutterSize="xs">
    <EuiFlexItem>
      <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiText size="s">
            <strong>Applied changes</strong>
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiBadge color="success">Success</EuiBadge>
        </EuiFlexItem>
      </EuiFlexGroup>
      {section.summary && (
        <EuiText size="xs" color="subdued">
          {section.summary}
        </EuiText>
      )}
    </EuiFlexItem>
    <EuiFlexItem>
      <EuiPanel paddingSize="s" hasBorder hasShadow={false} color="subdued">
        <EuiCodeBlock
          language="json"
          fontSize="s"
          paddingSize="none"
          isCopyable
          overflowHeight={240}
          transparentBackground
        >
          {JSON.stringify(section.appliedChanges, null, 2)}
        </EuiCodeBlock>
      </EuiPanel>
    </EuiFlexItem>
  </EuiFlexGroup>
);

const SectionApproval: React.FC<{
  section: Extract<ExecutionSection, { kind: 'approval' }>;
}> = ({ section }) => (
  <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
    <EuiFlexItem grow={false}>
      <EuiText size="s">
        <strong>{section.approved ? 'Approved' : 'Rejected'}</strong>
      </EuiText>
    </EuiFlexItem>
    {section.at && (
      <EuiFlexItem grow={false}>
        <EuiText size="xs" color="subdued">
          {new Date(section.at).toLocaleString()}
        </EuiText>
      </EuiFlexItem>
    )}
  </EuiFlexGroup>
);

const SectionFailure: React.FC<{
  section: Extract<ExecutionSection, { kind: 'failure' }>;
}> = ({ section }) => (
  <EuiCallOut color="danger" size="s" title={`Step "${section.stepId}" failed`}>
    <EuiText size="xs">{section.error}</EuiText>
  </EuiCallOut>
);

const renderSection = (
  section: ExecutionSection,
  ruleId: string | undefined,
  renderDiff: boolean
): React.ReactNode => {
  switch (section.kind) {
    case 'agent_reasoning':
      return <SectionAgentReasoning section={section} />;
    case 'proposed_changes':
      return (
        <SectionProposedChanges section={section} ruleId={ruleId} renderDiff={renderDiff} />
      );
    case 'applied_changes':
      return <SectionAppliedChanges section={section} />;
    case 'approval':
      return <SectionApproval section={section} />;
    case 'failure':
      return <SectionFailure section={section} />;
    default:
      return null;
  }
};

export const ExecutionDetailsView: React.FC<Props> = ({ ruleId, details }) => {
  if (details === 'loading') {
    return (
      <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiLoadingSpinner size="m" />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiText size="xs" color="subdued">
            Loading execution details…
          </EuiText>
        </EuiFlexItem>
      </EuiFlexGroup>
    );
  }
  if (details instanceof Error)
    return (
      <EuiCallOut color="danger" size="s" title="Failed to load details">
        {details.message}
      </EuiCallOut>
    );

  const isPending = details.overallStatus === 'waiting_for_input';

  if (details.sections.length === 0) {
    return (
      <EuiText size="s" color="subdued">
        No section output captured for this execution.
      </EuiText>
    );
  }

  const items = details.sections.map((section, i) => {
    const isRejected = section.kind === 'approval' && !section.approved;
    const iconKind = isRejected ? 'rejected' : section.kind;
    return (
      <EuiTimelineItem
        key={`${section.kind}-${section.stepId}-${i}`}
        verticalAlign="top"
        icon={avatarFor(iconKind)}
      >
        {renderSection(section, ruleId, isPending)}
      </EuiTimelineItem>
    );
  });

  return (
    <>
      <EuiSpacer size="s" />
      <EuiTimeline gutterSize="m">{items}</EuiTimeline>
    </>
  );
};
