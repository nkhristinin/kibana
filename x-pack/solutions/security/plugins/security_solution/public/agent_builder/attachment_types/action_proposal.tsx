/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useCallback, useId, useState } from 'react';
import { useQueryClient } from '@kbn/react-query';
import { i18n } from '@kbn/i18n';
import {
  EuiAccordion,
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCodeBlock,
  EuiErrorBoundary,
  EuiFlexGroup,
  EuiFlexItem,
  EuiIcon,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import type {
  AttachmentRenderProps,
  AttachmentServiceStartContract,
} from '@kbn/agent-builder-browser/attachments';
import type { Attachment } from '@kbn/agent-builder-common/attachments';
import { buildPath, type HttpStart } from '@kbn/core-http-browser';
import type { NotificationsStart } from '@kbn/core-notifications-browser';
import type { ApplicationStart } from '@kbn/core-application-browser';
import type { EuiBasicTableColumn } from '@elastic/eui';
import {
  EXCEPTIONS_UI_EDIT_PRIVILEGES,
  RULES_UI_EDIT_PRIVILEGE,
} from '@kbn/security-solution-features/constants';
import type { RuleResponse } from '../../../common/api/detection_engine/model/rule_schema';
import type {
  ActionProposalData,
  ActionProposalPayload,
  ActionProposalStatus,
  RuleChangePayload,
  RuleExceptionAddPayload,
  RuleInstallPayload,
} from '../../../common/agent_builder/action_recommendation';
import {
  SecurityAgentBuilderAttachments,
  DETECTION_ENGINE_RULES_URL,
  DETECTION_ENGINE_RULES_URL_FIND,
} from '../../../common/constants';
import { PERFORM_RULE_INSTALLATION_URL } from '../../../common/api/detection_engine/prebuilt_rules';
import { RuleDiffTab } from '../../detection_engine/rule_management/components/rule_details/rule_diff_tab';
import { ExceptionItemCardConditions } from '../../detection_engine/rule_exceptions/components/exception_item_card/conditions';
import { hasCapabilities } from '../../common/lib/capabilities';

interface RuleInstallEntry {
  rule_id: string;
  name: string;
  description?: string;
  severity?: string;
  mitre?: string[];
  why?: string;
  version?: number;
}

type ActionProposalAttachment = Attachment<string, ActionProposalData>;

// ────────────────────────────────────────────────────────────────────────────
// Factory dependencies — injected at plugin start.
// Button handlers close over these to make HTTP calls with the user's session.
// ────────────────────────────────────────────────────────────────────────────

interface ActionProposalDeps {
  http: HttpStart;
  notifications: NotificationsStart;
  application: ApplicationStart;
}

// Match the query keys used by Security Solution's rule hooks
// (use_fetch_rule_by_id_query.ts and use_find_rules_query.ts) so an open rule
// details page or rules list page automatically refetches after Approve.
const RULE_BY_ID_QUERY_KEY_PREFIX = ['GET', DETECTION_ENGINE_RULES_URL] as const;
const RULES_LIST_QUERY_KEY_PREFIX = ['GET', DETECTION_ENGINE_RULES_URL_FIND] as const;

const invalidateRuleCachesForPayload = (
  queryClient: ReturnType<typeof useQueryClient>,
  payload: ActionProposalPayload
): void => {
  const ruleIds: string[] = [];
  switch (payload.action_type) {
    case 'rule_change':
      ruleIds.push(payload.rule_id);
      break;
    case 'rule_exception_add':
      ruleIds.push(payload.rule_id);
      break;
    case 'rule_install':
      // Installed prebuilt rules become regular rules; invalidating the list is
      // enough since the user doesn't have specific rule IDs cached yet.
      break;
  }

  // Invalidate the per-rule cache for each affected rule id.
  for (const id of ruleIds) {
    queryClient.invalidateQueries([...RULE_BY_ID_QUERY_KEY_PREFIX, id]);
  }
  // Always invalidate the list — any of these actions can change list state
  // (counts, severity, install set).
  queryClient.invalidateQueries(RULES_LIST_QUERY_KEY_PREFIX);
};

// ────────────────────────────────────────────────────────────────────────────
// Per-action execution. Each case calls a Detection Engine API via http.fetch —
// which originates in the browser with the user's session, so auth "just works".
// ────────────────────────────────────────────────────────────────────────────

const fetchLiveRule = async (http: HttpStart, ruleId: string) =>
  (await http.fetch(DETECTION_ENGINE_RULES_URL, {
    method: 'GET',
    version: '2023-10-31',
    query: { id: ruleId },
  })) as Record<string, unknown>;

const sortKeysDeep = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }

  if (value && typeof value === 'object') {
    return Object.keys(value as Record<string, unknown>)
      .sort()
      .reduce<Record<string, unknown>>((acc, key) => {
        acc[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
        return acc;
      }, {});
  }

  return value;
};

const areEquivalentValues = (left: unknown, right: unknown): boolean =>
  JSON.stringify(sortKeysDeep(left)) === JSON.stringify(sortKeysDeep(right));

const executeRuleChange = async (payload: RuleChangePayload, http: HttpStart) => {
  const snapshot = parseAsObject(payload.current);
  if (!snapshot) {
    throw new Error(
      'The proposal is missing a valid current rule snapshot. Ask the agent to re-analyse and propose again.'
    );
  }

  const liveRule = await fetchLiveRule(http, payload.rule_id);
  const hasDiverged = payload.changed_fields.some(
    (field) => !areEquivalentValues(liveRule[field], snapshot[field])
  );

  if (hasDiverged) {
    throw new Error(
      'The rule has changed since this proposal was generated. Ask the agent to re-analyse and propose again.'
    );
  }

  await http.fetch(DETECTION_ENGINE_RULES_URL, {
    method: 'PATCH',
    version: '2023-10-31',
    body: JSON.stringify({
      id: payload.rule_id,
      ...payload.proposed_changes,
    }),
  });
};

const executeRuleInstall = async (payload: RuleInstallPayload, http: HttpStart) => {
  await http.fetch(PERFORM_RULE_INSTALLATION_URL, {
    method: 'POST',
    version: '1',
    body: JSON.stringify({
      mode: 'SPECIFIC_RULES',
      rules: payload.rules.map((r) => ({
        rule_id: r.rule_id,
        version: r.version ?? 1,
      })),
    }),
  });
};

const executeRuleExceptionAdd = async (payload: RuleExceptionAddPayload, http: HttpStart) => {
  await http.fetch(
    buildPath(`${DETECTION_ENGINE_RULES_URL}/{id}/exceptions`, { id: payload.rule_id }),
    {
      method: 'POST',
      version: '2023-10-31',
      body: JSON.stringify({
        items: payload.items,
      }),
    }
  );
};

async function executeAction(payload: ActionProposalPayload, http: HttpStart): Promise<void> {
  switch (payload.action_type) {
    case 'rule_change':
      return executeRuleChange(payload, http);
    case 'rule_exception_add':
      return executeRuleExceptionAdd(payload, http);
    case 'rule_install':
      return executeRuleInstall(payload, http);
  }
}

const canApproveAction = (
  payload: ActionProposalPayload,
  application: ApplicationStart
): boolean => {
  switch (payload.action_type) {
    case 'rule_exception_add':
      return hasCapabilities(application.capabilities, EXCEPTIONS_UI_EDIT_PRIVILEGES);
    case 'rule_change':
    case 'rule_install':
      return hasCapabilities(application.capabilities, RULES_UI_EDIT_PRIVILEGE);
  }
};

// ────────────────────────────────────────────────────────────────────────────
// Shared layout bits
// ────────────────────────────────────────────────────────────────────────────

const ProposalHeader: React.FC<{ summary: string; reason?: string }> = ({ summary, reason }) => (
  <>
    <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
      <EuiFlexItem grow={false}>
        <EuiIcon type="wrench" size="m" aria-hidden={true} />
      </EuiFlexItem>
      <EuiFlexItem>
        <EuiTitle size="xxs">
          <h6>{summary}</h6>
        </EuiTitle>
      </EuiFlexItem>
    </EuiFlexGroup>
    {reason && (
      <>
        <EuiSpacer size="xs" />
        <EuiText size="xs" color="subdued">
          {reason}
        </EuiText>
      </>
    )}
  </>
);

const StatusBanner: React.FC<{
  status: ActionProposalStatus;
  appliedBy?: string;
  appliedAt?: string;
  error?: string;
}> = ({ status, appliedBy, appliedAt, error }) => {
  if (status === 'applied') {
    const who = appliedBy ? ` by ${appliedBy}` : '';
    const when = appliedAt ? ` at ${new Date(appliedAt).toLocaleString()}` : '';
    return (
      <EuiCallOut
        size="s"
        iconType="check"
        color="success"
        announceOnMount={false}
        title={i18n.translate('xpack.securitySolution.agentBuilder.actionProposal.appliedTitle', {
          defaultMessage: 'Applied{who}{when}',
          values: { who, when },
        })}
      />
    );
  }
  if (status === 'dismissed') {
    return (
      <EuiCallOut
        size="s"
        iconType="cross"
        color="primary"
        announceOnMount={false}
        title={i18n.translate('xpack.securitySolution.agentBuilder.actionProposal.dismissedTitle', {
          defaultMessage: 'Dismissed',
        })}
      />
    );
  }
  if (status === 'failed') {
    return (
      <EuiCallOut
        size="s"
        iconType="warning"
        color="danger"
        announceOnMount={false}
        title={i18n.translate('xpack.securitySolution.agentBuilder.actionProposal.failedTitle', {
          defaultMessage: 'Failed to apply',
        })}
      >
        {error && <EuiText size="xs">{error}</EuiText>}
      </EuiCallOut>
    );
  }
  return null;
};

const MetricsRow: React.FC<{ metrics?: Record<string, unknown> }> = ({ metrics }) => {
  if (!metrics) return null;
  const entries = Object.entries(metrics).filter(
    ([, v]) => typeof v === 'number' || typeof v === 'string'
  );
  if (entries.length === 0) return null;
  return (
    <>
      <EuiSpacer size="s" />
      <EuiFlexGroup gutterSize="s" responsive={false} wrap>
        {entries.map(([key, value]) => (
          <EuiFlexItem grow={false} key={key}>
            <EuiBadge color="hollow">{`${key}: ${String(value)}`}</EuiBadge>
          </EuiFlexItem>
        ))}
      </EuiFlexGroup>
    </>
  );
};

const ChangedFieldsRow: React.FC<{ fields: string[] }> = ({ fields }) => {
  if (fields.length === 0) {
    return null;
  }

  return (
    <>
      <EuiText size="xs" color="subdued">
        {i18n.translate(
          'xpack.securitySolution.agentBuilder.actionProposal.ruleChange.changedFields',
          {
            defaultMessage: 'Changes',
          }
        )}
      </EuiText>
      <EuiSpacer size="xs" />
      <EuiFlexGroup gutterSize="xs" responsive={false} wrap>
        {fields.map((field) => (
          <EuiFlexItem grow={false} key={field}>
            <EuiBadge color="hollow">{field}</EuiBadge>
          </EuiFlexItem>
        ))}
      </EuiFlexGroup>
    </>
  );
};

const ApproveDismissButtons: React.FC<{
  disabled: boolean;
  isLoading: boolean;
  onApprove: () => void;
  onDismiss: () => void;
  approveLabel?: string;
  approveColor?: 'primary' | 'danger';
  /** When false, the Approve button is hidden (user lacks privilege). Dismiss stays visible. */
  canApprove: boolean;
}> = ({
  disabled,
  isLoading,
  onApprove,
  onDismiss,
  approveLabel,
  approveColor = 'primary',
  canApprove,
}) => (
  <EuiFlexGroup gutterSize="s" responsive={false} alignItems="center">
    {canApprove && (
      <EuiFlexItem grow={false}>
        <EuiButton
          color={approveColor}
          fill
          size="s"
          iconType="check"
          onClick={onApprove}
          disabled={disabled}
          isLoading={isLoading}
        >
          {approveLabel ??
            i18n.translate('xpack.securitySolution.agentBuilder.actionProposal.approve', {
              defaultMessage: 'Approve',
            })}
        </EuiButton>
      </EuiFlexItem>
    )}
    <EuiFlexItem grow={false}>
      <EuiButtonEmpty
        size="s"
        iconType="cross"
        onClick={onDismiss}
        disabled={disabled || isLoading}
      >
        {i18n.translate('xpack.securitySolution.agentBuilder.actionProposal.dismiss', {
          defaultMessage: 'Dismiss',
        })}
      </EuiButtonEmpty>
    </EuiFlexItem>
    {!canApprove && (
      <EuiFlexItem grow={false}>
        <EuiText size="xs" color="subdued">
          {i18n.translate('xpack.securitySolution.agentBuilder.actionProposal.noPrivilegeHint', {
            defaultMessage: 'You do not have permission to apply this action.',
          })}
        </EuiText>
      </EuiFlexItem>
    )}
  </EuiFlexGroup>
);

// ────────────────────────────────────────────────────────────────────────────
// Per-action views
// ────────────────────────────────────────────────────────────────────────────

/**
 * Parse a raw value (object or stringified-JSON) into a plain record, or null
 * if it isn't one.
 */
const parseAsObject = (raw: unknown): Record<string, unknown> | null => {
  let candidate: unknown = raw;
  if (typeof candidate === 'string') {
    try {
      candidate = JSON.parse(candidate);
    } catch {
      return null;
    }
  }
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return null;
  }
  return candidate as Record<string, unknown>;
};

const isDisableRuleChange = (payload: RuleChangePayload): boolean =>
  payload.intent === 'disable' || payload.proposed_changes.enabled === false;

/**
 * Ensure the rule object has the fields `RuleDiffTab`'s internal normalizeRule
 * touches without guarding — notably `threat` (runs `.filter()`) and `tags`.
 * Missing values default to empty arrays so the diff view doesn't crash on a
 * partial rule payload from the LLM.
 */
const withSafeDefaults = (rule: Record<string, unknown>): RuleResponse =>
  ({
    ...rule,
    threat: Array.isArray(rule.threat) ? rule.threat : [],
    tags: Array.isArray(rule.tags) ? rule.tags : [],
  } as RuleResponse);

/**
 * Validate + normalize the `current` rule. Must have at least name and type.
 */
const normalizeCurrentRule = (raw: unknown): RuleResponse | null => {
  const obj = parseAsObject(raw);
  if (!obj) return null;
  if (typeof obj.name !== 'string' || typeof obj.type !== 'string') return null;
  return withSafeDefaults(obj);
};

const getRuleName = (raw: unknown, fallbackRuleId: string): string => {
  const obj = parseAsObject(raw);
  return typeof obj?.name === 'string' ? obj.name : fallbackRuleId;
};

const mergePatchValue = (base: unknown, patch: unknown): unknown => {
  if (
    base &&
    typeof base === 'object' &&
    !Array.isArray(base) &&
    patch &&
    typeof patch === 'object' &&
    !Array.isArray(patch)
  ) {
    const baseObject = base as Record<string, unknown>;
    return Object.keys(patch as Record<string, unknown>).reduce<Record<string, unknown>>(
      (acc, key) => {
        acc[key] = mergePatchValue(baseObject[key], (patch as Record<string, unknown>)[key]);
        return acc;
      },
      { ...baseObject }
    );
  }

  return patch;
};

/**
 * Produce the proposed rule by merging the agent's `proposed_changes` payload
 * onto the `current` rule. That way the payload acts as a patch — the agent
 * only needs to supply the fields it is changing and the rest is inherited.
 */
const buildProposedRule = (
  current: RuleResponse,
  proposedChanges: Record<string, unknown>
): RuleResponse =>
  withSafeDefaults(
    mergePatchValue(current as unknown as Record<string, unknown>, proposedChanges) as Record<
      string,
      unknown
    >
  );

/**
 * Fallback when `RuleDiffTab` can't render (e.g. the agent produced a partial
 * rule shape). Shows only the changed_fields with before/after values plus the
 * raw JSON in code blocks so the user can still inspect + approve.
 */
const RuleChangeFallback: React.FC<{ payload: RuleChangePayload }> = ({ payload }) => {
  const pickField = (rule: unknown, field: string): string => {
    if (!rule || typeof rule !== 'object') return '—';
    const v = (rule as Record<string, unknown>)[field];
    if (v === undefined || v === null) return '—';
    return typeof v === 'string' ? v : JSON.stringify(v);
  };
  return (
    <EuiCallOut
      size="s"
      iconType="warning"
      color="warning"
      title={i18n.translate(
        'xpack.securitySolution.agentBuilder.actionProposal.ruleUpdate.fallbackTitle',
        { defaultMessage: 'Diff view unavailable — showing field-level changes' }
      )}
    >
      <EuiText size="xs">
        {i18n.translate(
          'xpack.securitySolution.agentBuilder.actionProposal.ruleUpdate.fallbackBody',
          {
            defaultMessage:
              'The proposal payload did not include a full rule object. The core change is shown below.',
          }
        )}
      </EuiText>
      <EuiSpacer size="s" />
      {(payload.changed_fields.length > 0 ? payload.changed_fields : ['query']).map((field) => (
        <div key={field}>
          <EuiText size="xs">
            <strong>{field}</strong>
          </EuiText>
          <EuiFlexGroup gutterSize="s" alignItems="flexStart" responsive={false}>
            <EuiFlexItem>
              <EuiText size="xs" color="subdued">
                {'Current'}
              </EuiText>
              <EuiCodeBlock fontSize="s" paddingSize="s" overflowHeight={120}>
                {pickField(payload.current, field)}
              </EuiCodeBlock>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiText size="xs" color="subdued">
                {'Proposed'}
              </EuiText>
              <EuiCodeBlock fontSize="s" paddingSize="s" overflowHeight={120}>
                {pickField(payload.proposed_changes, field)}
              </EuiCodeBlock>
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="xs" />
        </div>
      ))}
    </EuiCallOut>
  );
};

const RuleChangeView: React.FC<{
  payload: RuleChangePayload;
  status: ActionProposalStatus;
  isLoading: boolean;
  canApprove: boolean;
  onApprove: () => void;
  onDismiss: () => void;
}> = ({ payload, status, isLoading, canApprove, onApprove, onDismiss }) => {
  const detailsAccordionId = useId();
  const current = normalizeCurrentRule(payload.current);
  const ruleName = getRuleName(payload.current, payload.rule_id);
  const proposed = current ? buildProposedRule(current, payload.proposed_changes) : null;
  const canDiff = current !== null && proposed !== null;
  const isDisable = isDisableRuleChange(payload);
  const detailsButtonLabel = canDiff
    ? i18n.translate('xpack.securitySolution.agentBuilder.actionProposal.ruleChange.reviewDiff', {
        defaultMessage: 'Review full diff',
      })
    : i18n.translate(
        'xpack.securitySolution.agentBuilder.actionProposal.ruleChange.reviewDetails',
        {
          defaultMessage: 'Review change details',
        }
      );

  return (
    <>
      <EuiSpacer size="s" />
      {isDisable && (
        <>
          <EuiCallOut
            size="s"
            iconType="warning"
            color="warning"
            announceOnMount={false}
            title={i18n.translate(
              'xpack.securitySolution.agentBuilder.actionProposal.ruleChange.disableTitle',
              {
                defaultMessage: 'Disable {ruleName}',
                values: { ruleName },
              }
            )}
          >
            <EuiText size="s">
              {i18n.translate(
                'xpack.securitySolution.agentBuilder.actionProposal.ruleChange.disableDescription',
                {
                  defaultMessage:
                    'Approving this proposal disables the rule so it stops running until someone re-enables it.',
                }
              )}
            </EuiText>
          </EuiCallOut>
          <EuiSpacer size="s" />
        </>
      )}
      <ChangedFieldsRow fields={payload.changed_fields} />
      <EuiSpacer size="s" />
      <EuiAccordion
        id={detailsAccordionId}
        initialIsOpen={false}
        buttonContent={detailsButtonLabel}
        paddingSize="s"
      >
        {canDiff ? (
          <EuiErrorBoundary>
            <RuleDiffTab
              oldRule={current}
              newRule={proposed}
              leftDiffSideLabel={i18n.translate(
                'xpack.securitySolution.agentBuilder.actionProposal.ruleUpdate.currentLabel',
                { defaultMessage: 'Current rule' }
              )}
              leftDiffSideDescription={i18n.translate(
                'xpack.securitySolution.agentBuilder.actionProposal.ruleUpdate.currentDescription',
                { defaultMessage: 'The rule as it currently runs.' }
              )}
              rightDiffSideLabel={i18n.translate(
                'xpack.securitySolution.agentBuilder.actionProposal.ruleUpdate.proposedLabel',
                { defaultMessage: 'Proposed' }
              )}
              rightDiffSideDescription={i18n.translate(
                'xpack.securitySolution.agentBuilder.actionProposal.ruleUpdate.proposedDescription',
                { defaultMessage: "The agent's proposed change. Not yet applied." }
              )}
            />
          </EuiErrorBoundary>
        ) : (
          <RuleChangeFallback payload={payload} />
        )}
      </EuiAccordion>
      {status === 'pending' && (
        <>
          <EuiSpacer size="s" />
          <ApproveDismissButtons
            disabled={false}
            isLoading={isLoading}
            canApprove={canApprove}
            onApprove={onApprove}
            onDismiss={onDismiss}
            approveColor={isDisable ? 'danger' : 'primary'}
            approveLabel={i18n.translate(
              isDisable
                ? 'xpack.securitySolution.agentBuilder.actionProposal.ruleChange.disable'
                : 'xpack.securitySolution.agentBuilder.actionProposal.ruleChange.apply',
              {
                defaultMessage: isDisable ? 'Disable rule' : 'Apply rule change',
              }
            )}
          />
        </>
      )}
    </>
  );
};

const RuleInstallView: React.FC<{
  payload: RuleInstallPayload;
  status: ActionProposalStatus;
  isLoading: boolean;
  canApprove: boolean;
  onApprove: () => void;
  onDismiss: () => void;
}> = ({ payload, status, isLoading, canApprove, onApprove, onDismiss }) => {
  const columns: Array<EuiBasicTableColumn<RuleInstallEntry>> = [
    {
      field: 'name',
      name: i18n.translate(
        'xpack.securitySolution.agentBuilder.actionProposal.ruleInstall.colName',
        { defaultMessage: 'Rule' }
      ),
      render: (name: string, item: RuleInstallEntry) => (
        <EuiFlexGroup direction="column" gutterSize="none">
          <EuiFlexItem>
            <EuiText size="s">
              <strong>{name}</strong>
            </EuiText>
          </EuiFlexItem>
          {item.why && (
            <EuiFlexItem>
              <EuiText size="xs" color="subdued">
                {item.why}
              </EuiText>
            </EuiFlexItem>
          )}
        </EuiFlexGroup>
      ),
    },
    {
      field: 'severity',
      name: i18n.translate(
        'xpack.securitySolution.agentBuilder.actionProposal.ruleInstall.colSeverity',
        { defaultMessage: 'Severity' }
      ),
      width: '120px',
      render: (severity?: string) =>
        severity ? <EuiBadge color="hollow">{severity}</EuiBadge> : null,
    },
  ];

  return (
    <>
      <EuiSpacer size="s" />
      <EuiBasicTable<RuleInstallEntry>
        items={payload.rules}
        columns={columns}
        tableLayout="auto"
        compressed
        tableCaption={i18n.translate(
          'xpack.securitySolution.agentBuilder.actionProposal.ruleInstall.tableCaption',
          { defaultMessage: 'Rules included in this installation proposal' }
        )}
      />
      {status === 'pending' && (
        <>
          <EuiSpacer size="s" />
          <ApproveDismissButtons
            disabled={false}
            isLoading={isLoading}
            canApprove={canApprove}
            onApprove={onApprove}
            onDismiss={onDismiss}
            approveLabel={i18n.translate(
              'xpack.securitySolution.agentBuilder.actionProposal.ruleInstall.install',
              { defaultMessage: 'Install rules' }
            )}
          />
        </>
      )}
    </>
  );
};

const RuleExceptionProposalItem: React.FC<{
  index: number;
  item: RuleExceptionAddPayload['items'][number];
}> = ({ index, item }) => (
  <>
    <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
      <EuiFlexItem grow={false}>
        <EuiBadge color="hollow">{item.type}</EuiBadge>
      </EuiFlexItem>
      <EuiFlexItem>
        <EuiText size="s">
          <strong>{item.name}</strong>
        </EuiText>
      </EuiFlexItem>
    </EuiFlexGroup>
    {item.description ? (
      <>
        <EuiSpacer size="xs" />
        <EuiText size="xs" color="subdued">
          {item.description}
        </EuiText>
      </>
    ) : null}
    <EuiSpacer size="xs" />
    <ExceptionItemCardConditions
      os={item.os_types}
      entries={item.entries}
      dataTestSubj={`actionProposalRuleExceptionConditions-${index}`}
    />
  </>
);

const RuleExceptionAddView: React.FC<{
  payload: RuleExceptionAddPayload;
  status: ActionProposalStatus;
  isLoading: boolean;
  canApprove: boolean;
  onApprove: () => void;
  onDismiss: () => void;
}> = ({ payload, status, isLoading, canApprove, onApprove, onDismiss }) => {
  const ruleName = payload.rule_name ?? payload.rule_id;

  return (
    <>
      <EuiSpacer size="s" />
      <EuiCallOut
        size="s"
        iconType="plusInCircle"
        color="primary"
        announceOnMount={false}
        title={i18n.translate(
          'xpack.securitySolution.agentBuilder.actionProposal.ruleExceptionAdd.title',
          {
            defaultMessage:
              'Add {count} exception {count, plural, one {item} other {items}} to {ruleName}',
            values: {
              count: payload.items.length,
              ruleName,
            },
          }
        )}
      >
        <EuiText size="s">
          {i18n.translate(
            'xpack.securitySolution.agentBuilder.actionProposal.ruleExceptionAdd.description',
            {
              defaultMessage:
                'Approving this proposal adds the exception items to the rule default exception list. If the rule does not have one yet, it will be created automatically.',
            }
          )}
        </EuiText>
      </EuiCallOut>
      <EuiSpacer size="s" />
      {payload.items.map((item, index) => (
        <React.Fragment key={item.item_id ?? `${item.name}-${item.description}`}>
          {index > 0 ? <EuiSpacer size="m" /> : null}
          <RuleExceptionProposalItem index={index} item={item} />
        </React.Fragment>
      ))}
      {status === 'pending' && (
        <>
          <EuiSpacer size="s" />
          <ApproveDismissButtons
            disabled={false}
            isLoading={isLoading}
            canApprove={canApprove}
            onApprove={onApprove}
            onDismiss={onDismiss}
            approveLabel={i18n.translate(
              'xpack.securitySolution.agentBuilder.actionProposal.ruleExceptionAdd.apply',
              {
                defaultMessage: payload.items.length === 1 ? 'Add exception' : 'Add exceptions',
              }
            )}
          />
        </>
      )}
    </>
  );
};

// ────────────────────────────────────────────────────────────────────────────
// Dispatch — main inline renderer
// ────────────────────────────────────────────────────────────────────────────

const ActionProposalInlineContent: React.FC<
  AttachmentRenderProps<ActionProposalAttachment> & { deps: ActionProposalDeps }
> = ({ attachment, deps }) => {
  const data = attachment.data;
  // Local state — optimistic update. Platform currently has no client-side
  // attachment-data-update API, so the applied/dismissed state is session-local.
  // Reloading the conversation will show the server-side status (still pending)
  // until the Agent Builder team adds an updateAttachmentData primitive.
  const [status, setStatus] = useState<ActionProposalStatus>(data.status);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | undefined>(data.error);
  const [appliedAt, setAppliedAt] = useState<string | undefined>(data.applied_at);
  const queryClient = useQueryClient();

  const handleApprove = useCallback(async () => {
    setIsLoading(true);
    setError(undefined);
    try {
      await executeAction(data.payload, deps.http);
      // Refresh any rule details / list pages that may be open so they show
      // the new rule state without a manual reload.
      invalidateRuleCachesForPayload(queryClient, data.payload);
      const now = new Date().toISOString();
      setStatus('applied');
      setAppliedAt(now);
      deps.notifications.toasts.addSuccess({
        title: i18n.translate('xpack.securitySolution.agentBuilder.actionProposal.successToast', {
          defaultMessage: '{summary} applied',
          values: { summary: data.summary },
        }),
      });
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setStatus('failed');
      setError(message);
      deps.notifications.toasts.addDanger({
        title: i18n.translate('xpack.securitySolution.agentBuilder.actionProposal.errorToast', {
          defaultMessage: 'Failed to apply',
        }),
        text: message,
      });
    } finally {
      setIsLoading(false);
    }
  }, [data, deps, queryClient]);

  const handleDismiss = useCallback(() => {
    setStatus('dismissed');
  }, []);

  // Privilege gate: proposal types map to different APIs. Server-side routes still
  // enforce authz independently; this is about not offering a button the user's
  // click would fail on.
  const canApprove = canApproveAction(data.payload, deps.application);

  let body: React.ReactNode;
  switch (data.payload.action_type) {
    case 'rule_change':
      body = (
        <RuleChangeView
          payload={data.payload}
          status={status}
          isLoading={isLoading}
          canApprove={canApprove}
          onApprove={handleApprove}
          onDismiss={handleDismiss}
        />
      );
      break;
    case 'rule_exception_add':
      body = (
        <RuleExceptionAddView
          payload={data.payload}
          status={status}
          isLoading={isLoading}
          canApprove={canApprove}
          onApprove={handleApprove}
          onDismiss={handleDismiss}
        />
      );
      break;
    case 'rule_install':
      body = (
        <RuleInstallView
          payload={data.payload}
          status={status}
          isLoading={isLoading}
          canApprove={canApprove}
          onApprove={handleApprove}
          onDismiss={handleDismiss}
        />
      );
      break;
    default:
      body = (
        <EuiText size="s" color="subdued">
          {i18n.translate('xpack.securitySolution.agentBuilder.actionProposal.unknownAction', {
            defaultMessage: 'Unsupported action type.',
          })}
        </EuiText>
      );
  }

  return (
    <EuiPanel paddingSize="m" hasBorder>
      <ProposalHeader summary={data.summary} reason={data.reason} />
      {body}
      <MetricsRow metrics={data.metrics} />
      <EuiSpacer size="s" />
      <StatusBanner
        status={status}
        appliedBy={data.applied_by}
        appliedAt={appliedAt}
        error={error}
      />
      {isLoading && (
        <>
          <EuiSpacer size="xs" />
          <EuiFlexGroup alignItems="center" gutterSize="s">
            <EuiFlexItem grow={false}>
              <EuiLoadingSpinner size="s" />
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiText size="xs" color="subdued">
                {i18n.translate(
                  'xpack.securitySolution.agentBuilder.actionProposal.applyingLabel',
                  { defaultMessage: 'Applying…' }
                )}
              </EuiText>
            </EuiFlexItem>
          </EuiFlexGroup>
        </>
      )}
    </EuiPanel>
  );
};

// ────────────────────────────────────────────────────────────────────────────
// Registration
// ────────────────────────────────────────────────────────────────────────────

export const registerActionProposalAttachment = ({
  attachments,
  http,
  notifications,
  application,
}: {
  attachments: AttachmentServiceStartContract;
  http: HttpStart;
  notifications: NotificationsStart;
  application: ApplicationStart;
}): void => {
  const deps: ActionProposalDeps = { http, notifications, application };
  attachments.addAttachmentType<ActionProposalAttachment>(
    SecurityAgentBuilderAttachments.actionProposal,
    {
      getLabel: (attachment) =>
        attachment.data?.summary ??
        i18n.translate('xpack.securitySolution.agentBuilder.actionProposal.label', {
          defaultMessage: 'Action proposal',
        }),
      getIcon: () => 'wrench',
      renderInlineContent: (props) => <ActionProposalInlineContent {...props} deps={deps} />,
    }
  );
};
