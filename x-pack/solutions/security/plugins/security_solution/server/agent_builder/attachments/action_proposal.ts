/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AttachmentTypeDefinition } from '@kbn/agent-builder-server/attachments';
import type { Attachment } from '@kbn/agent-builder-common/attachments';
import { SecurityAgentBuilderAttachments } from '../../../common/constants';
import {
  actionProposalDataSchema as actionProposalSchema,
  type ActionProposalData,
} from '../../../common/agent_builder/action_recommendation';
export type {
  ActionProposalData,
  ActionProposalStatus,
  RuleChangePayload,
  RuleExceptionAddPayload,
  RuleInstallPayload,
} from '../../../common/agent_builder/action_recommendation';
import { SECURITY_PROPOSE_ACTION_TOOL_ID } from '../tools/core';

const isActionProposalData = (data: unknown): data is ActionProposalData =>
  actionProposalSchema.safeParse(data).success;

/**
 * Generic "action proposal" attachment. A skill that wants the user to approve a
 * mutation (rule update, prebuilt-rule install, exception add, delete, toggle, ...)
 * writes one of these via `attachments.add`. The client renderer dispatches on
 * `payload.action_type` to an action-specific view with Approve / Dismiss buttons.
 * The button handler performs the mutation via `http.fetch` — from the browser,
 * using the user's real session — so the mutation is authenticated correctly and
 * audit-attributed to the user.
 *
 * Skills MUST NOT call mutation APIs directly. They only create proposals.
 */
export const createActionProposalAttachmentType = (): AttachmentTypeDefinition => {
  return {
    id: SecurityAgentBuilderAttachments.actionProposal,
    validate: (input) => {
      const result = actionProposalSchema.safeParse(input);
      if (result.success) {
        return { valid: true, data: result.data };
      }
      return { valid: false, error: result.error.message };
    },
    format: (attachment: Attachment<string, unknown>) => {
      const data = attachment.data;
      if (!isActionProposalData(data)) {
        throw new Error(`Invalid action-proposal attachment data for ${attachment.id}`);
      }
      return {
        getRepresentation: () => ({
          type: 'text' as const,
          value: formatActionProposal(data),
        }),
      };
    },
    getAgentDescription:
      () => `This attachment type represents an ACTION PROPOSAL waiting for user approval. The user sees it rendered in chat with action-specific UI (for example: a diff for rule_change or a rules table for rule_install) plus Approve / Dismiss buttons.

Key rules for agents:
1. Prefer the \`security.core.propose_action\` tool to create these attachments so skills stay focused on reasoning rather than handcrafting payload JSON.
2. If there is already a pending proposal for the same rule and the same strategy, and the user asks for another compatible change ("also lower the severity", "make it run every 5m", "add one more exception item"), call \`security.core.propose_action\` again so the server updates the existing pending proposal instead of creating a second card.
3. If the user's new request is clearly unrelated to the current proposal's goal, start a new flow instead of forcing it into the existing proposal.
4. MUST NOT call mutation APIs directly. Mutations happen in the browser on user click.
5. After creating or updating the proposal, render the attachment inline and stop — wait for the user.
6. If the user reopens the conversation later and the attachment is already \`applied\` or \`dismissed\`, do not re-propose; acknowledge the prior decision.
`,
    getTools: () => [SECURITY_PROPOSE_ACTION_TOOL_ID],
  };
};

const formatActionProposal = (data: ActionProposalData): string => {
  const base = `[action proposal] status=${data.status} | ${data.payload.action_type}: ${data.summary}`;
  if (data.payload.action_type === 'rule_change') {
    const details = [
      `rule_id=${data.payload.rule_id}`,
      ...(data.payload.changed_fields.length > 0
        ? [`changed_fields=${data.payload.changed_fields.join(',')}`]
        : []),
    ];

    if (data.reason) return `${base}\n${details.join(' | ')}\nReason: ${data.reason}`;
    return `${base}\n${details.join(' | ')}`;
  }
  if (data.payload.action_type === 'rule_exception_add') {
    const details = [
      `rule_id=${data.payload.rule_id}`,
      `items=${data.payload.items.length}`,
      ...data.payload.items.slice(0, 3).map((item) => `item=${item.name}`),
    ];

    if (data.reason) return `${base}\n${details.join(' | ')}\nReason: ${data.reason}`;
    return `${base}\n${details.join(' | ')}`;
  }
  if (data.reason) return `${base}\nReason: ${data.reason}`;
  return base;
};
