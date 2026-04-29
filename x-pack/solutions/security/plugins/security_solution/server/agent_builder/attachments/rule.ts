/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AttachmentTypeDefinition } from '@kbn/agent-builder-server/attachments';
import type { Attachment } from '@kbn/agent-builder-common/attachments';
import { platformCoreTools } from '@kbn/agent-builder-common';
import { z } from '@kbn/zod/v4';
import { SecurityAgentBuilderAttachments } from '../../../common/constants';
import { SECURITY_CREATE_DETECTION_RULE_TOOL_ID, SECURITY_LABS_SEARCH_TOOL_ID } from '../tools';

import { securityAttachmentDataSchema } from './security_attachment_data_schema';

export const ruleAttachmentDataSchema = securityAttachmentDataSchema.extend({
  text: z.string(),
});

const DETECTION_RULE_SKILL_NAME_ID = 'detection-rule-edit';
const FIX_FP_SKILL_NAME_ID = 'fix-false-positive-alerts';
const FIX_RULE_FAILURES_SKILL_NAME_ID = 'fix-rule-execution-failures';

type RuleAttachmentData = z.infer<typeof ruleAttachmentDataSchema>;

/**
 * Type guard to narrow attachment data to RuleAttachmentData
 */
const isRuleAttachmentData = (data: unknown): data is RuleAttachmentData => {
  return ruleAttachmentDataSchema.safeParse(data).success;
};
export const createRuleAttachmentType = (): AttachmentTypeDefinition => {
  return {
    id: SecurityAgentBuilderAttachments.rule,
    validate: (input) => {
      const parseResult = ruleAttachmentDataSchema.safeParse(input);
      if (parseResult.success) {
        return { valid: true, data: parseResult.data };
      } else {
        return { valid: false, error: parseResult.error.message };
      }
    },
    format: (attachment: Attachment<string, unknown>) => {
      // Extract data to allow proper type narrowing
      const data = attachment.data;
      // Necessary because we cannot currently use the AttachmentType type as agent is not
      // registered with enum AttachmentType in agentBuilder attachment_types.ts
      if (!isRuleAttachmentData(data)) {
        throw new Error(`Invalid rule attachment data for attachment ${attachment.id}`);
      }
      return {
        getRepresentation: () => {
          return { type: 'text', value: formatRuleData(data) };
        },
      };
    },
    getTools: () => [
      platformCoreTools.generateEsql,
      platformCoreTools.productDocumentation,
      SECURITY_CREATE_DETECTION_RULE_TOOL_ID,
      SECURITY_LABS_SEARCH_TOOL_ID,
    ],

    getAgentDescription: () => {
      const description = `You have access to a security detection rule stored as stringified JSON in the "text" field. It may be an existing rule or an empty placeholder for a new rule.

SECURITY RULE DATA:
{ruleData}

---
Pick the skill that matches the user's intent and load it with read_skill before doing anything else. Do NOT default to an alerts-triage skill just because the user mentions the word "alerts" — if the attachment is a rule and the user is asking about the rule's behavior, the rule-focused skills below are the correct entry point.

If there is ALSO a pending security.action_proposal attachment in the conversation for this same rule and the user is clearly tweaking that proposed remediation ("also...", "instead...", "change the proposal to..."), prefer continuing that pending proposal flow rather than switching to a generic rule-editing experience, as long as the new request still fits the proposal's goal.

- If the user asks "is this a false positive?" / "are these alerts noisy?" / "can you tune this rule?" / "reduce false positives on this rule" / any intent to DIAGNOSE NOISE on an attached rule and propose a tuning fix → load the ${FIX_FP_SKILL_NAME_ID} skill from the skills/security/alerts/rules directory.
- If the user says the rule is BROKEN, FAILING, throwing EXECUTION ERRORS, or asks whether to STOP / DISABLE it because of failures → load the ${FIX_RULE_FAILURES_SKILL_NAME_ID} skill from the skills/security/alerts/rules directory.
- If the user asks to CREATE, EDIT, or UPDATE the rule itself (change its name, tags, severity, MITRE mappings, query syntax, etc.) → load the ${DETECTION_RULE_SKILL_NAME_ID} skill from the skills/security/rules directory.

If the intent is ambiguous, prefer ${FIX_FP_SKILL_NAME_ID} whenever the user is asking about the rule's ALERT VOLUME or QUALITY (false positives, noise, tuning), prefer ${FIX_RULE_FAILURES_SKILL_NAME_ID} when the user is asking about RULE FAILURES OR WHETHER TO STOP THE RULE, and prefer ${DETECTION_RULE_SKILL_NAME_ID} when the user is asking about the rule's CONFIGURATION.`;
      return description;
    },
  };
};

const formatRuleData = (data: RuleAttachmentData): string => {
  return data.text;
};
