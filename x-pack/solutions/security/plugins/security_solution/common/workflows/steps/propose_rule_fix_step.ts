/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import type { CommonStepDefinition } from '@kbn/workflows-extensions/common';
import { StepCategory } from '@kbn/workflows';
import { i18n } from '@kbn/i18n';

export const PROPOSE_RULE_FIX_STEP_TYPE_ID = 'security.rules.proposeFix';

export const ProposeRuleFixInputSchema = z.object({
  rule_id: z.string().describe('Detection rule saved-object ID (kibana.alert.rule.uuid) to diagnose.'),
});

export const ProposeRuleFixOutputSchema = z.object({
  rule_id: z.string(),
  proposedChanges: z
    .record(z.string(), z.unknown())
    .describe('Map of rule fields to patch (query, index, language, etc.).'),
  summary: z.string().describe('Human-readable summary of what the proposed fix does.'),
});

export type ProposeRuleFixInput = z.infer<typeof ProposeRuleFixInputSchema>;
export type ProposeRuleFixOutput = z.infer<typeof ProposeRuleFixOutputSchema>;

export const proposeRuleFixStepCommonDefinition: CommonStepDefinition<
  typeof ProposeRuleFixInputSchema,
  typeof ProposeRuleFixOutputSchema
> = {
  id: PROPOSE_RULE_FIX_STEP_TYPE_ID,
  category: StepCategory.KibanaSecurity,
  label: i18n.translate('xpack.securitySolution.workflows.proposeRuleFixStep.label', {
    defaultMessage: 'Propose Detection Rule Fix',
  }),
  description: i18n.translate('xpack.securitySolution.workflows.proposeRuleFixStep.description', {
    defaultMessage:
      'Diagnoses a failing detection rule and proposes a fix (query, index pattern, field mapping, etc.).',
  }),
  documentation: {
    details: i18n.translate(
      'xpack.securitySolution.workflows.proposeRuleFixStep.documentation.details',
      {
        defaultMessage:
          'POC stub: returns a proposal without actually running the LLM. Replace with the real fix-rule-errors skill invocation.',
      }
    ),
    examples: [
      `## Propose a fix for a failing rule
\`\`\`yaml
- name: propose_fix
  type: ${PROPOSE_RULE_FIX_STEP_TYPE_ID}
  with:
    rule_id: "{{ inputs.rule_id }}"
\`\`\``,
    ],
  },
  inputSchema: ProposeRuleFixInputSchema,
  outputSchema: ProposeRuleFixOutputSchema,
};
