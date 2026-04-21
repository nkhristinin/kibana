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

export const APPLY_RULE_FIX_STEP_TYPE_ID = 'security.rules.applyFix';

export const ApplyRuleFixInputSchema = z.object({
  rule_id: z.string().describe('Detection rule saved-object ID to patch.'),
  // Typed as unknown so workflow YAML can pass an interpolated object via Liquid
  // (e.g. {{ steps.parse_proposal.output.proposedChanges }}). Runtime expects an
  // object; the handler coerces/validates.
  changes: z.unknown().describe('Rule fields to patch (object).'),
});

export const ApplyRuleFixOutputSchema = z.object({
  rule_id: z.string(),
  appliedChanges: z.record(z.string(), z.unknown()),
  summary: z.string(),
});

export type ApplyRuleFixInput = z.infer<typeof ApplyRuleFixInputSchema>;
export type ApplyRuleFixOutput = z.infer<typeof ApplyRuleFixOutputSchema>;

export const applyRuleFixStepCommonDefinition: CommonStepDefinition<
  typeof ApplyRuleFixInputSchema,
  typeof ApplyRuleFixOutputSchema
> = {
  id: APPLY_RULE_FIX_STEP_TYPE_ID,
  category: StepCategory.KibanaSecurity,
  label: i18n.translate('xpack.securitySolution.workflows.applyRuleFixStep.label', {
    defaultMessage: 'Apply Detection Rule Fix',
  }),
  description: i18n.translate('xpack.securitySolution.workflows.applyRuleFixStep.description', {
    defaultMessage:
      'Applies a previously-proposed fix to a detection rule by PATCHing it via the detection engine API.',
  }),
  documentation: {
    details: i18n.translate(
      'xpack.securitySolution.workflows.applyRuleFixStep.documentation.details',
      {
        defaultMessage:
          'Only call this after a successful propose step and (if in suggest mode) a waitForInput approval.',
      }
    ),
    examples: [
      `## Apply proposed fix
\`\`\`yaml
- name: apply_fix
  type: ${APPLY_RULE_FIX_STEP_TYPE_ID}
  with:
    rule_id: "{{ inputs.rule_id }}"
    changes: "{{ steps.propose_fix.output.proposedChanges }}"
\`\`\``,
    ],
  },
  inputSchema: ApplyRuleFixInputSchema,
  outputSchema: ApplyRuleFixOutputSchema,
};
