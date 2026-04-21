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

export const GET_AUTONOMOUS_MODE_STEP_TYPE_ID = 'security.autonomousMode.get';

export const GetAutonomousModeInputSchema = z.object({}).optional();

export const GetAutonomousModeOutputSchema = z.object({
  mode: z
    .enum(['auto', 'suggest'])
    .describe('Current space-level autonomous mode: "auto" applies fixes automatically, "suggest" waits for user approval.'),
});

export type GetAutonomousModeInput = z.infer<typeof GetAutonomousModeInputSchema>;
export type GetAutonomousModeOutput = z.infer<typeof GetAutonomousModeOutputSchema>;

export const getAutonomousModeStepCommonDefinition: CommonStepDefinition<
  typeof GetAutonomousModeInputSchema,
  typeof GetAutonomousModeOutputSchema
> = {
  id: GET_AUTONOMOUS_MODE_STEP_TYPE_ID,
  category: StepCategory.KibanaSecurity,
  label: i18n.translate('xpack.securitySolution.workflows.getAutonomousModeStep.label', {
    defaultMessage: 'Get Autonomous Mode',
  }),
  description: i18n.translate('xpack.securitySolution.workflows.getAutonomousModeStep.description', {
    defaultMessage:
      'Reads the current space-level autonomous mode setting for detection engine automation.',
  }),
  documentation: {
    details: i18n.translate(
      'xpack.securitySolution.workflows.getAutonomousModeStep.documentation.details',
      {
        defaultMessage:
          'Returns "auto" or "suggest". Use this to branch a workflow between applying fixes automatically and pausing for approval via waitForInput.',
      }
    ),
    examples: [
      `## Read space autonomous mode
\`\`\`yaml
- name: read_mode
  type: ${GET_AUTONOMOUS_MODE_STEP_TYPE_ID}
\`\`\``,
    ],
  },
  inputSchema: GetAutonomousModeInputSchema,
  outputSchema: GetAutonomousModeOutputSchema,
};
