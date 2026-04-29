/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import { CreateRuleExceptionListItemProps } from '@kbn/securitysolution-exceptions-common/api';

export const actionProposalStatusSchema = z.enum(['pending', 'applied', 'dismissed', 'failed']);

export const actionProposalMetricsSchema = z
  .record(z.string(), z.union([z.string(), z.number()]))
  .optional();

export const ruleChangeIntentSchema = z.enum([
  'query_tuning',
  'disable',
  'schedule_change',
  'metadata_change',
  'other',
]);

export const ruleChangePayloadSchema = z.object({
  action_type: z.literal('rule_change'),
  rule_id: z.string(),
  current: z.unknown(), // full RuleResponse JSON — validated client-side
  proposed_changes: z
    .record(z.string(), z.unknown())
    .refine((value) => Object.keys(value).length > 0, {
      message: '`proposed_changes` must include at least one field.',
    }),
  changed_fields: z.array(z.string()).min(1),
  intent: ruleChangeIntentSchema.optional(),
});

export const ruleInstallPayloadSchema = z.object({
  action_type: z.literal('rule_install'),
  rules: z
    .array(
      z.object({
        rule_id: z.string(), // prebuilt-rule signature id
        version: z.number().int().positive().optional(),
        name: z.string(),
        description: z.string().optional(),
        severity: z.string().optional(),
        mitre: z.array(z.string()).optional(),
        why: z.string().optional(),
      })
    )
    .min(1),
});

export const ruleExceptionAddPayloadSchema = z.object({
  action_type: z.literal('rule_exception_add'),
  rule_id: z.string(),
  rule_name: z.string().optional(),
  items: z.array(CreateRuleExceptionListItemProps).min(1),
});

export const actionProposalPayloadSchema = z.discriminatedUnion('action_type', [
  ruleChangePayloadSchema,
  ruleInstallPayloadSchema,
  ruleExceptionAddPayloadSchema,
]);

export const actionProposalDataSchema = z.object({
  attachmentLabel: z.string().optional(),
  status: actionProposalStatusSchema,
  summary: z.string(),
  reason: z.string().optional(),
  metrics: actionProposalMetricsSchema,
  applied_at: z.string().optional(),
  applied_by: z.string().optional(),
  error: z.string().optional(),
  payload: actionProposalPayloadSchema,
});

export type ActionProposalData = z.infer<typeof actionProposalDataSchema>;
export type ActionProposalPayload = z.infer<typeof actionProposalPayloadSchema>;
export type ActionProposalStatus = z.infer<typeof actionProposalStatusSchema>;
export type RuleChangeIntent = z.infer<typeof ruleChangeIntentSchema>;
export type RuleChangePayload = z.infer<typeof ruleChangePayloadSchema>;
export type RuleInstallPayload = z.infer<typeof ruleInstallPayloadSchema>;
export type RuleExceptionAddPayload = z.infer<typeof ruleExceptionAddPayloadSchema>;
