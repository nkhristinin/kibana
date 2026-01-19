/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod';

export const TailRuleExecutionTraceRequestParams = z.object({
  ruleId: z.string().min(1),
});
export type TailRuleExecutionTraceRequestParams = z.infer<
  typeof TailRuleExecutionTraceRequestParams
>;

export const TailRuleExecutionTraceRequestQuery = z.object({
  date_start: z.string().optional(),
  after_ts: z.string().optional(),
  after_seq: z.coerce.number().int().optional(),
  limit: z.coerce.number().int().min(1).max(500).optional().default(200),
});
export type TailRuleExecutionTraceRequestQuery = z.infer<typeof TailRuleExecutionTraceRequestQuery>;

export const TailRuleExecutionTraceItem = z.object({
  ts: z.string(),
  seq: z.number().int(),
  level: z.string(),
  logger: z.string(),
  execution_id: z.string(),
  message_text: z.string(),
  message: z.unknown().optional(),
});
export type TailRuleExecutionTraceItem = z.infer<typeof TailRuleExecutionTraceItem>;

export const TailRuleExecutionTraceResponse = z.object({
  rule_id: z.string().min(1),
  next_after_ts: z.string().optional(),
  next_after_seq: z.number().int().optional(),
  items: z.array(TailRuleExecutionTraceItem),
});
export type TailRuleExecutionTraceResponse = z.infer<typeof TailRuleExecutionTraceResponse>;
