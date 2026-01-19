/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod';

export const ConnectRuleExecutionTraceRequestParams = z.object({
  ruleId: z.string().min(1),
});
export type ConnectRuleExecutionTraceRequestParams = z.infer<
  typeof ConnectRuleExecutionTraceRequestParams
>;

export const ConnectRuleExecutionTraceRequestBody = z.object({
  ttl_ms: z.number().int().positive().optional(),
});
export type ConnectRuleExecutionTraceRequestBody = z.infer<
  typeof ConnectRuleExecutionTraceRequestBody
>;

export const ConnectRuleExecutionTraceResponse = z.object({
  session_id: z.string().min(1),
  expires_at: z.string().datetime(),
});
export type ConnectRuleExecutionTraceResponse = z.infer<typeof ConnectRuleExecutionTraceResponse>;
