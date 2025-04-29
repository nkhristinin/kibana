/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { INTERNAL_DETECTION_ENGINE_URL as INTERNAL_URL } from '../../../constants';

export const GET_RULE_EXECUTIONS_WITH_DEBUG_LOG =
  `${INTERNAL_URL}/rules/{ruleId}/executions_with_debug_log` as const;
export const GET_RULE_DEBUGE_LOG_BY_EXECUTION_ID =
  `${INTERNAL_URL}/rules/{ruleId}/debug_log/{executionId}` as const;

export const getRuleDebugLogByExecutionIdUrl = (
  ruleId: string,
  executionId: string,
  page: number,
  perPage: number
) =>
  `${INTERNAL_URL}/rules/${ruleId}/debug_log/${executionId}` as const;

export const getRuleExecutionsWithDebugLogUrl = (ruleId: string) =>
  `${INTERNAL_URL}/rules/${ruleId}/executions_with_debug_log` as const;
