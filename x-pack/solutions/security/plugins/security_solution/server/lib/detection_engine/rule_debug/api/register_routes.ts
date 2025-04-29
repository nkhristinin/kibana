/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SecuritySolutionPluginRouter } from '../../../../types';
import { getRuleDebugLogByExecutionId } from './get_rule_debug_log_by_execution_route';
import { getRuleExecutionsWithDebugLog } from './get_rule_executions_with_debug_log_route';

export const registerRuleDebugLogRoutes = (router: SecuritySolutionPluginRouter) => {
  getRuleExecutionsWithDebugLog(router);
  getRuleDebugLogByExecutionId(router);
};
