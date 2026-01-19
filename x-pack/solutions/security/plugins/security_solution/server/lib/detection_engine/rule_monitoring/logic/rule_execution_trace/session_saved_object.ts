/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SavedObjectsType } from '@kbn/core-saved-objects-server';

export const RULE_EXECUTION_TRACE_SESSION_SO_TYPE = 'security-rule-exec-trace-session';

export interface RuleExecutionTraceSessionAttributes {
  execution_id?: string;
  rule_id: string;
  created_at: string;
  expires_at: string;
}

export const ruleExecutionTraceSessionType: SavedObjectsType = {
  name: RULE_EXECUTION_TRACE_SESSION_SO_TYPE,
  namespaceType: 'single',
  hidden: false,
  mappings: {
    dynamic: false,
    properties: {
      execution_id: { type: 'keyword' },
      rule_id: { type: 'keyword' },
      created_at: { type: 'date' },
      expires_at: { type: 'date' },
    },
  },
};


