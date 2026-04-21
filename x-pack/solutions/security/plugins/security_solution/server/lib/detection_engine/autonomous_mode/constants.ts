/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Workflow IDs the Security rule UI surfaces pending / recent executions from.
 * Used by the rule page to show "pending automation approvals" for a rule.
 * Add new workflow IDs here as more autonomous-mode workflows ship.
 */
export const MONITORED_WORKFLOW_IDS: readonly string[] = [
  'security.rules.autonomousFix',
] as const;
