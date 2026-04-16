/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export interface PrebuiltWorkflowDefinition {
  id: string;
  yaml: string;
}

export const PREBUILT_WORKFLOWS: PrebuiltWorkflowDefinition[] = [
  {
    id: 'workflow-00000000-0000-5ec0-0000-fa15e00a1e72',
    yaml: `version: "1"
name: Fix false positive alerts
description: When a new security detection rule is created, analyze alerts for false positives and provide recommendations to fix them.
enabled: true
tags:
  - prebuilt
inputs:
  - name: rule_id
    type: string
    required: true
triggers:
  - type: security_rules.created
steps:
  - name: fix_false_positives
    type: ai.agent
    with:
      message: |
        Load fix-false-postive-alerts skill and use {{inputs.rule_id}} as rule ID. Follow skill instructions
`,
  },
];
