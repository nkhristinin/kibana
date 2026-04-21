/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createServerStepDefinition } from '@kbn/workflows-extensions/server';
import { proposeRuleFixStepCommonDefinition } from '../../../common/workflows/steps';

export const proposeRuleFixStepDefinition = createServerStepDefinition({
  ...proposeRuleFixStepCommonDefinition,
  handler: async (context) => {
    const { rule_id: ruleId } = context.input;

    // POC stub. Replace with the real fix-rule-errors diagnosis logic
    // (see server/agent_builder/skills/fix_rule_errors/).
    const proposedChanges: Record<string, unknown> = {
      index: ['logs-*'],
    };
    const summary = `Proposed fix for rule ${ruleId}: update index patterns to logs-*`;

    context.logger.info(summary);

    return {
      output: {
        rule_id: ruleId,
        proposedChanges,
        summary,
      },
    };
  },
});
