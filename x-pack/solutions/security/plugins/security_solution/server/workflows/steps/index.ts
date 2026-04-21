/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { CoreSetup } from '@kbn/core/server';
import type { WorkflowsExtensionsServerPluginSetup } from '@kbn/workflows-extensions/server';
import { alertsSearchStepDefinition } from './alerts_search_step';
import { getGetAutonomousModeStepDefinition } from './get_autonomous_mode_step';
import { proposeRuleFixStepDefinition } from './propose_rule_fix_step';
import { getApplyRuleFixStepDefinition } from './apply_rule_fix_step';

export const registerWorkflowSteps = (
  workflowsExtensions: WorkflowsExtensionsServerPluginSetup,
  getStartServices: CoreSetup['getStartServices']
): void => {
  workflowsExtensions.registerStepDefinition(alertsSearchStepDefinition);
  workflowsExtensions.registerStepDefinition(getGetAutonomousModeStepDefinition(getStartServices));
  workflowsExtensions.registerStepDefinition(proposeRuleFixStepDefinition);
  workflowsExtensions.registerStepDefinition(getApplyRuleFixStepDefinition(getStartServices));
};
