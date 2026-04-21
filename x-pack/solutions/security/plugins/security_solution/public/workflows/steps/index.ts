/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { WorkflowsExtensionsPublicPluginSetup } from '@kbn/workflows-extensions/public';

export const registerWorkflowStepDefinitions = (
  workflowsExtensions: WorkflowsExtensionsPublicPluginSetup
): void => {
  workflowsExtensions.registerStepDefinition(() =>
    import('./alerts_search_step').then((m) => m.alertsSearchPublicStepDefinition)
  );
  workflowsExtensions.registerStepDefinition(() =>
    import('./get_autonomous_mode_step').then((m) => m.getAutonomousModePublicStepDefinition)
  );
  workflowsExtensions.registerStepDefinition(() =>
    import('./propose_rule_fix_step').then((m) => m.proposeRuleFixPublicStepDefinition)
  );
  workflowsExtensions.registerStepDefinition(() =>
    import('./apply_rule_fix_step').then((m) => m.applyRuleFixPublicStepDefinition)
  );
  workflowsExtensions.registerStepDefinition(() =>
    import('./noisy_rule_step').then((m) => m.noisyRulePublicStepDefinition)
  );
};
