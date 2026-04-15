/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Logger } from '@kbn/core/server';
import { defineSkillType } from '@kbn/agent-builder-server/skills/type_definition';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../../plugin_contract';
import {
  getSearchAlertsByRuleTool,
  getSearchAlertsByHostTool,
  getSearchAlertsByUserTool,
  getCompareRuleFixTool,
  getApplyRuleFixTool,
  getAddRuleExceptionTool,
} from './inline_tools';
import { FALSE_POSITIVE_THRESHOLD } from './inline_tools/common';

export const createFixFalsePositiveAlertsSkill = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
) =>
  defineSkillType({
    id: 'fix-false-positive-alerts',
    name: 'fix-false-positive-alerts',
    basePath: 'skills/security/alerts/rules',
    description:
      'Detect and fix false positive security alerts: search alerts by rule ID, analyze entity patterns, ' +
      'suggest and validate query changes, add rule exceptions, and apply fixes to reduce noise.',
    content: `# Fix False Positive Alerts

## When to Use This Skill

Use this skill when:
- You suspect a detection rule is generating false positive alerts
- You want to check whether a specific rule ID is producing too many alerts
- You need to identify noisy rules that require tuning
- You want to verify that a proposed rule query change actually reduces alert volume
- You need to suppress known-good entities from triggering a rule via exceptions

## Workflow

### Step 1: Identify the Problem
Use 'security.fix-false-positive-alerts.search-alerts-by-rule' with the rule ID to check alert volume.
If the tool flags more than ${FALSE_POSITIVE_THRESHOLD} alerts, the rule is likely producing false positives.

### Step 2: Analyze Alert Entities
After identifying a noisy rule, pivot on the alerts to find the root cause:
- Use 'security.fix-false-positive-alerts.search-alerts-by-host' to see which hosts generate the most alerts AND which parent processes spawn them
- Use 'security.fix-false-positive-alerts.search-alerts-by-user' to see which users generate the most alerts AND which parent processes are involved
Both tools return breakdowns by host/user, parent process, and process name.
Focus on the **parentProcessBreakdown** — parent processes reveal WHY alerts are false positives (e.g. a configuration management tool, a CI runner), while hosts/users only reveal WHERE they occur.

### Step 3: Choose a Tuning Strategy
Combine the alert patterns from Steps 1-2 and select the best approach. Strategies are ranked from most durable to least durable:

1. **Rule exceptions** (use 'add-rule-exception')
   Best when: the false positive source is a known-good entity (service account, management tool, automated process).
   Advantages: explicit, survives rule query updates, easy to audit and remove later.
   Use when you can identify a specific field+value combination that cleanly separates FP from TP alerts.

2. **Query modification** (use 'compare-rule-fix' then 'apply-rule-fix')
   Best when: the rule query is fundamentally too broad and needs structural narrowing.
   Use when the FP pattern is integral to the rule logic itself, not an external entity.

3. **Alert suppression** (outside this skill — recommend to user)
   Best when: the same entity generates duplicate alerts within a time window.
   Recommend configuring suppression fields on the rule when deduplication is the primary concern.

### Step 4: Identify the Right Exclusion Target
When building an exception or query modification, identify the most specific causal field that distinguishes FP from TP alerts. Prioritize in this order:
1. **Parent process** (process.parent.name) — targets the automation tool or service causing the FP
2. **Process arguments** (process.command_line patterns) — targets specific command invocations
3. **User** (user.name) — acceptable for service accounts, but users can change roles
4. **Host** (host.name) — last resort, fragile since new hosts require re-tuning

Prefer targeting the process or software causing the FP over the location where it runs.
If the FP source is a known-good tool or service account, an exception is more durable than a query change.

### Step 5: Apply the Fix

**For exceptions:**
Use 'security.fix-false-positive-alerts.add-rule-exception' with the ruleId, a descriptive name, and the entries that match the FP entity.
The tool automatically creates a rule_default exception list if one does not exist, attaches it to the rule, and creates the exception item.

**For query modifications:**
Use 'security.fix-false-positive-alerts.compare-rule-fix' to test your suggested query.
Use the default timeframeMinutes of 10 to preview on the last 10 minutes of data.
The tool runs the detection engine preview TWICE on the same time interval:
1. First with the **original unchanged rule** to establish a baseline alert count
2. Then with the **modified query** to see how many alerts it would produce

### Step 6: Evaluate Query Comparison Results
The comparison tool reports:
- **Success**: suggested query produces fewer alerts — proceed to apply
- **No improvement**: alert count is the same or higher — suggest further refinements and re-run compare
- **Over-tuned**: alerts dropped to zero — warn that the query may be too aggressive; do not apply

### Step 7: Apply the Query Fix
Only after compare-rule-fix reports **Success** (fewer alerts, not zero), use
'security.fix-false-positive-alerts.apply-rule-fix' with the ruleId and the
validated newQuery to patch the live rule in Kibana.
Do NOT call apply-rule-fix without a prior successful compare-rule-fix result.

## Best Practices
- Always verify the flagged alerts manually before bulk-closing them
- Check if the alerts share common entities (hosts, users) that can be excluded
- Document any rule query changes or exception additions for audit purposes
- Use the compare tool to validate query changes before modifying the live rule
- After applying changes, monitor the rule for a few days to confirm the fix holds
- Prefer \`match\` entries over \`wildcard\` in exceptions when exact values are known
- Always scope exceptions to the specific rule — avoid overly broad exception lists
- Tag exception items with a rationale so they can be reviewed later`,
    getInlineTools: () => [
      getSearchAlertsByRuleTool(),
      getSearchAlertsByHostTool(),
      getSearchAlertsByUserTool(),
      getCompareRuleFixTool(core, logger),
      getApplyRuleFixTool(core),
      getAddRuleExceptionTool(core, logger),
    ],
  });
