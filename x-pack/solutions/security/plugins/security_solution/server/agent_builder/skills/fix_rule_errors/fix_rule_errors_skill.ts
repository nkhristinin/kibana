/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { defineSkillType } from '@kbn/agent-builder-server/skills/type_definition';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../../plugin_contract';
import { getGetRuleErrorsTool, getValidateRuleFixTool, getApplyRuleFixTool } from './inline_tools';

export const createFixRuleErrorsSkill = (core: SecuritySolutionPluginCoreSetupDependencies) =>
  defineSkillType({
    id: 'fix-rule-errors',
    name: 'fix-rule-errors',
    basePath: 'skills/security/rules/errors',
    description:
      'Diagnose and fix failing detection rules: fetch rule definitions and execution errors, ' +
      'classify error types, propose fixes (query corrections, index pattern updates, field mapping fixes), ' +
      'validate proposed changes via preview, and apply the fix to the live rule.',
    content: `# Fix Rule Errors

## When to Use This Skill

Use this skill when:
- A detection rule is failing with execution errors
- You need to diagnose why a rule is not running successfully
- You want to fix a rule that has index_not_found, query syntax, or field mapping errors
- You need to validate that a proposed rule change resolves the execution errors before applying it

## Error Categories

This skill handles the following error types:

| Category | Examples | Fix Strategy |
|----------|----------|--------------|
| index_pattern | index_not_found_exception, missing data view | Update index patterns to match available indices |
| query_syntax | parsing_exception, verification_exception | Correct KQL/EQL/ES|QL syntax |
| field_mapping | Unknown field, type mismatch | Use correct ECS field names |
| too_many_results | Bucket limit exceeded, max_signals | Add filters or adjust thresholds |
| ml_job | ML job missing or not started | Suggest correct ML job ID |

System errors (timeouts, shard failures) are not auto-fixable — report them to the user.

## Workflow

### Step 1: Fetch Rule and Errors
Use 'security.fix-rule-errors.get-rule-errors' with the rule ID to get:
- The full rule definition (query, index patterns, language, type, etc.)
- Recent execution error messages
- Failure count and error classification
- Whether the error type is auto-fixable

### Step 2: Diagnose and Propose a Fix
Based on the error category and the rule definition, propose specific changes:

**For index_pattern errors:**
- Check which indices the rule targets
- Suggest updated index patterns (e.g., replace deleted index with current equivalent)
- Consider common Elastic index naming: logs-*, filebeat-*, winlogbeat-*, .ds-logs-*

**For query_syntax errors:**
- Read the error message carefully — it usually points to the exact syntax issue
- Fix KQL syntax (proper field:value, AND/OR operators, escaping)
- Fix EQL syntax (proper event categories, sequence syntax)
- Fix ES|QL syntax (proper FROM, WHERE, STATS clauses)

**For field_mapping errors:**
- Replace unknown fields with correct ECS field names
- Check for typos in field names
- Ensure field types match the query operators used

**For too_many_results errors:**
- Add more specific filters to narrow the query
- Increase the threshold value if using threshold rules
- Add time constraints or entity-specific filters

**For ml_job errors:**
- Verify the ML job ID exists and is correct
- Suggest starting the ML job if it's stopped

### Step 3: Validate the Fix
Use 'security.fix-rule-errors.validate-rule-fix' to test the proposed changes.
Pass only the fields that need to change in the proposedChanges parameter.
The tool merges your changes onto the current rule and runs a preview.

- If validation **passes** (no errors): proceed to apply
- If validation **fails**: revise the fix and try again
- If the preview is **aborted**: the fix may cause performance issues — simplify

### Step 4: Apply the Fix
Only after validate-rule-fix reports success, use 'security.fix-rule-errors.apply-rule-fix'
with the same proposedChanges that were validated.

Do NOT call apply-rule-fix without a prior successful validate-rule-fix result.

## Best Practices
- Always fetch the rule errors first to understand the full context
- Read the error message carefully — it usually tells you exactly what's wrong
- Only change the minimum necessary fields to fix the error
- Always validate before applying — never apply untested changes
- If the first fix attempt fails validation, try a different approach
- For index_pattern errors, check if the index was renamed or if a data view changed
- For query_syntax errors, pay attention to the query language (KQL vs EQL vs ES|QL)
- Document what you changed and why in your response to the user`,
    getInlineTools: () => [
      getGetRuleErrorsTool(core),
      getValidateRuleFixTool(core),
      getApplyRuleFixTool(core),
    ],
  });
