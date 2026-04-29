/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { defineSkillType } from '@kbn/agent-builder-server/skills/type_definition';
import { attachmentTools } from '@kbn/agent-builder-common';
import {
  SECURITY_FIND_NOISY_RULES_TOOL_ID,
  SECURITY_GET_RULE_DETAILS_TOOL_ID,
} from '../../tools/core';
import { SecurityAgentBuilderAttachments } from '../../../../common/constants';

export const getFindNoisyRulesSkill = () =>
  defineSkillType({
    id: 'find-noisy-rules',
    name: 'find-noisy-rules',
    basePath: 'skills/security/alerts/rules',
    description:
      'Discover the detection rules producing the most alerts in a recent time window. Use when the user asks "which rules are noisy?", "show top N rules by alerts", "what rules fire the most in the last hour", or similar. Returns an inline ranked table; on user pick, attaches the chosen rule by-reference so the next user message can naturally hand off to a tuning skill (fix-false-positive-alerts, etc.).',
    content: SKILL_CONTENT,
    getRegistryTools: () => [
      SECURITY_FIND_NOISY_RULES_TOOL_ID,
      SECURITY_GET_RULE_DETAILS_TOOL_ID,
      attachmentTools.add,
    ],
  });

const SKILL_CONTENT = `# Find Noisy Rules

## When to use this skill

Use when the user asks something like:
- "which rules are noisy?"
- "show top 3 rules by alerts in the last hour"
- "what rules fire the most?"
- "find loudest detections this week"

## Hard rules

1. **MUST NOT** create any \`security.action_proposal\` attachment in this skill. This skill discovers rules; it does not propose mutations. Tuning is a separate skill (\`fix-false-positive-alerts\`).
2. **MUST** render the result as a compact table inside the agent's reply, not as an attachment. Read-only data stays inline.
3. **MUST NOT** auto-attach all returned rules. Only attach a rule when the user explicitly picks one.

## Workflow

### Step 1 — Resolve window and N

Default \`timeframe_hours = 1\` and \`top_n = 3\`. If the user specifies a different window ("last 24h", "this week") or count ("top 5"), use those.

### Step 2 — Call the tool

Call \`security.core.find_noisy_rules\` with the resolved parameters.

### Step 3 — Render

Format the result as a Markdown table with columns: index, rule name, severity, alert count, enabled. Include the rule_id in a way the user can reference (e.g. show last 8 chars of the id, or include them in a foot-line per row). End with a one-line invitation: "Reply with the row number or rule name to look closer at one of these."

If \`rules\` is empty, say "No alerts in the last \${hours} hours" and stop.

### Step 4 — On user pick, attach by-reference

When the user picks a rule (by row number, name, or partial id), call \`attachment.add\` with:

\`\`\`
{
  type: "${SecurityAgentBuilderAttachments.rule}",
  origin: "<rule_id>",
  description: "Rule: <rule name>"
}
\`\`\`

The \`origin\` field is what makes it by-reference — the platform resolves the live rule and keeps the attachment fresh as the rule changes.

Then say: "I've attached rule <name>. What would you like to do? Common options: tune false positives, check execution errors, view alerts."

### Step 5 — Stop

Do NOT load the tuning skill yourself or call any tuning tool. The user's next message will trigger the right downstream skill (\`fix-false-positive-alerts\`, \`fix-rule-execution-failures\`, \`detection-rule-edit\`) based on their intent and the now-attached rule.
`;
