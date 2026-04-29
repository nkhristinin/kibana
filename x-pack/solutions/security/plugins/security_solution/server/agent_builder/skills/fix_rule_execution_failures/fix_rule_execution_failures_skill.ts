/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { defineSkillType } from '@kbn/agent-builder-server/skills/type_definition';
import { attachmentTools } from '@kbn/agent-builder-common';
import {
  SECURITY_GET_RULE_DETAILS_TOOL_ID,
  SECURITY_PROPOSE_ACTION_TOOL_ID,
} from '../../tools/core';

export const getFixRuleExecutionFailuresSkill = () =>
  defineSkillType({
    id: 'fix-rule-execution-failures',
    name: 'fix-rule-execution-failures',
    basePath: 'skills/security/alerts/rules',
    description:
      'Diagnose a broken or repeatedly failing detection rule and propose a safe next action. Use it both for the first remediation recommendation and for compatible follow-up tweaks to that same remediation proposal. By default the skill publishes an action-proposal attachment in chat, but it can also be used in a staged way by callers that explicitly ask for reasoning-only output or structured action JSON without creating a card.',
    content: SKILL_CONTENT,
    getRegistryTools: () => [
      SECURITY_GET_RULE_DETAILS_TOOL_ID,
      SECURITY_PROPOSE_ACTION_TOOL_ID,
      attachmentTools.read,
    ],
  });

const SKILL_CONTENT = `# Fix Rule Execution Failures

## When to use this skill

Use this skill when the user:
- Attaches a rule and says it is broken, failing, throwing execution errors, or should be stopped for now.
- Describes a rule failure and wants you to recommend either a fix or a temporary stop-gap.
- Follows up on an existing rule-failure remediation proposal for that same rule with another compatible stabilizing tweak.

This skill only produces proposals. It never mutates a rule directly. Its goal is to stabilize or safely contain a failing rule. Compatible follow-up changes can be folded into the same pending remediation proposal. Unrelated metadata edits should not be silently absorbed into this remediation flow.

## Hard rules

1. **MUST NOT** call any mutation API directly. Only create a proposal via \`security.core.propose_action\`.
2. **MUST** choose at most one remediation strategy for the current turn:
   - \`rule_change\` with \`intent: "query_tuning"\` when there is a clear, narrow, low-risk query fix.
   - \`rule_change\` with \`intent: "disable"\` and \`proposed_changes.enabled = false\` when the failure is persistent, unclear, unsafe to patch blindly, or the user explicitly wants the rule stopped.
3. **MUST** default to full proposal mode unless the caller explicitly asks for a staged output such as reasoning-only or action-json-only.

## Operating modes

This skill supports three modes. The caller decides the mode explicitly. If the caller does not say otherwise, use **Proposal mode**.

### Mode A — Proposal mode (default chat behavior)

Use all stages below. At the end, call \`security.core.propose_action\`, render the returned attachment inline, and briefly explain the recommendation.

### Mode B — Reasoning-only mode

If the caller explicitly asks for assessment only, reasoning only, diagnosis only, or says not to create a proposal yet:
- resolve only the missing context
- analyze the failure shape
- choose the safest remediation strategy
- stop before proposal creation

Return compact JSON only:

\`\`\`json
{
  "context": {
    "rule_id": "<saved-object rule id>",
    "failure_signals": ["<key observations>"]
  },
  "reasoning": {
    "recommended_strategy": "rule_change | disable | no_action",
    "confidence": "low | medium | high",
    "reason": "<why this is the safest next step>"
  }
}
\`\`\`

### Mode C — Action JSON only

If the caller explicitly asks for a proposed action without creating a card:
- do the same analysis as Proposal mode
- stop before calling \`security.core.propose_action\`
- return structured action JSON only

Return compact JSON only:

\`\`\`json
{
  "summary": "<stable one-line summary>",
  "reason": "<one sentence on why this action should help>",
  "action": {
    "action_type": "rule_change",
    "rule_id": "<saved-object rule id>",
    "...": "action-specific fields"
  }
}
\`\`\`

## Workflow

### Step 1 — Resolve the rule

Preferred path:
- If a rule attachment is present, read it with \`attachment_read\` and parse \`data.text\` as JSON. The \`.id\` field is the saved-object id for the rule.

Fallback:
- If the user already gave you the saved-object rule id, use it directly.
- Otherwise, if you only have the rule id from some other context, call \`security.core.get_rule_details\`.

Caller-provided context:
- If the caller already supplied a reliable saved-object \`rule_id\`, normalized rule JSON, or a structured failure summary, reuse that input and only fetch what is still missing.

### Step 2 — Decide whether this is a fix or a disable

Use the user's failure description plus the current rule shape to decide:

Choose **query change** only when all of the following are true:
- The user described a specific query problem you can fix safely in one step.
- The fix is narrow and localized to the query or language.
- You can explain the exact change in one sentence.

Typical examples:
- The query references a field that is wrong and you can replace it with the intended one.
- The query needs a small exclusion to avoid a broken data source or benign pattern.
- The language setting is wrong for the current query string.

Choose **disable rule** when any of the following is true:
- The user explicitly asks to stop the rule.
- The failure is persistent but the safe fix is unclear.
- The error suggests broader investigation is needed outside a simple query edit.
- A speculative query patch would be riskier than pausing the rule.

### Step 3 — Build the remediation

#### If proposing a query change

Call:

\`\`\`
security.core.propose_action({
  action_type: "rule_change",
  rule_id: "<saved-object rule id>",
  proposed_changes: {
    "query": "<new query>"
  },
  intent: "query_tuning",
  summary: "<short title>",
  reason: "<one sentence on what failed and why this query fix should help>"
})
\`\`\`

Only use this when you are confident about the exact query. Compatible follow-up stabilizing changes on the same rule can add fields such as \`language\`, \`interval\`, or \`from\` by calling the tool again. Do NOT absorb unrelated metadata edits into this remediation flow.

#### If proposing to disable the rule

Call:

\`\`\`
security.core.propose_action({
  action_type: "rule_change",
  rule_id: "<saved-object rule id>",
  proposed_changes: {
    "enabled": false
  },
  intent: "disable",
  summary: "<short title>",
  reason: "<one sentence on why disabling is the safest immediate action>"
})
\`\`\`

In **Action JSON only** mode, stop here and return structured JSON using the same fields that would be passed to the proposer tool.

### Step 4 — Render and stop

In **Proposal mode**, render the returned attachment inline with \`<render_attachment id="<returned attachment id>" />\`. If a pending rule-change proposal for this rule already exists, the tool will update that same attachment instead of creating a second card.

Tell the user, briefly:
- what you are proposing,
- why this is the safest next step,
- and that they can click **Approve** to apply it.

If the user follows up with another compatible stabilizing "also..." change for the same remediation, call \`security.core.propose_action\` again so the pending proposal is updated in place. In Reasoning-only or Action JSON only mode, stop after returning the requested JSON and do not render an attachment.
`;
