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
  SECURITY_SEARCH_ALERTS_BY_RULE_TOOL_ID,
  SECURITY_AGGREGATE_ALERTS_FOR_RULE_TOOL_ID,
  SECURITY_PREVIEW_RULE_TOOL_ID,
  SECURITY_PROPOSE_ACTION_TOOL_ID,
} from '../../tools/core';

export const getFixFalsePositiveAlertsSkill = () =>
  defineSkillType({
    id: 'fix-false-positive-alerts',
    name: 'fix-false-positive-alerts',
    basePath: 'skills/security/alerts/rules',
    description:
      'Diagnose whether a detection rule is producing false-positive alerts and propose a focused remediation. Use when the user attaches a rule (or an alert) and asks whether it is noisy, whether a specific pattern is a false positive, asks to tune a rule, asks to add an exception, or asks for a compatible follow-up tweak to an existing false-positive proposal. By default the skill publishes an action-proposal attachment in chat, but it can also be used in a staged way by callers that explicitly ask for reasoning-only output or structured action JSON without creating a card.',
    content: SKILL_CONTENT,
    getRegistryTools: () => [
      SECURITY_GET_RULE_DETAILS_TOOL_ID,
      SECURITY_SEARCH_ALERTS_BY_RULE_TOOL_ID,
      SECURITY_AGGREGATE_ALERTS_FOR_RULE_TOOL_ID,
      SECURITY_PREVIEW_RULE_TOOL_ID,
      // attachment_read is still needed to resolve the attached rule; proposal
      // creation now goes through a shared proposer tool so this skill's logic
      // stays reusable for later deterministic flows.
      attachmentTools.read,
      SECURITY_PROPOSE_ACTION_TOOL_ID,
    ],
  });

const SKILL_CONTENT = `# Fix False Positive Alerts

## When to use this skill

Use this skill when the user:
- Attaches a detection rule (or an alert) and asks "is this a false positive?" / "why is this rule noisy?" / "can you tune this rule?"
- Asks to reduce false positives on a specific rule.
- Asks to add an exception instead of changing the rule query.
- Follows up on an existing false-positive tuning proposal for that same rule with another compatible tweak such as "also lower the severity" or "make it run every 5m".

This skill's primary job is to reduce noise without unnecessarily weakening the detection. Start with the smallest change justified by the alert analysis. That may be a query-level exclusion or a rule exception item. Compatible follow-up changes that still support the same goal can be folded into the same pending proposal when they stay within the same strategy. Unrelated rule-editing requests (name, tags, MITRE mappings, etc.) should not be silently absorbed into this remediation flow.

## Hard rules (must follow exactly)

1. **MUST NOT** perform any rule mutation yourself. You never apply the change. You only propose. The user approves the action by clicking a button in the action-proposal attachment — that browser click is what performs the actual mutation (which is why the approval flow is out-of-agent, not a tool call).
2. **MUST** run \`security.core.preview_rule\` BEFORE creating or updating a proposal that changes the rule query. If the preview's \`is_improved\` is false, or \`is_over_tuned\` is true, DO NOT propose that query change — tell the user why and stop.
3. **MUST** produce at most one remediation strategy for the current turn. Do not mix query tuning and exception creation in a single answer.
4. **MUST** default to full proposal mode unless the caller explicitly asks for a staged output such as reasoning-only or action-json-only.

## Operating modes

This skill supports three modes. The caller decides the mode explicitly. If the caller does not say otherwise, use **Proposal mode**.

### Mode A — Proposal mode (default chat behavior)

Use all stages below. At the end, call \`security.core.propose_action\`, render the returned attachment inline, and briefly explain the recommendation.

### Mode B — Reasoning-only mode

If the caller explicitly asks for assessment only, reasoning only, diagnosis only, or says not to create a proposal yet:
- resolve only the missing context
- analyze the rule and alerts
- choose the best remediation strategy
- stop before proposal creation

Return compact JSON only:

\`\`\`json
{
  "context": {
    "rule_id": "<saved-object rule id>",
    "signals": ["<high-signal observations>"]
  },
  "reasoning": {
    "recommended_strategy": "rule_change | rule_exception_add | no_action",
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
    "action_type": "rule_change | rule_exception_add",
    "rule_id": "<saved-object rule id>",
    "...": "action-specific fields"
  }
}
\`\`\`

## Workflow

Treat the workflow below as staged. A caller can stop after Step 4 for Reasoning-only mode, stop after Step 5 for Action JSON only, or continue through Step 5 and Step 6 for Proposal mode.

### Step 1 — Resolve context

Two entry points. Handle whichever you have:

**Rule attached:** Read the rule attachment with \`attachment_read\`. Parse \`data.text\` as JSON. The \`.id\` field is the rule's saved-object id — this is the \`rule_id\` to pass to every tool below.

**Alert attached (no rule):** Extract \`kibana.alert.rule.uuid\` from the alert — that is the \`rule_id\`. Call \`security.core.get_rule_details\` with that \`rule_id\` to fetch the rule (you need its full JSON in the next step).

**Caller-provided context:** If the caller already supplied a reliable saved-object \`rule_id\`, normalized rule JSON, alert summary, or dominant entities, reuse that input and only fetch what is still missing.

### Step 2 — Assess noise

Call \`security.core.search_alerts_by_rule\` and \`security.core.aggregate_alerts_for_rule\` with the resolved \`rule_id\`. Inspect the results:
- If the total count is low (< 10 in the default window), tell the user the rule is not noisy and stop.
- Otherwise, look at the aggregation buckets. A single dominant bucket in \`by_parent_process\`, \`by_user\`, or \`by_host\` is a strong signal for an exclusion target. Parent process is usually the highest-value signal (it identifies a specific benign automation, e.g. \`ci-runner\`, \`puppet\`, \`ansible-playbook\`).

### Step 3 — Hypothesise an exclusion

Pick the field + values that look most like benign activity. Examples:
- \`process.parent.name\` is \`["ci-runner"]\` — 87% of alerts came from this parent.
- \`user.name\` is \`["svc-backup"]\` — service account responsible for most alerts.

Prefer narrow exclusions. Never exclude on \`host.name\` alone unless the narrative justifies excluding an entire host.

### Step 4 — Choose the strategy

Choose **query change** when:
- the fix naturally belongs in the rule logic,
- the user asks to tune or change the query,
- or you need to change rule fields like \`query\`, \`language\`, \`severity\`, \`interval\`, or \`from\`.

Choose **rule exception** when:
- the user explicitly asks for an exception,
- or the safest fix is a narrow reusable exception item on one or more concrete fields/values.

If you choose **query change**, call \`security.core.preview_rule\` with the hypothesised exclusions. Read the \`verdict\`:
- \`is_improved = false\` → pick a different field or values; do not propose this change.
- \`is_over_tuned = true\` → the exclusion is too broad; narrow it or pick a different field.
- Good reduction → proceed to Step 5.

If you choose **rule exception**, you can proceed directly to Step 5 using the field/value pattern you identified.

### Step 5 — Materialize the recommendation

Build a proposed remediation for the selected strategy.

For **query change**:
- First-turn diagnosis usually changes only \`query\` (and sometimes \`language\`).
- Later compatible follow-ups on the same rule can add fields like \`severity\`, \`risk_score\`, \`interval\`, or \`from\` when they still support the same noise-reduction plan.

For **rule exception**:
- Create one or more exception items with a clear \`name\`, \`description\`, and \`entries\`.
- Prefer simple, narrowly scoped entries such as \`match\`, \`match_any\`, \`exists\`, or \`wildcard\`.
- Use \`operator: "included"\` for the standard "suppress alerts when this benign condition is present" case.

Do NOT absorb unrelated metadata edits like renaming the rule, changing tags, or MITRE mappings into this remediation flow.

In **Action JSON only** mode, stop here and return structured JSON using the same fields that would be passed to the proposer tool.

In **Proposal mode**, create the proposal with the shared proposer tool:

\`\`\`
// Query change
security.core.propose_action({
  action_type: "rule_change",
  rule_id: "<saved-object rule id>",
  proposed_changes: {
    "query": "<updated query string>"
  },
  intent: "query_tuning",
  summary: "<stable one-line summary for the overall tuning plan, e.g. 'Tune Rule X to reduce false positives'>",
  reason: "<one sentence — which entity you excluded and why>",
  metrics: {
    "original_count": <n>,
    "surviving_count": <m>,
    "reduction_percent": <p>
  }
})
\`\`\`

\`\`\`
// Rule exception
security.core.propose_action({
  action_type: "rule_exception_add",
  rule_id: "<saved-object rule id>",
  items: [
    {
      "name": "Exclude ci-runner parent process",
      "description": "Suppress alerts triggered by known benign CI automation",
      "type": "simple",
      "entries": [
        {
          "type": "match",
          "field": "process.parent.name",
          "operator": "included",
          "value": "ci-runner"
        }
      ]
    }
  ],
  summary: "Add exception to reduce false positives on Rule X",
  reason: "<one sentence — which entity you excluded and why>",
})
\`\`\`

Then render the returned attachment inline: \`<render_attachment id="<returned attachment id>" />\`. If a pending proposal with the same strategy for this rule already exists, the tool will update that same attachment instead of creating a second card. If the user switches strategies (for example from query tuning to adding an exception), create a separate proposal card. Briefly tell the user what you propose and why, and let them know they can click **Approve** on the attachment to apply the change (or **Dismiss** to discard it).

### Step 6 — Stop

That is the end of the skill's work for this turn. Do NOT call any further mutation tools. In Proposal mode, the user's click on the Approve button executes the change in the browser, attributed to the user. If the user follows up with another compatible "also..." change for the same remediation and the same strategy, call \`security.core.propose_action\` again so the pending proposal is updated in place. If the user pivots from query tuning to exceptions (or the reverse), create a new proposal instead of forcing both strategies into one card. In Reasoning-only or Action JSON only mode, stop after returning the requested JSON and do not render an attachment.`;
