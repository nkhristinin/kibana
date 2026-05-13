/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { defineSkillType } from '@kbn/agent-builder-server/skills/type_definition';
import { SECURITY_FIND_RULES_TOOL_ID, SECURITY_ALERTS_TOOL_ID } from '../../tools';

export const findRulesSkill = defineSkillType({
  id: 'find-rules',
  name: 'find-rules',
  basePath: 'skills/security/rules',
  description:
    'Discover, list, rank, group, and count Security detection rules across the rule inventory. ' +
    'Browse rules by tags (with tag discovery), MITRE technique/tactic, severity, rule type, ' +
    'risk score range, name substring, source index pattern, or enabled state. ' +
    'Rank rules by alert volume to identify noisy detections. ' +
    "Read-only and scoped to MULTI-rule discovery — for individual rule actions or other rule-engine queries see the appropriate sibling skills documented in this skill's content.",
  content: `# Find Detection Rules

## When to Use This Skill

Use this skill when the user asks to **list or rank multiple Security detection rules** by:
- Metadata: tags, enabled state, rule type, severity, name pattern, risk score, MITRE technique/tactic, index pattern
- Alert volume: which rules are noisy / produced the most alerts

## Do NOT Use When

- The user is triaging a specific alert (alert id) — that's alert-analysis
- The user wants to create or edit a **single** rule via the rule attachment in chat — that's detection-rule-edit
- The user wants a proactive ES|QL hunt for suspicious activity — that's threat-hunting
- The user is asking about alerting V2 (ES|QL alerts) rules — that's rule-management

## ⚠️ Action Limitations — Read-Only Skill

This skill **only reads** detection rules. The following actions are **not supported** by any tool currently available to the agent:

- Bulk enable / disable rules
- Bulk delete rules
- Bulk duplicate rules
- Modifying tags, severity, schedule, or any other field on an existing rule that is not loaded into the chat as a rule attachment
- Running bulk actions against the detection engine API

If the user asks for any of these after seeing a rule list (e.g. "now enable all of them", "disable these", "change the severity on these to high"):

1. **Do NOT** invoke other tools hoping one will work.
2. **Do NOT** spawn a sub-agent to retry.
3. **Do NOT** look for a connector to call the Kibana API.
4. **Do** respond plainly: explain that bulk rule mutation is not available in chat yet, and direct the user to **Security → Rules → Detection Rules** in the UI (Bulk actions → Enable/Disable/Delete) or the \`POST /api/detection_engine/rules/_bulk_action\` endpoint, including the rule IDs from the listing for convenience.

Single-rule edits via an existing **rule attachment in this chat** are still routed to detection-rule-edit — that path is supported.

## 🚫 Grounding — Never Invent Values

Every tag name, index pattern, rule name, rule ID, alert count, or total in your response must come from a tool result earlier in this conversation. Do not fill in plausible-looking values from prior knowledge, do not round counts ("about 50" when the tool said 47), do not add an "and also" rule that was not in the result set, and do not echo a rule UUID you have not seen in a tool result.

If a filter returns zero results, say so. Do not list rules from memory or from a previous turn's result set.

## 🏷️ Tag Discovery — ALWAYS Discover Before Filtering by Tag (No Exceptions)

Tag values are environment-specific and you cannot know the canonical strings in this space from prior knowledge — even widely-used names like "MITRE" may be spelled, cased, or absent differently here.

**Whenever any tag filter is involved — whether the user named the tag string directly ("rules tagged MITRE"), referenced a category ("endpoint rules"), or described semantic intent ("anything about network security") — you MUST:**

1. **First call** \`security.find_rules\` with \`groupBy: "tags"\` to enumerate the actual tag values in this space. This is the same data the Detection Rules UI tag filter loads.
2. **Read the returned tag list.** Pick the exact strings whose meaning matches the user's intent.
3. **Then call** \`security.find_rules\` again with one \`{ tag: "<exact value>" }\` condition per tag.

Do not skip discovery, even when the user's wording looks like a known tag. If \`groupBy: "tags"\` returns no tag matching the user's intent, tell the user plainly and offer the closest available values — do not invent one.

Exception — **structured MITRE IDs** (\`T####\`, \`T####.###\`, \`TA####\`): use \`{ mitreTechnique: "T1059" }\` / \`{ mitreTactic: "TA0002" }\` directly, no discovery needed. The format is canonical and schema-enforced.

## Process

### 1. Choose the right tool

- **Rule metadata / counts / sort** → \`security.find_rules\` (structured filters).
- **Alert volume ranking** ("noisiest rules", "top N by alerts"):
  1. Call \`security.alerts\` to aggregate alerts grouped by \`kibana.alert.rule.uuid\` (NOT \`kibana.alert.rule.name\` — names are not guaranteed unique).
  2. Then call \`security.find_rules\` with one \`{ ruleUuid: "<uuid>" }\` condition per top rule (each as its own AndGroup, OR-combined across groups) to translate the UUIDs into rule names + metadata. The same UUID also identifies rules in the event log (\`kibana.saved_objects.id\`) — so this is the one identifier to use across all rule lookups. ⚠️ Note the atom name: \`ruleUuid\` is the Saved Object UUID (\`kibana.alert.rule.uuid\`), NOT the static detection-engine \`rule_id\` — both identifiers are surfaced in the tool's output as \`id\` and \`ruleId\` respectively.
- **Tag discovery** (before filtering by tag) → \`security.find_rules\` with \`groupBy: "tags"\`. See "Tag Discovery" above.

### 2. Build a structured filter (no KQL)

\`security.find_rules\` takes a structured filter — never raw KQL. The shape mirrors the indicator-match rule's \`threat_mapping\`:

- \`filter: AndGroup[]\` — **outer array = OR**. Rules matching ANY group are included.
- \`exclude: AndGroup[]\` — same shape; rules matching ANY group are EXCLUDED.
- \`AndGroup\` = \`Condition[]\` — **inner array = AND**. All conditions in a group must match.
- \`Condition\` = **one atomic fact** (one field per object), e.g. \`{ severity: "critical" }\`, \`{ tag: "MITRE" }\`, \`{ mitreTechnique: "T1059" }\`.

**One rule to remember:** outer is OR, inner is AND, leaf is one fact. There is no "OR within a field" — to express OR you always split into two groups.

### 3. Atomic conditions

Use exactly one of these shapes per object:

| User intent | Condition |
|---|---|
| Enabled / disabled | \`{ enabled: true }\` or \`{ enabled: false }\` |
| Custom vs prebuilt | \`{ ruleSource: "custom" }\` or \`{ ruleSource: "prebuilt" }\` |
| One severity | \`{ severity: "critical" }\` |
| One rule type | \`{ ruleType: "query" }\` |
| One tag (discover first — see Tag Discovery) | \`{ tag: "MITRE" }\` |
| One MITRE technique | \`{ mitreTechnique: "T1059" }\` |
| One MITRE tactic | \`{ mitreTactic: "TA0002" }\` |
| Name substring | \`{ nameContains: "PowerShell" }\` |
| Min risk score | \`{ riskScoreMin: 70 }\` |
| Max risk score | \`{ riskScoreMax: 90 }\` |
| Index pattern | \`{ indexPattern: "logs-endpoint*" }\` |
| Rule lookup by SO UUID (alert → rule translation, event-log lookups) | \`{ ruleUuid: "<kibana.alert.rule.uuid value>" }\` |

### 4. Pattern examples

- **"Critical severity rules"** → \`filter: [[{ severity: "critical" }]]\`
- **"Critical OR high severity"** → \`filter: [[{ severity: "critical" }], [{ severity: "high" }]]\`
- **"Critical AND MITRE-tagged"** → \`filter: [[{ severity: "critical" }, { tag: "MITRE" }]]\`
- **"Tagged MITRE AND Custom (same rule)"** → \`filter: [[{ tag: "MITRE" }, { tag: "Custom" }]]\`
- **"Tagged MITRE OR Custom"** → \`filter: [[{ tag: "MITRE" }], [{ tag: "Custom" }]]\`
- **"(critical AND MITRE) OR (high AND Custom)"** → \`filter: [[{ severity: "critical" }, { tag: "MITRE" }], [{ severity: "high" }, { tag: "Custom" }]]\`
- **"MITRE-tagged but NOT Custom"** → \`filter: [[{ tag: "MITRE" }]]\`, \`exclude: [[{ tag: "Custom" }]]\`
- **"Risk score between 70 and 90"** → \`filter: [[{ riskScoreMin: 70 }, { riskScoreMax: 90 }]]\`
- **"All disabled rules"** → \`filter: [[{ enabled: false }]]\`

### 5. Sort, page, group

- Sort: \`sortField: "severity"\` (or \`risk_score\`, \`updatedAt\`, etc.) + \`sortOrder: "desc"\`
- Top-N: \`perPage: N\`
- Count grouped by attribute: \`groupBy: "ruleType"\` (or \`tags\`, \`enabled\`, \`mitreTechnique\`, \`mitreTactic\`)
- The tool returns at most 500 groups per aggregation. If \`truncated: true\` is set, additional groups exist beyond the cap (\`otherDocCount\` tells you how many) — surface this to the user instead of stating that a value does not exist.

### 6. Render the result

**Rule lists** — default columns, in this order: **Name | Severity | Enabled | Type**.

Add a column only when one of these applies:
- The user **filtered by** that field (e.g. a \`{ tag: "MITRE" }\` condition → add Tags column).
- The user **sorted by** that field (e.g. \`sortField: "updatedAt"\` → add Updated column).
- The user **explicitly asked** for that field (e.g. "show me the MITRE techniques" → add MITRE column).

Show at most 20 rows. If the result \`total\` exceeds what is shown, append a single line like "Showing 20 of 47 matching rules."

**\`groupBy\` results** — two columns: **Value | Count**, sorted by count descending.

**Alert-volume rankings** — two columns: **Rule Name | Alert Count**, sorted by alert count descending.`,
  getRegistryTools: () => [SECURITY_FIND_RULES_TOOL_ID, SECURITY_ALERTS_TOOL_ID],
});
