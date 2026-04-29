/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { defineSkillType } from '@kbn/agent-builder-server/skills/type_definition';
import {
  SECURITY_PROPOSE_ACTION_TOOL_ID,
  SECURITY_REVIEW_PREBUILT_RULES_TO_INSTALL_TOOL_ID,
} from '../../tools/core';

export const getInstallRelevantPrebuiltRulesSkill = () =>
  defineSkillType({
    id: 'install-relevant-prebuilt-rules',
    name: 'install-relevant-prebuilt-rules',
    basePath: 'skills/security/alerts/rules',
    description:
      'Recommend and propose installation of relevant prebuilt detection rules. This MVP uses lightweight matching against installable prebuilt rule names and tags, then creates a rule-install proposal the user can approve from chat.',
    content: SKILL_CONTENT,
    getRegistryTools: () => [
      SECURITY_REVIEW_PREBUILT_RULES_TO_INSTALL_TOOL_ID,
      SECURITY_PROPOSE_ACTION_TOOL_ID,
    ],
  });

const SKILL_CONTENT = `# Install Relevant Prebuilt Rules

## When to use this skill

Use this skill when the user:
- Asks which prebuilt rules should be installed for a use case, integration, or threat theme.
- Wants you to install a small relevant set of prebuilt rules from chat.

This MVP skill uses lightweight matching against installable prebuilt rule names and tags. It is intentionally simple and exists to exercise the shared proposal flow and a different attachment UI.

## Hard rules

1. **MUST NOT** install rules directly. Only create a proposal via \`security.core.propose_action\`.
2. **MUST** inspect candidate rules first with \`security.core.review_prebuilt_rules_to_install\`.
3. **MUST** propose a small set, usually 1-5 rules, not a giant bulk install.

## Workflow

### Step 1 — Derive simple search hints

From the user's request, derive:
- \`tags\`: short category hints such as \`["Elastic", "Cloud"]\`, \`["Linux"]\`, \`["Execution"]\`
- \`names\`: short name fragments only when the user gave a clear product or technique name

Do not overfit. If the request is broad, prefer tags over names.

### Step 2 — Review installable candidates

Call:

\`\`\`
security.core.review_prebuilt_rules_to_install({
  tags: [...],
  names: [...],
  limit: 10
})
\`\`\`

Inspect the returned candidates and choose the most relevant subset.

### Step 3 — Create the install proposal

Call:

\`\`\`
security.core.propose_action({
  action_type: "rule_install",
  summary: "<short title>",
  reason: "<one sentence on why these rules are relevant>",
  rules: [
    { rule_id: "<prebuilt rule signature id>", version: <version>, why: "<short per-rule note>" }
  ]
})
\`\`\`

Only include rules you can justify. If the candidates are weak or obviously unrelated, explain that and stop instead of forcing a proposal.

### Step 4 — Render and stop

Render the returned attachment inline with \`<render_attachment id="<returned attachment id>" />\`.

After rendering the attachment, keep the reply very short:
- 1-2 short sentences only
- explain the overall theme of the selected rules at a high level
- tell the user that clicking **Approve** will install them

Do **NOT** repeat the selected rules as a markdown table, bullet list, or second detailed summary after rendering the attachment. The attachment is the canonical detailed view.`;
