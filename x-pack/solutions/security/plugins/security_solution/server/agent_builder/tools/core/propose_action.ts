/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import { ToolType } from '@kbn/agent-builder-common';
import { getLatestVersion } from '@kbn/agent-builder-common/attachments';
import { ToolResultType } from '@kbn/agent-builder-common/tools/tool_result';
import type { BuiltinToolDefinition } from '@kbn/agent-builder-server';
import type { Logger } from '@kbn/logging';
import { CreateRuleExceptionListItemProps } from '@kbn/securitysolution-exceptions-common/api';
import {
  actionProposalDataSchema,
  actionProposalMetricsSchema,
  ruleChangeIntentSchema,
  type ActionProposalData,
} from '../../../../common/agent_builder/action_recommendation';
import { PatchRuleRequestBody } from '../../../../common/api/detection_engine/rule_management/crud/patch_rule/patch_rule_route.gen';
import { validatePatchRuleRequestBody } from '../../../../common/api/detection_engine/rule_management/crud/patch_rule/request_schema_validation';
import { SecurityAgentBuilderAttachments } from '../../../../common/constants';
import { convertAlertingRuleToRuleResponse } from '../../../lib/detection_engine/rule_management/logic/detection_rules_client/converters/convert_alerting_rule_to_rule_response';
import { convertPrebuiltRuleAssetToRuleResponse } from '../../../lib/detection_engine/rule_management/logic/detection_rules_client/converters/convert_prebuilt_rule_asset_to_rule_response';
import { readRules } from '../../../lib/detection_engine/rule_management/logic/detection_rules_client/read_rules';
import { createPrebuiltRuleAssetsClient } from '../../../lib/detection_engine/prebuilt_rules/logic/rule_assets/prebuilt_rule_assets_client';
import { securityTool } from '../constants';
import { getAgentBuilderResourceAvailability } from '../../utils/get_agent_builder_resource_availability';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../../plugin_contract';

export const SECURITY_PROPOSE_ACTION_TOOL_ID = securityTool('core.propose_action');

const installRuleSelectionSchema = z.object({
  rule_id: z.string().describe('Prebuilt rule signature id.'),
  version: z
    .number()
    .int()
    .positive()
    .optional()
    .describe('Specific prebuilt rule version to install. Defaults to latest if omitted.'),
  why: z.string().optional().describe('Optional short per-rule note shown in the proposal table.'),
});

const commonActionSchema = z.object({
  summary: z
    .string()
    .min(1)
    .describe('Short user-facing summary shown in the proposal attachment header.'),
  reason: z
    .string()
    .optional()
    .describe('Optional one or two sentence explanation of why this action is being proposed.'),
  metrics: actionProposalMetricsSchema.describe(
    'Optional metrics badges to render with the proposal.'
  ),
});

const proposeActionSchema = commonActionSchema.extend({
  action_type: z
    .enum(['rule_change', 'rule_exception_add', 'rule_install'])
    .describe('The kind of action proposal to create.'),
  rule_id: z.string().optional().describe('Saved-object id of the live rule to change.'),
  proposed_changes: z
    .record(z.string(), z.unknown())
    .optional()
    .describe('Patch object containing the rule fields to change.'),
  items: z
    .array(CreateRuleExceptionListItemProps)
    .min(1)
    .optional()
    .describe('Exception items to add to the rule default exception list.'),
  intent: ruleChangeIntentSchema
    .optional()
    .describe('Optional hint describing why this rule change is being proposed.'),
  rules: z
    .array(installRuleSelectionSchema)
    .min(1)
    .max(20)
    .optional()
    .describe('Rules to include in a rule_install proposal.'),
});

type ProposeAction = z.infer<typeof proposeActionSchema>;

type RuleChangeAction = ProposeAction & {
  action_type: 'rule_change';
  rule_id: string;
  proposed_changes: Record<string, unknown>;
};
type RuleExceptionAddAction = ProposeAction & {
  action_type: 'rule_exception_add';
  rule_id: string;
  items: Array<z.infer<typeof CreateRuleExceptionListItemProps>>;
};
type InstallAction = ProposeAction & {
  action_type: 'rule_install';
  rules: Array<z.infer<typeof installRuleSelectionSchema>>;
};

type RuleScopedActionType = 'rule_change' | 'rule_exception_add';

interface PendingRuleProposal {
  attachmentId: string;
  createdAt: string;
  data: ActionProposalData;
}

const mergePatchValue = (base: unknown, patch: unknown): unknown => {
  if (
    base &&
    typeof base === 'object' &&
    !Array.isArray(base) &&
    patch &&
    typeof patch === 'object' &&
    !Array.isArray(patch)
  ) {
    const baseObject = base as Record<string, unknown>;
    return Object.keys(patch as Record<string, unknown>).reduce<Record<string, unknown>>(
      (acc, key) => {
        acc[key] = mergePatchValue(baseObject[key], (patch as Record<string, unknown>)[key]);
        return acc;
      },
      { ...baseObject }
    );
  }

  return patch;
};

const mergeActionMetrics = (
  existing: z.infer<typeof actionProposalMetricsSchema>,
  incoming: z.infer<typeof actionProposalMetricsSchema>
) => {
  if (!existing && !incoming) {
    return undefined;
  }

  return {
    ...(existing ?? {}),
    ...(incoming ?? {}),
  };
};

const toRuleChangeAction = (action: ProposeAction): RuleChangeAction => {
  if (action.action_type !== 'rule_change' || !action.rule_id || !action.proposed_changes) {
    throw new Error('`rule_change` proposals require `rule_id` and `proposed_changes`.');
  }

  if (Object.keys(action.proposed_changes).length === 0) {
    throw new Error(
      '`rule_change` proposals must include at least one field in `proposed_changes`.'
    );
  }

  if ('id' in action.proposed_changes || 'rule_id' in action.proposed_changes) {
    throw new Error(
      '`proposed_changes` must not contain `id` or `rule_id`; pass the rule id separately.'
    );
  }

  const patchPayload = {
    id: action.rule_id,
    ...action.proposed_changes,
  };
  const parseResult = PatchRuleRequestBody.safeParse(patchPayload);
  if (!parseResult.success) {
    throw new Error(`Invalid rule change payload: ${parseResult.error.message}`);
  }

  const validationErrors = validatePatchRuleRequestBody(parseResult.data);
  if (validationErrors.length > 0) {
    throw new Error(`Invalid rule change payload: ${validationErrors.join('; ')}`);
  }

  return action as RuleChangeAction;
};

const toInstallAction = (action: ProposeAction): InstallAction => {
  if (action.action_type !== 'rule_install' || !action.rules?.length) {
    throw new Error('`rule_install` proposals require at least one entry in `rules`.');
  }

  return action as InstallAction;
};

const toRuleExceptionAddAction = (action: ProposeAction): RuleExceptionAddAction => {
  if (action.action_type !== 'rule_exception_add' || !action.rule_id || !action.items?.length) {
    throw new Error('`rule_exception_add` proposals require `rule_id` and at least one item.');
  }

  return action as RuleExceptionAddAction;
};

const getCurrentRule = async ({
  core,
  request,
  ruleId,
}: {
  core: SecuritySolutionPluginCoreSetupDependencies;
  request: Parameters<
    NonNullable<BuiltinToolDefinition<typeof proposeActionSchema>['handler']>
  >[1]['request'];
  ruleId: string;
}) => {
  const [, startPlugins] = await core.getStartServices();
  const rulesClient = await startPlugins.alerting.getRulesClientWithRequest(request);
  const rule = await readRules({ rulesClient, id: ruleId, ruleId: undefined });

  if (!rule) {
    throw new Error(`Rule not found: ${ruleId}`);
  }

  return convertAlertingRuleToRuleResponse(rule);
};

const resolveInstallRules = async ({
  core,
  request,
  rules,
}: {
  core: SecuritySolutionPluginCoreSetupDependencies;
  request: Parameters<
    NonNullable<BuiltinToolDefinition<typeof proposeActionSchema>['handler']>
  >[1]['request'];
  rules: Array<{ rule_id: string; version?: number; why?: string }>;
}) => {
  const [coreStart] = await core.getStartServices();
  const soClient = coreStart.savedObjects.getScopedClient(request);
  const ruleAssetsClient = createPrebuiltRuleAssetsClient(soClient);

  const requestedRuleIds = rules.map(({ rule_id: ruleId }) => ruleId);
  const latestVersions = await ruleAssetsClient.fetchLatestVersions({ ruleIds: requestedRuleIds });
  const latestVersionMap = new Map(latestVersions.map((version) => [version.rule_id, version]));

  const versionsToFetch = rules.map((rule) => {
    if (rule.version != null) {
      return { rule_id: rule.rule_id, version: rule.version };
    }

    const latest = latestVersionMap.get(rule.rule_id);
    if (!latest) {
      throw new Error(`Unable to find installable prebuilt rule: ${rule.rule_id}`);
    }

    return latest;
  });

  const requestedWhyMap = new Map(rules.map((rule) => [rule.rule_id, rule.why]));
  const assets = await ruleAssetsClient.fetchAssetsByVersion(versionsToFetch);
  const assetMap = new Map(assets.map((asset) => [asset.rule_id, asset]));

  return versionsToFetch.map(({ rule_id: ruleId, version }) => {
    const asset = assetMap.get(ruleId);
    if (!asset) {
      throw new Error(`Unable to load prebuilt rule asset: ${ruleId}`);
    }

    const rule = convertPrebuiltRuleAssetToRuleResponse(asset);
    return {
      rule_id: ruleId,
      version,
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      mitre: rule.threat?.map((threat) => threat.tactic.name),
      why: requestedWhyMap.get(ruleId),
    };
  });
};

const findPendingRuleProposal = ({
  attachments,
  actionType,
  ruleId,
}: {
  attachments: Parameters<
    NonNullable<BuiltinToolDefinition<typeof proposeActionSchema>['handler']>
  >[1]['attachments'];
  actionType: RuleScopedActionType;
  ruleId: string;
}): PendingRuleProposal | undefined => {
  return attachments.getActive().reduce<PendingRuleProposal | undefined>((latest, attachment) => {
    if (attachment.type !== SecurityAgentBuilderAttachments.actionProposal) {
      return latest;
    }

    const latestVersion = getLatestVersion(attachment);
    if (!latestVersion) {
      return latest;
    }

    const parseResult = actionProposalDataSchema.safeParse(latestVersion.data);
    if (!parseResult.success) {
      return latest;
    }

    const data = parseResult.data;
    if (
      data.status !== 'pending' ||
      data.payload.action_type !== actionType ||
      data.payload.rule_id !== ruleId
    ) {
      return latest;
    }

    if (!latest) {
      return {
        attachmentId: attachment.id,
        createdAt: latestVersion.created_at,
        data,
      };
    }

    return latest.createdAt > latestVersion.created_at
      ? latest
      : {
          attachmentId: attachment.id,
          createdAt: latestVersion.created_at,
          data,
        };
  }, undefined);
};

const buildRuleChangeAttachmentData = ({
  action,
  currentRule,
  existingProposal,
}: {
  action: RuleChangeAction;
  currentRule: Awaited<ReturnType<typeof getCurrentRule>>;
  existingProposal?: ActionProposalData;
}) => {
  const existingRuleChangePayload =
    existingProposal?.payload.action_type === 'rule_change' ? existingProposal.payload : undefined;
  const reason = action.reason ?? existingProposal?.reason;
  const metrics = mergeActionMetrics(existingProposal?.metrics, action.metrics);
  const intent = action.intent ?? existingRuleChangePayload?.intent;

  return {
    status: 'pending' as const,
    summary: action.summary,
    ...(reason && { reason }),
    ...(metrics && { metrics }),
    payload: {
      action_type: 'rule_change' as const,
      rule_id: action.rule_id,
      current: currentRule,
      proposed_changes: action.proposed_changes,
      changed_fields: Object.keys(action.proposed_changes),
      ...(intent && { intent }),
    },
  };
};

const buildRuleExceptionAddAttachmentData = ({
  action,
  currentRule,
  existingProposal,
}: {
  action: RuleExceptionAddAction;
  currentRule: Awaited<ReturnType<typeof getCurrentRule>>;
  existingProposal?: ActionProposalData;
}) => {
  const reason = action.reason ?? existingProposal?.reason;
  const metrics = mergeActionMetrics(existingProposal?.metrics, action.metrics);

  return {
    status: 'pending' as const,
    summary: action.summary,
    ...(reason && { reason }),
    ...(metrics && { metrics }),
    payload: {
      action_type: 'rule_exception_add' as const,
      rule_id: action.rule_id,
      rule_name: currentRule.name,
      items: action.items,
    },
  };
};

const buildAttachmentData = async ({
  action,
  core,
  request,
}: {
  action: ProposeAction;
  core: SecuritySolutionPluginCoreSetupDependencies;
  request: Parameters<
    NonNullable<BuiltinToolDefinition<typeof proposeActionSchema>['handler']>
  >[1]['request'];
}) => {
  switch (action.action_type) {
    case 'rule_change': {
      const ruleChangeAction = toRuleChangeAction(action);
      const currentRule = await getCurrentRule({
        core,
        request,
        ruleId: ruleChangeAction.rule_id,
      });
      return buildRuleChangeAttachmentData({
        action: ruleChangeAction,
        currentRule,
      });
    }
    case 'rule_exception_add': {
      const ruleExceptionAction = toRuleExceptionAddAction(action);
      const currentRule = await getCurrentRule({
        core,
        request,
        ruleId: ruleExceptionAction.rule_id,
      });
      return buildRuleExceptionAddAttachmentData({
        action: ruleExceptionAction,
        currentRule,
      });
    }
    case 'rule_install': {
      const installAction = toInstallAction(action);
      const installRules = await resolveInstallRules({
        core,
        request,
        rules: installAction.rules,
      });
      return {
        status: 'pending' as const,
        summary: installAction.summary,
        reason: installAction.reason,
        metrics: installAction.metrics,
        payload: {
          action_type: 'rule_install' as const,
          rules: installRules,
        },
      };
    }
  }
};

const createOrUpdateProposalAttachment = async ({
  action,
  attachments,
  core,
  request,
}: {
  action: ProposeAction;
  attachments: Parameters<
    NonNullable<BuiltinToolDefinition<typeof proposeActionSchema>['handler']>
  >[1]['attachments'];
  core: SecuritySolutionPluginCoreSetupDependencies;
  request: Parameters<
    NonNullable<BuiltinToolDefinition<typeof proposeActionSchema>['handler']>
  >[1]['request'];
}) => {
  if (action.action_type === 'rule_change') {
    const ruleChangeAction = toRuleChangeAction(action);
    const existingProposal = findPendingRuleProposal({
      attachments,
      actionType: 'rule_change',
      ruleId: ruleChangeAction.rule_id,
    });

    const mergedRuleChangeAction = existingProposal
      ? toRuleChangeAction({
          ...ruleChangeAction,
          proposed_changes: mergePatchValue(
            existingProposal.data.payload.action_type === 'rule_change'
              ? existingProposal.data.payload.proposed_changes
              : {},
            ruleChangeAction.proposed_changes
          ) as Record<string, unknown>,
        })
      : ruleChangeAction;

    const currentRule = await getCurrentRule({
      core,
      request,
      ruleId: mergedRuleChangeAction.rule_id,
    });
    const data = buildRuleChangeAttachmentData({
      action: mergedRuleChangeAction,
      currentRule,
      existingProposal: existingProposal?.data,
    });

    if (!existingProposal) {
      return attachments.add({
        type: SecurityAgentBuilderAttachments.actionProposal,
        data,
        description: data.summary,
      });
    }

    const updated = await attachments.update(existingProposal.attachmentId, {
      data,
      description: data.summary,
    });

    if (!updated) {
      throw new Error(
        `Failed to update action proposal attachment: ${existingProposal.attachmentId}`
      );
    }

    return updated;
  }

  if (action.action_type === 'rule_exception_add') {
    const ruleExceptionAction = toRuleExceptionAddAction(action);
    const existingProposal = findPendingRuleProposal({
      attachments,
      actionType: 'rule_exception_add',
      ruleId: ruleExceptionAction.rule_id,
    });

    const mergedRuleExceptionAction = toRuleExceptionAddAction({
      ...ruleExceptionAction,
      items:
        existingProposal?.data.payload.action_type === 'rule_exception_add'
          ? [...existingProposal.data.payload.items, ...ruleExceptionAction.items]
          : ruleExceptionAction.items,
    });

    const currentRule = await getCurrentRule({
      core,
      request,
      ruleId: mergedRuleExceptionAction.rule_id,
    });
    const data = buildRuleExceptionAddAttachmentData({
      action: mergedRuleExceptionAction,
      currentRule,
      existingProposal: existingProposal?.data,
    });

    if (!existingProposal) {
      return attachments.add({
        type: SecurityAgentBuilderAttachments.actionProposal,
        data,
        description: data.summary,
      });
    }

    const updated = await attachments.update(existingProposal.attachmentId, {
      data,
      description: data.summary,
    });

    if (!updated) {
      throw new Error(
        `Failed to update action proposal attachment: ${existingProposal.attachmentId}`
      );
    }

    return updated;
  }

  {
    const data = await buildAttachmentData({ action, core, request });
    return attachments.add({
      type: SecurityAgentBuilderAttachments.actionProposal,
      data,
      description: action.summary,
    });
  }
};

export const proposeActionTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof proposeActionSchema> => ({
  id: SECURITY_PROPOSE_ACTION_TOOL_ID,
  type: ToolType.builtin,
  description:
    'Create or update a typed security.action_proposal attachment for an intended live action. Use this after reasoning through the problem; it builds the proposal payload server-side so skills do not need to handcraft attachment JSON. For rule changes and rule-exception additions, a pending proposal with the same action type for the same rule is updated instead of creating a second card.',
  schema: proposeActionSchema,
  tags: ['security', 'proposal', 'rule', 'prebuilt-rules'],
  availability: {
    cacheMode: 'space',
    handler: async ({ request }) => getAgentBuilderResourceAvailability({ core, request, logger }),
  },
  handler: async (action, { attachments, request }) => {
    try {
      const created = await createOrUpdateProposalAttachment({
        action,
        attachments,
        core,
        request,
      });

      return {
        results: [
          {
            type: ToolResultType.other,
            data: {
              success: true,
              attachmentId: created.id,
              version: created.current_version,
              action_type: action.action_type,
            },
          },
        ],
      };
    } catch (error) {
      logger.error(`propose_action failed: ${error.message}`, error);
      return {
        results: [
          {
            type: ToolResultType.error,
            data: {
              message: `Failed to create action proposal: ${error.message}`,
            },
          },
        ],
      };
    }
  },
});
