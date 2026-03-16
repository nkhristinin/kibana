/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { BuiltInAgentDefinition } from '@kbn/agent-builder-server/agents';
import { platformCoreTools } from '@kbn/agent-builder-common';
import type { Logger } from '@kbn/logging';
import { THREAT_HUNTING_AGENT_ID } from '../../../common/constants';
import {
  SECURITY_ATTACK_DISCOVERY_SEARCH_TOOL_ID,
  SECURITY_LABS_SEARCH_TOOL_ID,
  SECURITY_ALERTS_TOOL_ID,
  SECURITY_ENTITY_RISK_SCORE_TOOL_ID,
  SECURITY_FIND_RULES_TOOL_ID,
  SECURITY_GET_RULE_DETAILS_TOOL_ID,
  SECURITY_RULE_EXECUTION_HISTORY_TOOL_ID,
  SECURITY_RULE_GAPS_TOOL_ID,
  SECURITY_RULES_HEALTH_TOOL_ID,
  SECURITY_COVERAGE_OVERVIEW_TOOL_ID,
  SECURITY_PREBUILT_RULES_STATUS_TOOL_ID,
  SECURITY_EXECUTION_STATS_TOOL_ID,
} from '../tools';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../plugin_contract';
import { getAgentBuilderResourceAvailability } from '../utils/get_agent_builder_resource_availability';

const PLATFORM_TOOL_IDS = [
  platformCoreTools.search,
  platformCoreTools.listIndices,
  platformCoreTools.getIndexMapping,
  platformCoreTools.getDocumentById,
  platformCoreTools.cases,
  platformCoreTools.productDocumentation,
  platformCoreTools.generateEsql,
  platformCoreTools.executeEsql,
];

const SECURITY_TOOL_IDS = [
  SECURITY_ALERTS_TOOL_ID,
  SECURITY_ATTACK_DISCOVERY_SEARCH_TOOL_ID,
  SECURITY_ENTITY_RISK_SCORE_TOOL_ID,
  SECURITY_LABS_SEARCH_TOOL_ID,
  SECURITY_FIND_RULES_TOOL_ID,
  SECURITY_GET_RULE_DETAILS_TOOL_ID,
  SECURITY_RULE_EXECUTION_HISTORY_TOOL_ID,
  SECURITY_RULE_GAPS_TOOL_ID,
  SECURITY_RULES_HEALTH_TOOL_ID,
  SECURITY_COVERAGE_OVERVIEW_TOOL_ID,
  SECURITY_PREBUILT_RULES_STATUS_TOOL_ID,
  SECURITY_EXECUTION_STATS_TOOL_ID,
];

export const THREAT_HUNTING_AGENT_TOOL_IDS = [...PLATFORM_TOOL_IDS, ...SECURITY_TOOL_IDS];

export const createThreatHuntingAgent = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltInAgentDefinition => {
  return {
    id: THREAT_HUNTING_AGENT_ID,
    avatar_icon: 'logoSecurity',
    name: 'Threat Hunting Agent',
    description:
      'Agent specialized in security alert analysis and entity analysis tasks, including alert investigation, entity investigation and security documentation.',
    labels: ['security'],
    availability: {
      cacheMode: 'space',
      handler: async ({ request }) => {
        return getAgentBuilderResourceAvailability({ core, request, logger });
      },
    },
    configuration: {
      instructions: `You are a security analyst and expert in resolving security incidents. Your role is to assist by answering questions about Elastic Security.

For questions about detection rule performance, health, and execution:
- Use find_rules to search/filter/list rules by status, name, tags, or enabled state.
- Use get_rule_details for full configuration of a specific rule.
- Use execution_stats for aggregate execution metrics and to identify which specific rules are most delayed, slowest, or erroring (via top_rules_by); also supports duration percentiles, schedule delay, search/indexing duration, top errors/warnings, and time-series trends.
- Use rules_health for a summary of rule counts by outcome, execution KPIs, and gap overview.
- Use rule_execution_history for per-rule execution log entries.
- Use rule_gaps for coverage gap details.
- Use coverage_overview for MITRE ATT&CK technique coverage.
- Use prebuilt_rules_status for installed prebuilt rule counts.`,
      tools: [
        {
          tool_ids: THREAT_HUNTING_AGENT_TOOL_IDS,
        },
      ],
    },
  };
};
