/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from '@kbn/zod/v4';
import { ToolType, ToolResultType } from '@kbn/agent-builder-common';
import type { BuiltinToolDefinition } from '@kbn/agent-builder-server';
import type { Logger } from '@kbn/logging';
import { getAgentBuilderResourceAvailability } from '../utils/get_agent_builder_resource_availability';
import type { SecuritySolutionPluginCoreSetupDependencies } from '../../plugin_contract';
import { securityTool } from './constants';

export const SECURITY_COVERAGE_OVERVIEW_TOOL_ID = securityTool('coverage_overview');

const coverageOverviewSchema = z.object({
  activity: z
    .enum(['enabled', 'disabled'])
    .optional()
    .describe('Filter to only enabled or only disabled rules'),
  source: z
    .enum(['prebuilt', 'custom'])
    .optional()
    .describe('Filter by rule source: prebuilt (Elastic) or custom'),
});

interface ThreatEntry {
  framework: string;
  tactic: { id: string; name: string; reference?: string };
  technique?: Array<{
    id: string;
    name: string;
    reference?: string;
    subtechnique?: Array<{ id: string; name: string; reference?: string }>;
  }>;
}

interface TechniqueInfo {
  technique_name: string;
  enabled_rules: number;
  disabled_rules: number;
  subtechniques: Map<string, { name: string; enabled: number; disabled: number }>;
}

interface TacticInfo {
  tactic_name: string;
  techniques: Map<string, TechniqueInfo>;
}

const SIEM_RULE_FILTER = 'alert.attributes.consumer: "siem"';

export const coverageOverviewTool = (
  core: SecuritySolutionPluginCoreSetupDependencies,
  logger: Logger
): BuiltinToolDefinition<typeof coverageOverviewSchema> => {
  return {
    id: SECURITY_COVERAGE_OVERVIEW_TOOL_ID,
    type: ToolType.builtin,
    description:
      'Get MITRE ATT&CK coverage overview showing which tactics and techniques are covered by detection rules. Returns technique counts per tactic and a coverage summary. Use to answer "what techniques are we covering?", "where are our detection gaps?", "how is our MITRE coverage?".',
    schema: coverageOverviewSchema,
    tags: ['security', 'detection', 'rules', 'mitre', 'coverage'],
    availability: {
      cacheMode: 'space',
      handler: async ({ request }) => {
        return getAgentBuilderResourceAvailability({ core, request, logger });
      },
    },
    handler: async (params, { request }) => {
      try {
        const [, startPlugins] = await core.getStartServices();
        const rulesClient = await startPlugins.alerting.getRulesClientWithRequest(request);

        const filters: string[] = [SIEM_RULE_FILTER];
        if (params.activity === 'enabled') {
          filters.push('alert.attributes.enabled: true');
        } else if (params.activity === 'disabled') {
          filters.push('alert.attributes.enabled: false');
        }
        if (params.source === 'prebuilt') {
          filters.push('alert.attributes.params.immutable: true');
        } else if (params.source === 'custom') {
          filters.push('alert.attributes.params.immutable: false');
        }

        const tacticMap = new Map<string, TacticInfo>();
        let totalRules = 0;
        let rulesWithThreat = 0;
        let page = 1;
        const perPage = 1000;

        // Paginate through all rules to build the coverage map
        while (true) {
          const result = await rulesClient.find({
            options: {
              filter: filters.join(' AND '),
              perPage,
              page,
              sortField: 'name',
              sortOrder: 'asc',
            },
            excludeFromPublicApi: false,
          });

          for (const rule of result.data) {
            totalRules++;
            const ruleParams = rule.params as Record<string, unknown>;
            const threat = ruleParams.threat as ThreatEntry[] | undefined;
            if (!threat?.length) continue;

            rulesWithThreat++;
            const isEnabled = rule.enabled;

            for (const entry of threat) {
              if (entry.framework !== 'MITRE ATT&CK' || !entry.tactic) continue;

              const tacticId = entry.tactic.id;
              if (!tacticMap.has(tacticId)) {
                tacticMap.set(tacticId, {
                  tactic_name: entry.tactic.name,
                  techniques: new Map(),
                });
              }
              const tacticInfo = tacticMap.get(tacticId)!;

              for (const technique of entry.technique ?? []) {
                if (!tacticInfo.techniques.has(technique.id)) {
                  tacticInfo.techniques.set(technique.id, {
                    technique_name: technique.name,
                    enabled_rules: 0,
                    disabled_rules: 0,
                    subtechniques: new Map(),
                  });
                }
                const techInfo = tacticInfo.techniques.get(technique.id)!;
                if (isEnabled) {
                  techInfo.enabled_rules++;
                } else {
                  techInfo.disabled_rules++;
                }

                for (const sub of technique.subtechnique ?? []) {
                  if (!techInfo.subtechniques.has(sub.id)) {
                    techInfo.subtechniques.set(sub.id, {
                      name: sub.name,
                      enabled: 0,
                      disabled: 0,
                    });
                  }
                  const subInfo = techInfo.subtechniques.get(sub.id)!;
                  if (isEnabled) {
                    subInfo.enabled++;
                  } else {
                    subInfo.disabled++;
                  }
                }
              }
            }
          }

          if (result.data.length < perPage) break;
          page++;
        }

        let totalTechniquesCovered = 0;
        const coverage = Array.from(tacticMap.entries()).map(([tacticId, tacticInfo]) => {
          const techniques = Array.from(tacticInfo.techniques.entries()).map(
            ([techId, techInfo]) => {
              totalTechniquesCovered++;
              const subtechniques = Array.from(techInfo.subtechniques.entries()).map(
                ([subId, subInfo]) => ({
                  id: subId,
                  name: subInfo.name,
                  enabled_rules: subInfo.enabled,
                  disabled_rules: subInfo.disabled,
                })
              );

              return {
                id: techId,
                name: techInfo.technique_name,
                enabled_rules: techInfo.enabled_rules,
                disabled_rules: techInfo.disabled_rules,
                total_rules: techInfo.enabled_rules + techInfo.disabled_rules,
                ...(subtechniques.length > 0 ? { subtechniques } : {}),
              };
            }
          );

          return {
            tactic_id: tacticId,
            tactic_name: tacticInfo.tactic_name,
            techniques_covered: techniques.length,
            techniques,
          };
        });

        return {
          results: [
            {
              type: ToolResultType.other,
              data: {
                summary: {
                  total_rules: totalRules,
                  rules_with_mitre_mapping: rulesWithThreat,
                  total_tactics_covered: coverage.length,
                  total_techniques_covered: totalTechniquesCovered,
                },
                coverage,
              },
            },
          ],
        };
      } catch (error) {
        logger.error(`coverage_overview tool failed: ${error.message}`);
        return {
          results: [
            {
              type: ToolResultType.error,
              data: { message: `Failed to get coverage overview: ${error.message}` },
            },
          ],
        };
      }
    },
  };
};
