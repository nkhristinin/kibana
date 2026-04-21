/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { CoreSetup, CoreStart } from '@kbn/core/server';
import { createServerStepDefinition } from '@kbn/workflows-extensions/server';
import { DETECTION_ENGINE_RULES_URL } from '../../../common/constants';
import { applyRuleFixStepCommonDefinition } from '../../../common/workflows/steps';

const getServerUrl = (coreStart: CoreStart): string | undefined => {
  const info = coreStart.http.getServerInfo();
  if (!info) return undefined;
  return `${info.protocol}://${info.hostname}:${info.port}`;
};

export const getApplyRuleFixStepDefinition = (getStartServices: CoreSetup['getStartServices']) =>
  createServerStepDefinition({
    ...applyRuleFixStepCommonDefinition,
    handler: async (context) => {
      const { rule_id: ruleId } = context.input;
      const changes = (
        context.input.changes &&
        typeof context.input.changes === 'object' &&
        !Array.isArray(context.input.changes)
          ? (context.input.changes as Record<string, unknown>)
          : {}
      ) as Record<string, unknown>;
      try {
        const [coreStart] = await getStartServices();
        const request = context.contextManager.getFakeRequest();
        const baseUrl =
          coreStart.http.basePath.publicBaseUrl ?? getServerUrl(coreStart) ?? 'http://localhost:5601';
        const serverBasePath = coreStart.http.basePath.serverBasePath;
        const url = `${baseUrl}${serverBasePath}${DETECTION_ENGINE_RULES_URL}`;

        const headers: Record<string, string> = {
          'content-type': 'application/json',
          'kbn-xsrf': 'true',
        };
        const auth = request.headers?.authorization;
        if (typeof auth === 'string') headers.authorization = auth;

        const patchBody = { id: ruleId, ...changes };
        const res = await fetch(url, {
          method: 'PATCH',
          headers,
          body: JSON.stringify(patchBody),
        });

        if (!res.ok) {
          const errText = await res.text();
          throw new Error(`Rule patch failed (HTTP ${res.status}): ${errText}`);
        }

        const updated = (await res.json()) as { name?: string };
        const summary = `Applied fix to rule "${updated.name ?? ruleId}". Fields: ${Object.keys(
          changes
        ).join(', ')}`;

        context.logger.info(summary);

        return {
          output: { rule_id: ruleId, appliedChanges: changes, summary },
        };
      } catch (error) {
        context.logger.error(
          'Failed to apply rule fix',
          error instanceof Error ? error : new Error(String(error))
        );
        return {
          error: new Error(error instanceof Error ? error.message : 'Failed to apply rule fix'),
        };
      }
    },
  });
