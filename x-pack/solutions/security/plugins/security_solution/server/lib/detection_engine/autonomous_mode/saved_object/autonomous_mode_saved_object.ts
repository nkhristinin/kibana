/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SavedObjectsClientContract, SavedObjectsType } from '@kbn/core/server';
import type { SavedObjectsFullModelVersion } from '@kbn/core-saved-objects-server';
import { SECURITY_SOLUTION_SAVED_OBJECT_INDEX } from '@kbn/core-saved-objects-server';
import { schema } from '@kbn/config-schema';

export const AUTONOMOUS_MODE_SO_TYPE = 'siem-autonomous-mode';
export const AUTONOMOUS_MODE_SO_ID = 'autonomous-mode-settings';

export type AutonomousMode = 'auto' | 'suggest';

export interface AutonomousModeSavedObjectAttributes {
  mode: AutonomousMode;
  monitoredWorkflowIds: string[];
}

const AttributesSchemaV1 = schema.object({
  mode: schema.oneOf([schema.literal('auto'), schema.literal('suggest')]),
});

const AttributesSchemaV2 = schema.object({
  mode: schema.oneOf([schema.literal('auto'), schema.literal('suggest')]),
  monitoredWorkflowIds: schema.arrayOf(schema.string(), { defaultValue: [] }),
});

const version1: SavedObjectsFullModelVersion = {
  changes: [],
  schemas: {
    forwardCompatibility: AttributesSchemaV1.extends({}, { unknowns: 'ignore' }),
    create: AttributesSchemaV1,
  },
};

const version2: SavedObjectsFullModelVersion = {
  changes: [
    {
      type: 'mappings_addition',
      addedMappings: {
        monitoredWorkflowIds: { type: 'keyword' },
      },
    },
  ],
  schemas: {
    forwardCompatibility: AttributesSchemaV2.extends({}, { unknowns: 'ignore' }),
    create: AttributesSchemaV2,
  },
};

export const autonomousModeSavedObjectType: SavedObjectsType = {
  name: AUTONOMOUS_MODE_SO_TYPE,
  indexPattern: SECURITY_SOLUTION_SAVED_OBJECT_INDEX,
  hidden: false,
  namespaceType: 'single',
  mappings: {
    properties: {
      mode: { type: 'keyword' },
      monitoredWorkflowIds: { type: 'keyword' },
    },
  },
  modelVersions: { 1: version1, 2: version2 },
};

const DEFAULTS: AutonomousModeSavedObjectAttributes = {
  mode: 'suggest',
  monitoredWorkflowIds: [],
};

export const getAutonomousModeSettings = async (
  soClient: SavedObjectsClientContract
): Promise<AutonomousModeSavedObjectAttributes> => {
  try {
    const so = await soClient.get<AutonomousModeSavedObjectAttributes>(
      AUTONOMOUS_MODE_SO_TYPE,
      AUTONOMOUS_MODE_SO_ID
    );
    return {
      mode: so.attributes.mode ?? DEFAULTS.mode,
      monitoredWorkflowIds: so.attributes.monitoredWorkflowIds ?? [],
    };
  } catch (err) {
    if (err?.output?.statusCode === 404) return DEFAULTS;
    throw err;
  }
};

export const setAutonomousModeSettings = async (
  soClient: SavedObjectsClientContract,
  next: Partial<AutonomousModeSavedObjectAttributes>
): Promise<AutonomousModeSavedObjectAttributes> => {
  const current = await getAutonomousModeSettings(soClient);
  const merged: AutonomousModeSavedObjectAttributes = {
    mode: next.mode ?? current.mode,
    monitoredWorkflowIds: next.monitoredWorkflowIds ?? current.monitoredWorkflowIds,
  };
  await soClient.create<AutonomousModeSavedObjectAttributes>(
    AUTONOMOUS_MODE_SO_TYPE,
    merged,
    { id: AUTONOMOUS_MODE_SO_ID, overwrite: true }
  );
  return merged;
};

// Backwards-compat helper used by the workflow step
export const getAutonomousMode = async (
  soClient: SavedObjectsClientContract
): Promise<AutonomousMode> => {
  const s = await getAutonomousModeSettings(soClient);
  return s.mode;
};
