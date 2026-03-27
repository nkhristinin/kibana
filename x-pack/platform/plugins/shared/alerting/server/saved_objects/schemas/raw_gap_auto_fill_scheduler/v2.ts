/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';
import type { TypeOf } from '@kbn/config-schema';
import { rawGapAutoFillSchedulerSchemaV1 } from '.';

export const rawGapAutoFillSchedulerSchemaV2 = rawGapAutoFillSchedulerSchemaV1.extends({
  excludedReasons: schema.maybe(schema.arrayOf(schema.string())),
});

export type RawGapAutoFillSchedulerAttributesV2 = TypeOf<typeof rawGapAutoFillSchedulerSchemaV2>;
