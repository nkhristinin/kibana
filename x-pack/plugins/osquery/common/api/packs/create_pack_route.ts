/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import * as t from 'io-ts';
import { toNumberRt } from '@kbn/io-ts-utils';

export const createPackRequestBodySchema = t.type({
  name: t.string,
  description: t.union([t.string, t.undefined]),
  enabled: t.union([t.boolean, t.undefined]),
  policy_ids: t.union([t.array(t.string), t.undefined]),
  shards: t.record(t.string, toNumberRt),
  queries: t.record(
    t.string,
    t.type({
      query: t.string,
      interval: t.union([toNumberRt, t.undefined]),
      snapshot: t.union([t.boolean, t.undefined]),
      removed: t.union([t.boolean, t.undefined]),
      platform: t.union([t.string, t.undefined]),
      version: t.union([t.string, t.undefined]),
      ecs_mapping: t.union([
        t.record(
          t.string,
          t.type({
            field: t.union([t.string, t.undefined]),
            value: t.union([t.string, t.array(t.string), t.undefined]),
          })
        ),
        t.undefined,
      ]),
    })
  ),
});

export type CreatePackRequestBodySchema = t.OutputOf<typeof createPackRequestBodySchema>;
