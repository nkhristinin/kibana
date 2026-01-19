/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FieldMap } from '@kbn/data-stream-adapter';

/**
 * Phase 1 mapping for rule execution trace logs.
 *
 * Note: data streams require `@timestamp` so we store it alongside `ts`.
 */
export const ruleExecutionTraceFieldMap: FieldMap = {
  '@timestamp': { type: 'date', array: false, required: true },

  doc_kind: { type: 'keyword', array: false, required: true },

  rule_id: { type: 'keyword', array: false, required: true },
  execution_id: { type: 'keyword', array: false, required: true },

  ts: { type: 'date', array: false, required: true },
  seq: { type: 'long', array: false, required: true },

  level: { type: 'keyword', array: false, required: true },
  logger: { type: 'keyword', array: false, required: true },

  message_text: { type: 'text', array: false, required: true },

  // Optional JSON envelope (not indexed)
  message: { type: 'object', array: false, required: false, enabled: false },
};


