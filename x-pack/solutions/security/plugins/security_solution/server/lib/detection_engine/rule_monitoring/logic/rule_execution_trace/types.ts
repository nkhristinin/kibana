/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export interface RuleExecutionTraceLogDoc {
  '@timestamp': string;
  doc_kind: 'log';

  rule_id: string;
  execution_id: string;

  ts: string;
  seq: number;

  level: string;
  logger: string;

  message_text: string;
  message?: unknown;
}


