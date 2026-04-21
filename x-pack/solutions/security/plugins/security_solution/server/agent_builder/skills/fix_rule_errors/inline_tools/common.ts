/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const MINIMUM_FAILURE_THRESHOLD = 3;

export const ERROR_CATEGORIES = [
  'index_pattern',
  'query_syntax',
  'field_mapping',
  'too_many_results',
  'ml_job',
  'system_error',
  'unknown',
] as const;

export type ErrorCategory = (typeof ERROR_CATEGORIES)[number];

/**
 * Classify an error message into a fixable category based on known patterns.
 */
export const classifyError = (errorMessage: string): ErrorCategory => {
  const msg = errorMessage.toLowerCase();

  if (
    msg.includes('index_not_found') ||
    msg.includes('no such index') ||
    msg.includes('data view') ||
    msg.includes('index pattern')
  ) {
    return 'index_pattern';
  }

  if (
    msg.includes('parsing_exception') ||
    msg.includes('parse_exception') ||
    msg.includes('x_content_parse') ||
    msg.includes('failed to parse') ||
    msg.includes('syntax error')
  ) {
    return 'query_syntax';
  }

  if (
    msg.includes('verification_exception') ||
    msg.includes('unknown column') ||
    msg.includes('unknown field') ||
    msg.includes('no mapping found') ||
    msg.includes('type mismatch')
  ) {
    return 'field_mapping';
  }

  if (
    msg.includes('too many buckets') ||
    msg.includes('max_signals') ||
    msg.includes('circuit_breaking') ||
    msg.includes('too many results')
  ) {
    return 'too_many_results';
  }

  if (
    msg.includes('missing') && msg.includes('ml') ||
    msg.includes('machine_learning') ||
    msg.includes('anomaly') ||
    msg.includes('ml job')
  ) {
    return 'ml_job';
  }

  if (
    msg.includes('timeout') ||
    msg.includes('shard') ||
    msg.includes('circuit_breaking') ||
    msg.includes('gap')
  ) {
    return 'system_error';
  }

  return 'unknown';
};

export const FIXABLE_CATEGORIES: ErrorCategory[] = [
  'index_pattern',
  'query_syntax',
  'field_mapping',
  'too_many_results',
  'ml_job',
];

export const isFixableError = (category: ErrorCategory): boolean =>
  FIXABLE_CATEGORIES.includes(category);
