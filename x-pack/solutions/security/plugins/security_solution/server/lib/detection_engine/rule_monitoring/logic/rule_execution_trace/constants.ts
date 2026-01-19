/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const RULE_EXECUTION_TRACE_DATA_STREAM_PREFIX = '.kibana_security_rule_exec_trace';

export const RULE_EXECUTION_TRACE_COMPONENT_TEMPLATE_NAME = `${RULE_EXECUTION_TRACE_DATA_STREAM_PREFIX}-component-template`;
export const RULE_EXECUTION_TRACE_INDEX_TEMPLATE_NAME = `${RULE_EXECUTION_TRACE_DATA_STREAM_PREFIX}-index-template`;

export const RULE_EXECUTION_TRACE_TOTAL_FIELDS_LIMIT = 1000;

/**
 * Default retention for trace data using Data Stream Lifecycle (DSL).
 * DSL works in both serverless and traditional ES deployments.
 */
export const RULE_EXECUTION_TRACE_DEFAULT_RETENTION = '12h';
