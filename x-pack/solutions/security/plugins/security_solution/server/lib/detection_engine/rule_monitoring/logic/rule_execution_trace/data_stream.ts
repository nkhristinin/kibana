/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { DataStreamSpacesAdapter } from '@kbn/data-stream-adapter';

import {
  RULE_EXECUTION_TRACE_COMPONENT_TEMPLATE_NAME,
  RULE_EXECUTION_TRACE_DATA_STREAM_PREFIX,
  RULE_EXECUTION_TRACE_INDEX_TEMPLATE_NAME,
  RULE_EXECUTION_TRACE_TOTAL_FIELDS_LIMIT,
  RULE_EXECUTION_TRACE_DEFAULT_RETENTION,
} from './constants';
import { ruleExecutionTraceFieldMap } from './field_map';

/**
 * Creates the data stream adapter for rule execution trace logs.
 *
 * Uses Data Stream Lifecycle (DSL) for retention management, which works
 * in both serverless and traditional Elasticsearch deployments.
 */
export const createRuleExecutionTraceDatastream = ({
  retention = RULE_EXECUTION_TRACE_DEFAULT_RETENTION,
}: {
  retention?: string;
} = {}): DataStreamSpacesAdapter => {
  const ds = new DataStreamSpacesAdapter(RULE_EXECUTION_TRACE_DATA_STREAM_PREFIX, {
    kibanaVersion: '1.0.0', // Version tracking not needed for trace data
    totalFieldsLimit: RULE_EXECUTION_TRACE_TOTAL_FIELDS_LIMIT,
  });

  ds.setComponentTemplate({
    name: RULE_EXECUTION_TRACE_COMPONENT_TEMPLATE_NAME,
    fieldMap: ruleExecutionTraceFieldMap,
    // Align with the index template's `dynamic:false`.
    dynamic: false,
  });

  ds.setIndexTemplate({
    name: RULE_EXECUTION_TRACE_INDEX_TEMPLATE_NAME,
    componentTemplateRefs: [RULE_EXECUTION_TRACE_COMPONENT_TEMPLATE_NAME],
    template: {
      // Use Data Stream Lifecycle (DSL) for retention - works in both serverless and ESS
      lifecycle: {
        data_retention: retention,
      },
    },
    hidden: true,
  });

  return ds;
};
