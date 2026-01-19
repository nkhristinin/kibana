/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import type { Filter } from '@kbn/es-query';

export interface FieldAnalysis {
  field_name: string;
  field_type: string;
  is_searchable: boolean;
  is_aggregatable: boolean;
  has_keyword_subfield: boolean;
  used_in: 'query' | 'filter' | 'suppression';
  suggestions: string[];
}

export interface IndexAnalysis {
  index_name: string;
  doc_count: number;
  size_bytes?: number;
  size_human?: string;
  health?: string;
  status: 'active' | 'empty' | 'error';
  // Additional index metadata
  is_frozen?: boolean; // True if index name starts with "partial-" (frozen tier searchable snapshot)
  is_searchable_snapshot?: boolean; // True if "partial-" or "restored-" prefix
  is_hidden?: boolean;
  is_data_stream?: boolean;
  data_stream_name?: string;
  primary_shards?: number;
  replica_shards?: number;
  creation_date?: string;
}

/**
 * Extracts field names from a KQL or Lucene query string.
 * This is a simplified parser - it extracts tokens that look like field references.
 */
export function extractFieldsFromQuery(query: string | undefined, language: string): string[] {
  if (!query) return [];

  const fields = new Set<string>();

  // Pattern to match field:value or field:"value" patterns
  // Handles nested fields like process.name, host.os.name
  const fieldPattern = /([a-zA-Z_][a-zA-Z0-9_\.]*)\s*:/g;

  let match;
  while ((match = fieldPattern.exec(query)) !== null) {
    const field = match[1];
    // Skip KQL keywords
    if (!['and', 'or', 'not'].includes(field.toLowerCase())) {
      fields.add(field);
    }
  }

  return Array.from(fields);
}

/**
 * Extracts field names from Kibana filters array.
 */
export function extractFieldsFromFilters(filters: Filter[] | undefined): string[] {
  if (!filters || filters.length === 0) return [];

  const fields = new Set<string>();

  for (const filter of filters) {
    // Handle meta.key
    if (filter.meta?.key) {
      fields.add(filter.meta.key);
    }

    // Handle query.match
    if (filter.query?.match) {
      Object.keys(filter.query.match).forEach((f) => fields.add(f));
    }

    // Handle query.match_phrase
    if (filter.query?.match_phrase) {
      Object.keys(filter.query.match_phrase).forEach((f) => fields.add(f));
    }

    // Handle query.range
    if (filter.query?.range) {
      Object.keys(filter.query.range).forEach((f) => fields.add(f));
    }

    // Handle query.exists
    if (filter.query?.exists?.field) {
      fields.add(filter.query.exists.field);
    }

    // Handle query.term
    if (filter.query?.term) {
      Object.keys(filter.query.term).forEach((f) => fields.add(f));
    }

    // Handle query.terms
    if (filter.query?.terms) {
      Object.keys(filter.query.terms).forEach((f) => fields.add(f));
    }
  }

  return Array.from(fields);
}

/**
 * Generates optimization suggestions for a field based on its mapping.
 */
function generateFieldSuggestions(
  fieldName: string,
  fieldType: string,
  isAggregatable: boolean,
  hasKeywordSubfield: boolean,
  usedIn: string
): string[] {
  const suggestions: string[] = [];

  // Text field used for exact matching - suggest keyword
  if (fieldType === 'text' && !hasKeywordSubfield) {
    suggestions.push(
      `Field '${fieldName}' is type 'text' without a .keyword subfield. Exact matching and aggregations will be slow or unavailable.`
    );
  }

  // Text field with keyword subfield - suggest using it
  if (fieldType === 'text' && hasKeywordSubfield) {
    suggestions.push(
      `Field '${fieldName}' is type 'text'. Consider using '${fieldName}.keyword' for exact matching and better performance.`
    );
  }

  // Non-aggregatable field used for suppression
  if (usedIn === 'suppression' && !isAggregatable) {
    suggestions.push(
      `Field '${fieldName}' is not aggregatable but used for alert suppression. This may cause errors.`
    );
  }

  return suggestions;
}

/**
 * Analyzes indices to determine which have data and which are empty.
 * Also detects frozen indices and provides detailed metadata.
 *
 * When timeRange is provided, only indices that have documents within that
 * time range are included - matching the actual indices that ES would query.
 */
export async function analyzeIndices({
  esClient,
  indexPatterns,
  logger,
  timeRange,
}: {
  esClient: ElasticsearchClient;
  indexPatterns: string[];
  logger: Logger;
  timeRange?: { from: string; to: string };
}): Promise<IndexAnalysis[]> {
  const results: IndexAnalysis[] = [];

  try {
    // Resolve index patterns to actual indices
    const resolvedIndices = await esClient.indices.resolveIndex({
      name: indexPatterns.join(','),
      expand_wildcards: ['open'],
    });

    // Build a map of data stream backing indices
    const dataStreamMap = new Map<string, string>();
    for (const ds of resolvedIndices.data_streams) {
      for (const backingIndex of ds.backing_indices) {
        dataStreamMap.set(backingIndex, ds.name);
      }
    }

    let indexNames = [
      ...resolvedIndices.indices.map((i) => i.name),
      ...resolvedIndices.data_streams.flatMap((ds) => ds.backing_indices),
    ];

    if (indexNames.length === 0) {
      return indexPatterns.map((pattern) => ({
        index_name: pattern,
        doc_count: 0,
        status: 'empty' as const,
      }));
    }

    // If time range is provided, filter to only indices that have data in that range
    // This matches the actual indices that ES would query
    let indicesWithDataInRange: Set<string> | undefined;
    if (timeRange) {
      try {
        // Use a terms aggregation on _index to find which indices have data in range
        // This is efficient as it doesn't return documents, just index names
        const rangeCheckResponse = await esClient.search({
          index: indexNames.join(','),
          size: 0,
          ignore_unavailable: true,
          allow_no_indices: true,
          body: {
            query: {
              range: {
                '@timestamp': {
                  gte: timeRange.from,
                  lte: timeRange.to,
                },
              },
            },
            aggs: {
              indices_with_data: {
                terms: {
                  field: '_index',
                  size: 1000, // Up to 1000 indices
                },
              },
            },
          },
        });

        const indicesAgg = rangeCheckResponse.aggregations?.indices_with_data as
          | { buckets: Array<{ key: string; doc_count: number }> }
          | undefined;

        if (indicesAgg?.buckets) {
          indicesWithDataInRange = new Set(indicesAgg.buckets.map((b) => b.key));
          // Filter to only indices with data in range
          indexNames = indexNames.filter((name) => indicesWithDataInRange!.has(name));

          if (indexNames.length === 0) {
            // No indices have data in the time range
            return [
              {
                index_name: `(no data in range ${timeRange.from} to ${timeRange.to})`,
                doc_count: 0,
                status: 'empty' as const,
              },
            ];
          }
        }
      } catch (rangeError) {
        // If range check fails, fall back to showing all indices
        logger.debug(`[Index Analysis] Time range filter failed: ${rangeError}`);
      }
    }

    // Get index stats with more columns
    // h: index, docs.count, store.size (bytes), pri (primary shards), rep (replica), health, creation.date.string
    const statsResponse = await esClient.cat.indices({
      index: indexNames.slice(0, 50).join(','), // Limit to first 50 indices
      format: 'json',
      bytes: 'b', // Return sizes in bytes
      h: 'index,docs.count,store.size,pri.store.size,pri,rep,health,creation.date.string',
    });

    for (const stat of statsResponse) {
      const indexName = stat.index || 'unknown';
      const docCount = parseInt(stat['docs.count'] || '0', 10);
      const sizeBytes = parseInt(stat['store.size'] || '0', 10);
      const priShards = parseInt(stat.pri || '0', 10);
      const repShards = parseInt(stat.rep || '0', 10);

      // Check if this index is on the frozen tier (ES 8.x/9.x+)
      // Frozen tier indices created by ILM are prefixed with "partial-"
      // Cold tier searchable snapshots are prefixed with "restored-"
      const isFrozen = indexName.startsWith('partial-');
      const isSearchableSnapshot = indexName.startsWith('partial-') || indexName.startsWith('restored-');
      const isHidden = indexName.startsWith('.');

      // Check if part of a data stream
      const dataStreamName = dataStreamMap.get(indexName);

      results.push({
        index_name: indexName,
        doc_count: docCount,
        size_bytes: sizeBytes,
        size_human: formatBytes(sizeBytes),
        health: stat.health,
        status: docCount === 0 ? 'empty' : 'active',
        is_frozen: isFrozen,
        is_searchable_snapshot: isSearchableSnapshot,
        is_hidden: isHidden,
        is_data_stream: !!dataStreamName,
        data_stream_name: dataStreamName,
        primary_shards: priShards,
        replica_shards: repShards,
        creation_date: stat['creation.date.string'],
      });
    }

    // Check for patterns that resolved to nothing (only if no time range filter)
    if (!timeRange) {
      for (const pattern of indexPatterns) {
        const hasMatch = results.some(
          (r) => r.index_name.includes(pattern.replace('*', '')) || pattern.includes(r.index_name)
        );
        if (!hasMatch && !pattern.includes('*')) {
          results.push({
            index_name: pattern,
            doc_count: 0,
            status: 'empty',
          });
        }
      }
    }
  } catch (error) {
    logger.debug(`[Index Analysis] Failed to analyze indices: ${error}`);
    // Return basic info on failure
    return indexPatterns.map((pattern) => ({
      index_name: pattern,
      doc_count: -1,
      status: 'error' as const,
    }));
  }

  return results.sort((a, b) => b.doc_count - a.doc_count);
}

/**
 * Formats bytes to human-readable string.
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

/**
 * Analyzes field mappings for the given fields.
 */
export async function analyzeFields({
  esClient,
  indexPatterns,
  queryFields,
  filterFields,
  suppressionFields,
  logger,
}: {
  esClient: ElasticsearchClient;
  indexPatterns: string[];
  queryFields: string[];
  filterFields: string[];
  suppressionFields: string[];
  logger: Logger;
}): Promise<FieldAnalysis[]> {
  const allFields = [...new Set([...queryFields, ...filterFields, ...suppressionFields])];

  if (allFields.length === 0) {
    return [];
  }

  const results: FieldAnalysis[] = [];

  try {
    // Get field mappings
    const mappings = await esClient.indices.getFieldMapping({
      index: indexPatterns.join(','),
      fields: allFields,
      allow_no_indices: true,
      ignore_unavailable: true,
    });

    // Process each field
    for (const field of allFields) {
      let fieldType = 'unknown';
      let isSearchable = false;
      let isAggregatable = false;
      let hasKeywordSubfield = false;

      // Find mapping for this field across all indices
      for (const indexMappings of Object.values(mappings)) {
        const fieldMapping = indexMappings.mappings?.[field];
        if (fieldMapping?.mapping) {
          const mappingDetails = Object.values(fieldMapping.mapping)[0];
          if (mappingDetails) {
            fieldType = mappingDetails.type || 'unknown';
            // Keywords and dates are aggregatable
            isAggregatable = ['keyword', 'date', 'long', 'integer', 'short', 'byte', 'double', 'float', 'ip', 'boolean'].includes(fieldType);
            isSearchable = true;
            // Check for keyword subfield
            if (mappingDetails.fields?.keyword) {
              hasKeywordSubfield = true;
            }
            break; // Use first found mapping
          }
        }
      }

      // Also check for .keyword subfield explicitly
      if (!hasKeywordSubfield && fieldType === 'text') {
        const keywordField = `${field}.keyword`;
        for (const indexMappings of Object.values(mappings)) {
          if (indexMappings.mappings?.[keywordField]) {
            hasKeywordSubfield = true;
            break;
          }
        }
      }

      // Determine where this field is used
      let usedIn: 'query' | 'filter' | 'suppression' = 'query';
      if (suppressionFields.includes(field)) {
        usedIn = 'suppression';
      } else if (filterFields.includes(field) && !queryFields.includes(field)) {
        usedIn = 'filter';
      }

      const suggestions = generateFieldSuggestions(
        field,
        fieldType,
        isAggregatable,
        hasKeywordSubfield,
        usedIn
      );

      results.push({
        field_name: field,
        field_type: fieldType,
        is_searchable: isSearchable,
        is_aggregatable: isAggregatable,
        has_keyword_subfield: hasKeywordSubfield,
        used_in: usedIn,
        suggestions,
      });
    }
  } catch (error) {
    logger.debug(`[Field Analysis] Failed to analyze fields: ${error}`);
    // Return basic info on failure
    return allFields.map((field) => ({
      field_name: field,
      field_type: 'unknown',
      is_searchable: false,
      is_aggregatable: false,
      has_keyword_subfield: false,
      used_in: queryFields.includes(field) ? 'query' as const : 'filter' as const,
      suggestions: [],
    }));
  }

  return results;
}

/**
 * Checks cardinality of a field (useful for suppression fields).
 */
export async function checkFieldCardinality({
  esClient,
  indexPatterns,
  field,
  timeRange,
  logger,
}: {
  esClient: ElasticsearchClient;
  indexPatterns: string[];
  field: string;
  timeRange: { from: string; to: string };
  logger: Logger;
}): Promise<{ cardinality: number; isHighCardinality: boolean }> {
  try {
    const response = await esClient.search({
      index: indexPatterns.join(','),
      size: 0,
      ignore_unavailable: true,
      allow_no_indices: true,
      body: {
        query: {
          range: {
            '@timestamp': {
              gte: timeRange.from,
              lte: timeRange.to,
            },
          },
        },
        aggs: {
          field_cardinality: {
            cardinality: {
              field,
              precision_threshold: 10000,
            },
          },
        },
      },
    });

    const cardinality =
      (response.aggregations?.field_cardinality as { value: number })?.value || 0;

    return {
      cardinality,
      isHighCardinality: cardinality > 10000,
    };
  } catch (error) {
    logger.debug(`[Field Analysis] Failed to check cardinality for ${field}: ${error}`);
    return { cardinality: -1, isHighCardinality: false };
  }
}

