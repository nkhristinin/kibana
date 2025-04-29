/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
import type { ElasticsearchClient } from '@kbn/core-elasticsearch-server';
interface RuleDebugMessage {
  message: string;
  attachements?: Array<{
    name: string;
    body: string;
  }>;
  type: string;
  timestamp: Date;
}

interface RuleExecutionLog {
  executionId: string;
  log: RuleDebugMessage[];
}

export class RuleDebugService {
  private esClustierClient: ElasticsearchClient;
  private readonly dataStreamName = 'rule-debug-log';

  constructor() {}

  async setup({ esClustierClient }: { esClustierClient: ElasticsearchClient }) {
    this.esClustierClient = esClustierClient;

    // Create the data stream if it doesn't exist
    let dataStreamExists = false;
    try {
      await this.esClustierClient.indices.getDataStream({
        name: this.dataStreamName,
      });
      dataStreamExists = true;
    } catch (error) {
      if (error.meta?.statusCode !== 404) {
        throw error;
      }
    }
    if (!dataStreamExists) {
      await this.esClustierClient.indices.putIndexTemplate({
        name: `${this.dataStreamName}-template`,
        index_patterns: [this.dataStreamName],
        data_stream: {},
        template: {
          mappings: {
            properties: {
              '@timestamp': { type: 'date' },
              ruleId: { type: 'keyword' },
              executionId: { type: 'keyword' },
              message: { type: 'object', enabled: false }, // Store the entire JSON object
            },
          },
        },
      });

      await this.esClustierClient.indices.createDataStream({
        name: this.dataStreamName,
      });
    }
  }

  private async _addDebugMessage({
    ruleId,
    executionId,
    message,
    type,
    attachements,
    timestamp,
  }: RuleDebugMessage & { ruleId: string; executionId: string }) {
    // Store in Elasticsearch data stream
    await this.esClustierClient.index({
      index: this.dataStreamName,
      body: {
        ruleId,
        executionId,
        '@timestamp': timestamp,
        message: {
          message,
          type,
          attachements,
        },
      },
    });
  }

  async getDebugLog(ruleId: string): Promise<RuleExecutionLog[]> {
    // Retrieve from Elasticsearch data stream
    const response = await this.esClustierClient.search({
      index: this.dataStreamName,
      query: {
        term: { ruleId },
      },
      sort: [{ '@timestamp': { order: 'desc' } }],
    });

    const hits = response.hits.hits.map((hit: any) => hit._source);

    const groupedLogs: { [executionId: string]: RuleExecutionLog } = {};

    for (const hit of hits) {
      const { executionId, message, timestamp } = hit;
      if (!groupedLogs[executionId]) {
        groupedLogs[executionId] = { executionId, log: [] };
      }
      groupedLogs[executionId].log.push({ ...message, timestamp });
    }

    return Object.values(groupedLogs);
  }

  async getExecutionIdsByRuleId(ruleId: string): Promise<string[]> {
    const response = await this.esClustierClient.search({
      index: this.dataStreamName,
      size: 0, // No need to retrieve individual documents
      query: {
        term: { ruleId },
      },
      aggs: {
        uniqueExecutionIds: {
          terms: {
            field: 'executionId',
            size: 1000, // Adjust size as needed
          },
        },
      },
    });

    return response.aggregations.uniqueExecutionIds.buckets.map((bucket: any) => bucket.key);
  }

  async getMessagesByExecutionId(
    ruleId: string,
    executionId: string,
    page: number = 0,
    perPage: number = 10
  ): Promise<RuleDebugMessage[]> {
    const response = await this.esClustierClient.search({
      index: this.dataStreamName,
      query: {
        bool: {
          must: [{ term: { ruleId } }, { term: { executionId } }],
        },
      },
      sort: [{ '@timestamp': { order: 'asc' } }],
      from: page * perPage,
      size: perPage,
    });

    return {
      result: response.hits.hits.map((hit: any) => {
        const { message, '@timestamp': timestamp } = hit._source;
        return { ...message, timestamp };
      }),
      total: response.hits.total.value,
    };
  }

  createClient({ ruleId, executionId }: { ruleId: string; executionId: string }) {
    const timestamp = new Date();
    const sharedParams = {
      ruleId,
      executionId,
      timestamp,
    };
    return {
      addDebugMessage: async (message: string) => {
        await this._addDebugMessage({ ...sharedParams, message, type: 'message' });
      },
      addRequest: async (message: string, request: unknown, response: unknown) => {
        await this._addDebugMessage({
          ...sharedParams,
          message,
          type: 'request',
          attachements: [
            {
              name: 'request',
              body: JSON.stringify(request),
            },
            // {
            //   name: 'response',
            //   body: JSON.stringify(response),
            // },
          ],
        });
      },
    };
  }
}
