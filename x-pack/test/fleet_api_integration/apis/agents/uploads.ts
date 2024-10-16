/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import expect from '@kbn/expect';
import { AGENT_ACTIONS_INDEX, AGENT_ACTIONS_RESULTS_INDEX } from '@kbn/fleet-plugin/common';
import {
  FILE_STORAGE_DATA_AGENT_INDEX,
  FILE_STORAGE_METADATA_AGENT_INDEX,
} from '@kbn/fleet-plugin/server/constants';
import { FtrProviderContext } from '../../../api_integration/ftr_provider_context';
import { setupFleetAndAgents } from './services';
import { skipIfNoDockerRegistry } from '../../helpers';

export default function (providerContext: FtrProviderContext) {
  const { getService } = providerContext;
  const esArchiver = getService('esArchiver');
  const supertest = getService('supertest');
  const esClient = getService('es');

  const ES_INDEX_OPTIONS = { headers: { 'X-elastic-product-origin': 'fleet' } };

  const cleanupFiles = async () => {
    await esClient.deleteByQuery({
      index: `${FILE_STORAGE_DATA_AGENT_INDEX},${FILE_STORAGE_METADATA_AGENT_INDEX}`,
      refresh: true,
      ignore_unavailable: true,
      query: {
        bool: {
          filter: [
            {
              ids: {
                values: ['file1', 'file1.0'],
              },
            },
          ],
        },
      },
    });
  };

  // FAILING ES PROMOTION: https://github.com/elastic/kibana/issues/162730
  describe.skip('fleet_uploads', () => {
    skipIfNoDockerRegistry(providerContext);
    setupFleetAndAgents(providerContext);

    before(async () => {
      await esArchiver.unload('x-pack/test/functional/es_archives/fleet/empty_fleet_server');
      await getService('supertest').post(`/api/fleet/setup`).set('kbn-xsrf', 'xxx').send();
      await cleanupFiles();

      await esClient.create({
        index: AGENT_ACTIONS_INDEX,
        id: new Date().toISOString(),
        refresh: true,
        body: {
          type: 'REQUEST_DIAGNOSTICS',
          action_id: 'action1',
          agents: ['agent1'],
          '@timestamp': '2022-10-07T11:00:00.000Z',
        },
      });

      await esClient.create(
        {
          index: AGENT_ACTIONS_RESULTS_INDEX,
          id: new Date().toISOString(),
          refresh: true,
          body: {
            action_id: 'action1',
            agent_id: 'agent1',
            '@timestamp': '2022-10-07T12:00:00.000Z',
            data: {
              upload_id: 'file1',
            },
          },
        },
        ES_INDEX_OPTIONS
      );

      await esClient.index({
        index: FILE_STORAGE_METADATA_AGENT_INDEX,
        id: 'file1',
        refresh: true,
        op_type: 'create',
        body: {
          '@timestamp': new Date().toISOString(),
          upload_id: 'file1',
          action_id: 'action1',
          agent_id: 'agent1',
          file: {
            ChunkSize: 4194304,
            extension: 'zip',
            hash: {},
            mime_type: 'application/zip',
            mode: '0644',
            name: 'elastic-agent-diagnostics-2022-10-07T12-00-00Z-00.zip',
            path: '/agent/elastic-agent-diagnostics-2022-10-07T12-00-00Z-00.zip',
            size: 24917,
            Status: 'READY',
            type: 'file',
          },
        },
      });
    });
    after(async () => {
      await Promise.all([
        esArchiver.load('x-pack/test/functional/es_archives/fleet/empty_fleet_server'),
        cleanupFiles(),
      ]);
    });

    it('should get agent uploads', async () => {
      const { body } = await supertest
        .get(`/api/fleet/agents/agent1/uploads`)
        .set('kbn-xsrf', 'xxx')
        .expect(200);

      expect(body.items[0]).to.eql({
        actionId: 'action1',
        createTime: '2022-10-07T11:00:00.000Z',
        filePath:
          '/api/fleet/agents/files/file1/elastic-agent-diagnostics-2022-10-07T12-00-00Z-00.zip',
        id: 'file1',
        name: 'elastic-agent-diagnostics-2022-10-07T12-00-00Z-00.zip',
        status: 'READY',
      });
    });

    it('should get agent uploaded file', async () => {
      await esClient.index({
        index: FILE_STORAGE_DATA_AGENT_INDEX,
        id: 'file1.0',
        op_type: 'create',
        refresh: true,
        body: {
          '@timestamp': new Date().toISOString(),
          last: true,
          bid: 'file1',
          data: 'test',
        },
      });

      const { header } = await supertest
        .get(`/api/fleet/agents/files/file1/elastic-agent-diagnostics-2022-10-07T12-00-00Z-00.zip`)
        .set('kbn-xsrf', 'xxx')
        .expect(200);

      expect(header['content-type']).to.eql('application/octet-stream');
      expect(header['content-disposition']).to.eql(
        'attachment; filename="elastic-agent-diagnostics-2022-10-07T12-00-00Z-00.zip"'
      );
    });

    it('should return failed status with error message', async () => {
      await esClient.create({
        index: AGENT_ACTIONS_INDEX,
        id: new Date().toISOString(),
        refresh: true,
        body: {
          type: 'REQUEST_DIAGNOSTICS',
          action_id: 'action2',
          agents: ['agent2'],
          '@timestamp': '2022-10-07T11:00:00.000Z',
        },
      });
      await esClient.create(
        {
          index: AGENT_ACTIONS_RESULTS_INDEX,
          id: new Date().toISOString(),
          refresh: true,
          body: {
            action_id: 'action2',
            agent_id: 'agent2',
            '@timestamp': '2022-10-07T12:00:00.000Z',
            data: {},
            error: 'rate limit exceeded',
          },
        },
        ES_INDEX_OPTIONS
      );

      const { body } = await supertest
        .get(`/api/fleet/agents/agent2/uploads`)
        .set('kbn-xsrf', 'xxx')
        .expect(200);

      expect(body.items[0]).to.eql({
        actionId: 'action2',
        createTime: '2022-10-07T11:00:00.000Z',
        filePath: '',
        id: 'action2',
        name: 'elastic-agent-diagnostics-2022-10-07T11-00-00Z-00.zip',
        status: 'FAILED',
        error: 'rate limit exceeded',
      });
    });
  });
}
