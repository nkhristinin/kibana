/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import expect from '@kbn/expect';
import { ALERT_WORKFLOW_STATUS } from '@kbn/rule-data-utils';
import type * as estypes from '@elastic/elasticsearch/lib/api/typesWithBodyKey';

import {
  DETECTION_ENGINE_SIGNALS_STATUS_URL,
  DETECTION_ENGINE_QUERY_SIGNALS_URL,
} from '@kbn/security-solution-plugin/common/constants';
import { ROLES } from '@kbn/security-solution-plugin/common/test';
import { DetectionAlert } from '@kbn/security-solution-plugin/common/api/detection_engine';
import { FtrProviderContext } from '../../common/ftr_provider_context';
import {
  createSignalsIndex,
  deleteAllAlerts,
  setSignalStatus,
  getAlertUpdateByQueryEmptyResponse,
  getQuerySignalIds,
  deleteAllRules,
  createRule,
  waitForSignalsToBePresent,
  getSignalsByIds,
  waitForRuleSuccess,
  getRuleForSignalTesting,
} from '../../utils';
import { createUserAndRole, deleteUserAndRole } from '../../../common/services/security_solution';

// eslint-disable-next-line import/no-default-export
export default ({ getService }: FtrProviderContext) => {
  const supertest = getService('supertest');
  const esArchiver = getService('esArchiver');
  const supertestWithoutAuth = getService('supertestWithoutAuth');
  const log = getService('log');
  const es = getService('es');

  describe('open_close_signals', () => {
    describe('validation checks', () => {
      describe('update by ids', () => {
        it('should not give errors when querying and the signals index does not exist yet', async () => {
          const { body } = await supertest
            .post(DETECTION_ENGINE_SIGNALS_STATUS_URL)
            .set('kbn-xsrf', 'true')
            .send(setSignalStatus({ signalIds: ['123'], status: 'open' }))
            .expect(200);

          // remove any server generated items that are nondeterministic
          body.items.forEach((_: any, index: number) => {
            delete body.items[index].update.error.index_uuid;
          });
          delete body.took;

          expect(body).to.eql({
            errors: true,
            items: [
              {
                update: {
                  _id: '123',
                  _index: '.internal.alerts-security.alerts-default-000001',
                  error: {
                    index: '.internal.alerts-security.alerts-default-000001',
                    reason: '[123]: document missing',
                    shard: '0',
                    type: 'document_missing_exception',
                  },
                  status: 404,
                },
              },
            ],
          });
        });

        it('should not give errors when querying and the signals index does exist and is empty', async () => {
          await createSignalsIndex(supertest, log);
          const { body } = await supertest
            .post(DETECTION_ENGINE_SIGNALS_STATUS_URL)
            .set('kbn-xsrf', 'true')
            .send(setSignalStatus({ signalIds: ['123'], status: 'open' }))
            .expect(200);

          // remove any server generated items that are nondeterministic
          body.items.forEach((_: any, index: number) => {
            delete body.items[index].update.error.index_uuid;
          });
          delete body.took;

          expect(body).to.eql({
            errors: true,
            items: [
              {
                update: {
                  _id: '123',
                  _index: '.internal.alerts-security.alerts-default-000001',
                  error: {
                    index: '.internal.alerts-security.alerts-default-000001',
                    reason: '[123]: document missing',
                    shard: '0',
                    type: 'document_missing_exception',
                  },
                  status: 404,
                },
              },
            ],
          });

          await deleteAllAlerts(supertest, log, es);
        });
      });

      describe('update by query', () => {
        it('should not give errors when querying and the signals index does not exist yet', async () => {
          const { body } = await supertest
            .post(DETECTION_ENGINE_SIGNALS_STATUS_URL)
            .set('kbn-xsrf', 'true')
            .send(setSignalStatus({ query: { match_all: {} }, status: 'open' }))
            .expect(200);

          // remove any server generated items that are indeterministic
          delete body.took;

          expect(body).to.eql(getAlertUpdateByQueryEmptyResponse());
        });

        it('should not give errors when querying and the signals index does exist and is empty', async () => {
          await createSignalsIndex(supertest, log);
          const { body } = await supertest
            .post(DETECTION_ENGINE_SIGNALS_STATUS_URL)
            .set('kbn-xsrf', 'true')
            .send(setSignalStatus({ query: { match_all: {} }, status: 'open' }))
            .expect(200);

          // remove any server generated items that are indeterministic
          delete body.took;

          expect(body).to.eql(getAlertUpdateByQueryEmptyResponse());

          await deleteAllAlerts(supertest, log, es);
        });
      });

      describe('tests with auditbeat data', () => {
        before(async () => {
          await esArchiver.load('x-pack/test/functional/es_archives/auditbeat/hosts');
        });

        after(async () => {
          await esArchiver.unload('x-pack/test/functional/es_archives/auditbeat/hosts');
        });

        beforeEach(async () => {
          await deleteAllRules(supertest, log);
          await createSignalsIndex(supertest, log);
        });

        afterEach(async () => {
          await deleteAllAlerts(supertest, log, es);
          await deleteAllRules(supertest, log);
        });

        it('should be able to execute and get 10 signals', async () => {
          const rule = {
            ...getRuleForSignalTesting(['auditbeat-*']),
            query: 'process.executable: "/usr/bin/sudo"',
          };
          const { id } = await createRule(supertest, log, rule);
          await waitForRuleSuccess({ supertest, log, id });
          await waitForSignalsToBePresent(supertest, log, 10, [id]);
          const signalsOpen = await getSignalsByIds(supertest, log, [id]);
          expect(signalsOpen.hits.hits.length).equal(10);
        });

        it('should be have set the signals in an open state initially', async () => {
          const rule = {
            ...getRuleForSignalTesting(['auditbeat-*']),
            query: 'process.executable: "/usr/bin/sudo"',
          };
          const { id } = await createRule(supertest, log, rule);
          await waitForRuleSuccess({ supertest, log, id });
          await waitForSignalsToBePresent(supertest, log, 10, [id]);
          const signalsOpen = await getSignalsByIds(supertest, log, [id]);
          const everySignalOpen = signalsOpen.hits.hits.every(
            (hit) => hit._source?.[ALERT_WORKFLOW_STATUS] === 'open'
          );
          expect(everySignalOpen).to.eql(true);
        });

        it('should be able to get a count of 10 closed signals when closing 10', async () => {
          const rule = {
            ...getRuleForSignalTesting(['auditbeat-*']),
            query: 'process.executable: "/usr/bin/sudo"',
          };
          const { id } = await createRule(supertest, log, rule);
          await waitForRuleSuccess({ supertest, log, id });
          await waitForSignalsToBePresent(supertest, log, 10, [id]);
          const signalsOpen = await getSignalsByIds(supertest, log, [id]);
          const signalIds = signalsOpen.hits.hits.map((signal) => signal._id);

          // set all of the signals to the state of closed. There is no reason to use a waitUntil here
          // as this route intentionally has a waitFor within it and should only return when the query has
          // the data.
          await supertest
            .post(DETECTION_ENGINE_SIGNALS_STATUS_URL)
            .set('kbn-xsrf', 'true')
            .send(setSignalStatus({ signalIds, status: 'closed' }))
            .expect(200);

          const { body: signalsClosed }: { body: estypes.SearchResponse<DetectionAlert> } =
            await supertest
              .post(DETECTION_ENGINE_QUERY_SIGNALS_URL)
              .set('kbn-xsrf', 'true')
              .send(getQuerySignalIds(signalIds))
              .expect(200);
          expect(signalsClosed.hits.hits.length).to.equal(10);
        });

        it('should be able close signals immediately and they all should be closed', async () => {
          const rule = {
            ...getRuleForSignalTesting(['auditbeat-*']),
            query: 'process.executable: "/usr/bin/sudo"',
          };
          const { id } = await createRule(supertest, log, rule);
          await waitForRuleSuccess({ supertest, log, id });
          await waitForSignalsToBePresent(supertest, log, 1, [id]);
          const signalsOpen = await getSignalsByIds(supertest, log, [id]);
          const signalIds = signalsOpen.hits.hits.map((signal) => signal._id);

          // set all of the signals to the state of closed. There is no reason to use a waitUntil here
          // as this route intentionally has a waitFor within it and should only return when the query has
          // the data.
          await supertest
            .post(DETECTION_ENGINE_SIGNALS_STATUS_URL)
            .set('kbn-xsrf', 'true')
            .send(setSignalStatus({ signalIds, status: 'closed' }))
            .expect(200);

          const { body: signalsClosed }: { body: estypes.SearchResponse<DetectionAlert> } =
            await supertest
              .post(DETECTION_ENGINE_QUERY_SIGNALS_URL)
              .set('kbn-xsrf', 'true')
              .send(getQuerySignalIds(signalIds))
              .expect(200);

          const everySignalClosed = signalsClosed.hits.hits.every(
            (hit) => hit._source?.['kibana.alert.workflow_status'] === 'closed'
          );
          expect(everySignalClosed).to.eql(true);
        });

        // This fails and should be investigated or removed if it no longer applies
        it.skip('should be able to close signals with t1 analyst user', async () => {
          const rule = getRuleForSignalTesting(['auditbeat-*']);
          const { id } = await createRule(supertest, log, rule);
          await waitForRuleSuccess({ supertest, log, id });
          await waitForSignalsToBePresent(supertest, log, 1, [id]);
          await createUserAndRole(getService, ROLES.t1_analyst);
          const signalsOpen = await getSignalsByIds(supertest, log, [id]);
          const signalIds = signalsOpen.hits.hits.map((signal) => signal._id);

          // Try to set all of the signals to the state of closed.
          // This should not be possible with the given user.
          await supertestWithoutAuth
            .post(DETECTION_ENGINE_SIGNALS_STATUS_URL)
            .set('kbn-xsrf', 'true')
            .auth(ROLES.t1_analyst, 'changeme')
            .send(setSignalStatus({ signalIds, status: 'closed' }))
            .expect(200);

          // query for the signals with the superuser
          // to allow a check that the signals were NOT closed with t1 analyst
          const { body: signalsClosed }: { body: estypes.SearchResponse<DetectionAlert> } =
            await supertest
              .post(DETECTION_ENGINE_QUERY_SIGNALS_URL)
              .set('kbn-xsrf', 'true')
              .send(getQuerySignalIds(signalIds))
              .expect(200);

          const everySignalClosed = signalsClosed.hits.hits.every(
            (hit) => hit._source?.['kibana.alert.workflow_status'] === 'closed'
          );
          expect(everySignalClosed).to.eql(true);

          await deleteUserAndRole(getService, ROLES.t1_analyst);
        });

        // This fails and should be investigated or removed if it no longer applies
        it.skip('should be able to close signals with soc_manager user', async () => {
          const rule = getRuleForSignalTesting(['auditbeat-*']);
          const { id } = await createRule(supertest, log, rule);
          await waitForRuleSuccess({ supertest, log, id });
          await waitForSignalsToBePresent(supertest, log, 1, [id]);
          const userAndRole = ROLES.soc_manager;
          await createUserAndRole(getService, userAndRole);
          const signalsOpen = await getSignalsByIds(supertest, log, [id]);
          const signalIds = signalsOpen.hits.hits.map((signal) => signal._id);

          // Try to set all of the signals to the state of closed.
          // This should not be possible with the given user.
          await supertestWithoutAuth
            .post(DETECTION_ENGINE_SIGNALS_STATUS_URL)
            .set('kbn-xsrf', 'true')
            .auth(userAndRole, 'changeme') // each user has the same password
            .send(setSignalStatus({ signalIds, status: 'closed' }))
            .expect(200);

          const { body: signalsClosed }: { body: estypes.SearchResponse<DetectionAlert> } =
            await supertest
              .post(DETECTION_ENGINE_QUERY_SIGNALS_URL)
              .set('kbn-xsrf', 'true')
              .send(getQuerySignalIds(signalIds))
              .expect(200);

          const everySignalClosed = signalsClosed.hits.hits.every(
            (hit) => hit._source?.['kibana.alert.workflow_status'] === 'closed'
          );
          expect(everySignalClosed).to.eql(true);

          await deleteUserAndRole(getService, userAndRole);
        });
      });
    });
  });
};
