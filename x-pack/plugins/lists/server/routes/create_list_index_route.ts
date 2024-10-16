/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { validate } from '@kbn/securitysolution-io-ts-utils';
import { transformError } from '@kbn/securitysolution-es-utils';
import { LIST_INDEX } from '@kbn/securitysolution-list-constants';

import { createListIndexResponse } from '../../common/api';
import type { ListsPluginRouter } from '../types';

import { buildSiemResponse } from './utils';

import { getListClient } from '.';

export const createListIndexRoute = (router: ListsPluginRouter): void => {
  router.post(
    {
      options: {
        tags: ['access:lists-all'],
      },
      path: LIST_INDEX,
      validate: false,
    },
    async (context, _, response) => {
      const siemResponse = buildSiemResponse(response);

      try {
        const lists = await getListClient(context);
        const listIndexExists = await lists.getListIndexExists();
        const listItemIndexExists = await lists.getListItemIndexExists();

        const policyExists = await lists.getListPolicyExists();
        const policyListItemExists = await lists.getListItemPolicyExists();

        if (!policyExists) {
          await lists.setListPolicy();
        }
        if (!policyListItemExists) {
          await lists.setListItemPolicy();
        }

        const templateExists = await lists.getListTemplateExists();
        const templateListItemsExists = await lists.getListItemTemplateExists();
        const legacyTemplateExists = await lists.getLegacyListTemplateExists();
        const legacyTemplateListItemsExists = await lists.getLegacyListItemTemplateExists();

        if (!templateExists) {
          await lists.setListTemplate();
        }

        if (!templateListItemsExists) {
          await lists.setListItemTemplate();
        }

        try {
          // Check if the old legacy lists and items template exists and remove it
          if (legacyTemplateExists) {
            await lists.deleteLegacyListTemplate();
          }
          if (legacyTemplateListItemsExists) {
            await lists.deleteLegacyListItemTemplate();
          }
        } catch (err) {
          if (err.statusCode !== 404) {
            throw err;
          }
        }

        if (listIndexExists && listItemIndexExists) {
          return siemResponse.error({
            body: `index: "${lists.getListIndex()}" and "${lists.getListItemIndex()}" already exists`,
            statusCode: 409,
          });
        } else {
          if (!listIndexExists) {
            await lists.createListBootStrapIndex();
          }
          if (!listItemIndexExists) {
            await lists.createListItemBootStrapIndex();
          }

          const [validated, errors] = validate({ acknowledged: true }, createListIndexResponse);
          if (errors != null) {
            return siemResponse.error({ body: errors, statusCode: 500 });
          } else {
            return response.ok({ body: validated ?? {} });
          }
        }
      } catch (err) {
        const error = transformError(err);
        return siemResponse.error({
          body: error.message,
          statusCode: error.statusCode,
        });
      }
    }
  );
};
