/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

import { getStateColumnActions } from './columns';
import { configMock } from '../../../__mocks__/config';
import { dataViewMock } from '@kbn/discover-utils/src/__mocks__';
import { dataViewsMock } from '../../../__mocks__/data_views';
import { Capabilities } from '@kbn/core/types';
import { DiscoverAppState } from '../../../application/main/services/discover_app_state_container';

function getStateColumnAction(
  state: DiscoverAppState,
  setAppState: (state: Partial<DiscoverAppState>) => void
) {
  return getStateColumnActions({
    capabilities: {
      discover: {
        save: false,
      },
    } as unknown as Capabilities,
    config: configMock,
    dataView: dataViewMock,
    dataViews: dataViewsMock,
    useNewFieldsApi: true,
    setAppState,
    columns: state.columns,
    sort: state.sort,
  });
}

describe('Test column actions', () => {
  test('getStateColumnActions with empty state', () => {
    const setAppState = jest.fn();
    const actions = getStateColumnAction({}, setAppState);

    actions.onAddColumn('_score');
    expect(setAppState).toHaveBeenCalledWith({ columns: ['_score'], sort: [['_score', 'desc']] });
    actions.onAddColumn('test');
    expect(setAppState).toHaveBeenCalledWith({ columns: ['test'] });
  });
  test('getStateColumnActions with columns and sort in state', () => {
    const setAppState = jest.fn();
    const actions = getStateColumnAction(
      { columns: ['first', 'second'], sort: [['first', 'desc']] },
      setAppState
    );

    actions.onAddColumn('_score');
    expect(setAppState).toHaveBeenCalledWith({
      columns: ['first', 'second', '_score'],
      sort: [['first', 'desc']],
    });
    setAppState.mockClear();
    actions.onAddColumn('third');
    expect(setAppState).toHaveBeenCalledWith({
      columns: ['first', 'second', 'third'],
      sort: [['first', 'desc']],
    });
    setAppState.mockClear();
    actions.onRemoveColumn('first');
    expect(setAppState).toHaveBeenCalledWith({
      columns: ['second'],
      sort: [],
    });
    setAppState.mockClear();
    actions.onSetColumns(['first', 'second', 'third'], true);
    expect(setAppState).toHaveBeenCalledWith({
      columns: ['first', 'second', 'third'],
    });
    setAppState.mockClear();

    actions.onMoveColumn('second', 0);
    expect(setAppState).toHaveBeenCalledWith({
      columns: ['second', 'first'],
    });
  });
});
