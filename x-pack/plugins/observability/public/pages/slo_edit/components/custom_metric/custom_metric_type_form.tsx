/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  EuiComboBox,
  EuiComboBoxOptionOption,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiHorizontalRule,
  EuiIconTip,
  EuiSpacer,
  EuiTitle,
} from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import React from 'react';
import { Controller, useFormContext } from 'react-hook-form';
import { FormattedMessage } from '@kbn/i18n-react';
import { useFetchIndexPatternFields } from '../../../../hooks/slo/use_fetch_index_pattern_fields';
import { createOptionsFromFields } from '../../helpers/create_options';
import { CreateSLOForm } from '../../types';
import { DataPreviewChart } from '../common/data_preview_chart';
import { QueryBuilder } from '../common/query_builder';
import { IndexSelection } from '../custom_common/index_selection';
import { MetricIndicator } from './metric_indicator';

export { NEW_CUSTOM_METRIC } from './metric_indicator';

export function CustomMetricIndicatorTypeForm() {
  const { control, watch, getFieldState } = useFormContext<CreateSLOForm>();

  const { isLoading, data: indexFields } = useFetchIndexPatternFields(
    watch('indicator.params.index')
  );
  const timestampFields = (indexFields ?? []).filter((field) => field.type === 'date');

  return (
    <>
      <EuiTitle size="xs">
        <h3>
          <FormattedMessage
            id="xpack.observability.slo.sloEdit.sliType.histogram.sourceTitle"
            defaultMessage="Source"
          />
        </h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiFlexGroup direction="column" gutterSize="l">
        <EuiFlexGroup direction="row" gutterSize="l">
          <EuiFlexItem>
            <IndexSelection />
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiFormRow
              label={i18n.translate(
                'xpack.observability.slo.sloEdit.sliType.customMetric.timestampField.label',
                { defaultMessage: 'Timestamp field' }
              )}
              isInvalid={getFieldState('indicator.params.timestampField').invalid}
            >
              <Controller
                name="indicator.params.timestampField"
                defaultValue=""
                rules={{ required: true }}
                control={control}
                render={({ field: { ref, ...field }, fieldState }) => (
                  <EuiComboBox
                    {...field}
                    async
                    placeholder={i18n.translate(
                      'xpack.observability.slo.sloEdit.sliType.customMetric.timestampField.placeholder',
                      { defaultMessage: 'Select a timestamp field' }
                    )}
                    aria-label={i18n.translate(
                      'xpack.observability.slo.sloEdit.sliType.customMetric.timestampField.placeholder',
                      { defaultMessage: 'Select a timestamp field' }
                    )}
                    data-test-subj="customMetricIndicatorFormTimestampFieldSelect"
                    isClearable
                    isDisabled={!watch('indicator.params.index')}
                    isInvalid={fieldState.invalid}
                    isLoading={!!watch('indicator.params.index') && isLoading}
                    onChange={(selected: EuiComboBoxOptionOption[]) => {
                      if (selected.length) {
                        return field.onChange(selected[0].value);
                      }

                      field.onChange('');
                    }}
                    options={createOptionsFromFields(timestampFields)}
                    selectedOptions={
                      !!watch('indicator.params.index') &&
                      !!field.value &&
                      timestampFields.some((timestampField) => timestampField.name === field.value)
                        ? [
                            {
                              value: field.value,
                              label: field.value,
                              'data-test-subj': `customMetricIndicatorFormTimestampFieldSelectedValue`,
                            },
                          ]
                        : []
                    }
                    singleSelection={{ asPlainText: true }}
                  />
                )}
              />
            </EuiFormRow>
          </EuiFlexItem>
        </EuiFlexGroup>

        <EuiFlexItem>
          <QueryBuilder
            dataTestSubj="customMetricIndicatorFormQueryFilterInput"
            indexPatternString={watch('indicator.params.index')}
            label={i18n.translate(
              'xpack.observability.slo.sloEdit.sliType.customMetric.queryFilter',
              {
                defaultMessage: 'Query filter',
              }
            )}
            name="indicator.params.filter"
            placeholder={i18n.translate(
              'xpack.observability.slo.sloEdit.sliType.customMetric.customFilter',
              { defaultMessage: 'Custom filter to apply on the index' }
            )}
            tooltip={
              <EuiIconTip
                content={i18n.translate(
                  'xpack.observability.slo.sloEdit.sliType.customMetric.customFilter.tooltip',
                  {
                    defaultMessage:
                      'This KQL query can be used to filter the documents with some relevant criteria.',
                  }
                )}
                position="top"
              />
            }
          />
        </EuiFlexItem>

        <EuiFlexItem>
          <EuiHorizontalRule margin="none" />
        </EuiFlexItem>

        <EuiFlexItem>
          <EuiTitle size="xs">
            <h3>
              <FormattedMessage
                id="xpack.observability.slo.sloEdit.sliType.customMetric.goodTitle"
                defaultMessage="Good events"
              />
            </h3>
          </EuiTitle>
          <EuiSpacer size="s" />
          <MetricIndicator type="good" indexFields={indexFields} isLoadingIndex={isLoading} />
        </EuiFlexItem>

        <EuiFlexItem>
          <EuiHorizontalRule margin="none" />
        </EuiFlexItem>

        <EuiFlexItem>
          <EuiTitle size="xs">
            <h3>
              <FormattedMessage
                id="xpack.observability.slo.sloEdit.sliType.customMetric.totalTitle"
                defaultMessage="Total events"
              />
            </h3>
          </EuiTitle>
          <EuiSpacer size="s" />
          <MetricIndicator type="total" indexFields={indexFields} isLoadingIndex={isLoading} />
        </EuiFlexItem>

        <EuiFlexItem>
          <EuiHorizontalRule margin="none" />
        </EuiFlexItem>

        <DataPreviewChart />
      </EuiFlexGroup>
    </>
  );
}
