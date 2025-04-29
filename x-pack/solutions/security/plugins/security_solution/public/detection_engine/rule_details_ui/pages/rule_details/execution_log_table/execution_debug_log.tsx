/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { css } from '@emotion/css';
import styled from '@emotion/styled';
import {
  EuiModal,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiFlexItem,
  EuiFlexGroup,
  EuiText,
  EuiLoadingSpinner,
  EuiSpacer,
  EuiSearchBar,
  EuiBasicTable,
  EuiTitle,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiButton,
  EuiCodeBlock,
} from '@elastic/eui';
import { api } from '../../../../rule_monitoring/api';
import { FormattedDate } from '../../../../../common/components/formatted_date';

export const useExecutionsWithDebugLog = ({
  ruleId,
  executionId,
  page,
  perPage,
}: {
  ruleId: string;
  executionId: string;
  page: number;
  perPage: number;
}) => {
  return useQuery(
    [
      'detectionEngine',
      'ruleMonitoring',
      'executionResults',
      'executions',
      ruleId,
      executionId,
      page,
      perPage,
    ],
    ({ signal }) => {
      return api.fetchRuleDebugLogByExecutionId({ ruleId, signal, executionId, page, perPage });
    },
    {
      keepPreviousData: true,
      onError: (e) => {
        // addError(e, { title: 'error' });
      },
    }
  );
};

const ModalBody = styled(EuiFlexGroup)`
  overflow: hidden;
  padding: ${({ theme }) => theme.euiTheme.size.base};
`;

const modalWindow = css`
  min-height: 90vh;
  margin-top: 5vh;
  max-width: 1400px;
  min-width: 700px;
`;

const tableStyle = css`
  overflow: scroll;
`;

const Attachment = ({ attachement }) => {
  console.log('attachement', attachement);
  const [showFlyout, setShowFlyout] = useState(false);
  const request = JSON.parse(attachement?.body ?? {});
  return (
    <div>
      <EuiButton onClick={() => setShowFlyout(true)}>{attachement.name}</EuiButton>
      {showFlyout && (
        // <EuiFlyout ownFocus onClose={() => setShowFlyout(false)}>
        //   <EuiFlyoutHeader hasBorder>
        //     <EuiTitle size="m">
        //       <h2>{attachement.name}</h2>
        //     </EuiTitle>
        //   </EuiFlyoutHeader>
        //   <EuiFlyoutBody>
        //     <EuiCodeBlock language="html">{attachement.body}</EuiCodeBlock>
        //   </EuiFlyoutBody>
        // </EuiFlyout>

        <EuiModal maxWidth={false} className={modalWindow} onClose={() => setShowFlyout(false)}>
          <>
            <EuiModalHeader>
              <EuiFlexGroup justifyContent="spaceBetween" wrap>
                <EuiFlexItem grow={false}>
                  <EuiModalHeaderTitle data-test-subj="value-list-items-modal-title">
                    {attachement.name}
                  </EuiModalHeaderTitle>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiModalHeader>
            <ModalBody direction="column">
              <EuiText>
                <h4>{request.url}</h4>
              </EuiText>
              {request.body && (
                <EuiCodeBlock language="json" isCopyable overflowHeight={600} isVirtualized>
                  {JSON.stringify(request.body, null, 2)}
                </EuiCodeBlock>
              )}
            </ModalBody>
          </>
        </EuiModal>
      )}
    </div>
  );
};

export const ExecutionDebugLog = ({ ruleId, executionId, onCloseModal }) => {
  const [pageIndex, setPageIndex] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const { data, isLoading, isError } = useExecutionsWithDebugLog({
    ruleId,
    executionId,
    page: pageIndex,
    perPage: pageSize,
  });

  const pagination = {
    pageIndex,
    pageSize,
    totalItemCount: data?.total ?? 0,
    pageSizeOptions: [5, 10, 25],
  };

  const onTableChange = ({ page }) => {
    if (page) {
      setPageIndex(page.index);
      setPageSize(page.size);
    }
  };

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (isError) {
    return <div>Error loading debug log</div>;
  }

  if (!data) {
    return <div>No debug log found for this execution</div>;
  }

  const columns = [
    {
      field: 'timestamp',
      name: 'time',
      render: (value) => <FormattedDate value={value} fieldName={['timestamp']} />,
      width: '20%',
    },
    {
      field: 'message',
      name: 'message',
    },
    {
      field: 'attachements',
      name: 'attachements',
      render: (value) => {
        console.log(value);
        return (
          <>
            {value?.map((attachement) => {
              return <Attachment attachement={attachement} />;
            })}
          </>
        );
      },
      width: '20%',
    },
  ];

  return (
    // <EuiModal maxWidth={false} className={modalWindow} onClose={onCloseModal}>
    //   <>
    //     <EuiModalHeader>
    //       <EuiFlexGroup justifyContent="spaceBetween" wrap>
    //         <EuiFlexItem grow={false}>
    //           <EuiModalHeaderTitle data-test-subj="value-list-items-modal-title">
    //             Execution log
    //           </EuiModalHeaderTitle>
    //         </EuiFlexItem>
    //       </EuiFlexGroup>
    //     </EuiModalHeader>
    //     <ModalBody direction="column">
    //       <EuiFlexItem grow={true} className={tableStyle}>
    //         <EuiBasicTable
    //           data-test-subj="value-list-items-modal-table"
    //           items={data}
    //           columns={columns}
    //           // pagination={pagination}
    //           // sorting={sorting}
    //           // error={isError ? FAILED_TO_FETCH_LIST_ITEM : undefined}
    //           loading={isLoading}
    //           // onChange={onChange}
    //           // noItemsMessage={NOT_FOUND_ITEMS}
    //         />
    //       </EuiFlexItem>
    //     </ModalBody>
    //   </>
    // </EuiModal>
    <div>
      <EuiFlyout ownFocus onClose={onCloseModal} size="100%" maxWidth={'100%'}>
        <EuiFlyoutHeader hasBorder>
          <EuiTitle size="m">
            <h2>Execution log</h2>
          </EuiTitle>
        </EuiFlyoutHeader>
        <EuiFlyoutBody>
          <EuiBasicTable
            data-test-subj="value-list-items-modal-table"
            items={data?.result ?? []}
            columns={columns}
            pagination={pagination}
            // sorting={sorting}
            // error={isError ? FAILED_TO_FETCH_LIST_ITEM : undefined}
            loading={isLoading}
            onChange={onTableChange}
            // noItemsMessage={NOT_FOUND_ITEMS}
          />
        </EuiFlyoutBody>
      </EuiFlyout>
    </div>
  );
};
