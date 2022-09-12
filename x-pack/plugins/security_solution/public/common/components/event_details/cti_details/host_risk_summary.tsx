/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { EuiLoadingSpinner, EuiPanel, EuiSpacer, EuiLink, EuiText } from '@elastic/eui';
import { FormattedMessage } from '@kbn/i18n-react';
import * as i18n from './translations';
import { EnrichedDataRow, ThreatSummaryPanelHeader } from './threat_summary_view';
import { RiskScore } from '../../severity/common';
import type { RiskSeverity } from '../../../../../common/search_strategy';
import type { HostRisk } from '../../../../risk_score/containers';
import { RISKY_HOSTS_DOC_LINK } from '../../../../../common/constants';

const HostRiskSummaryComponent: React.FC<{
  hostRisk: HostRisk;
  originalHostRisk?: RiskSeverity;
}> = ({ hostRisk, originalHostRisk }) => {
  const currentHostRiskScore = hostRisk?.result?.[0]?.host?.risk?.calculated_level;
  return (
    <>
      <EuiPanel hasBorder paddingSize="s" grow={false}>
        <ThreatSummaryPanelHeader
          title={i18n.HOST_RISK_DATA_TITLE}
          toolTipContent={
            <FormattedMessage
              id="xpack.securitySolution.alertDetails.overview.hostDataTooltipContent"
              defaultMessage="Risk classification is displayed only when available for a host. Ensure {hostRiskScoreDocumentationLink} is enabled within your environment."
              values={{
                hostRiskScoreDocumentationLink: (
                  <EuiLink href={RISKY_HOSTS_DOC_LINK} target="_blank">
                    <FormattedMessage
                      id="xpack.securitySolution.alertDetails.overview.hostRiskScoreLink"
                      defaultMessage="Host Risk Score"
                    />
                  </EuiLink>
                ),
              }}
            />
          }
        />

        {hostRisk.loading && <EuiLoadingSpinner data-test-subj="loading" />}

        {!hostRisk.loading && (!hostRisk.isModuleEnabled || hostRisk.result?.length === 0) && (
          <>
            <EuiSpacer size="s" />
            <EuiText color="subdued" size="xs">
              {i18n.NO_HOST_RISK_DATA_DESCRIPTION}
            </EuiText>
          </>
        )}

        {hostRisk.isModuleEnabled && hostRisk.result && (
          <>
            {currentHostRiskScore && (
              <>
                <EnrichedDataRow
                  field={i18n.CURRENT_HOST_RISK_CLASSIFICATION}
                  value={<RiskScore severity={currentHostRiskScore} hideBackgroundColor />}
                />
              </>
            )}
            {originalHostRisk && currentHostRiskScore !== originalHostRisk && (
              <>
                <EnrichedDataRow
                  field={i18n.ORIGINAL_HOST_RISK_CLASSIFICATION}
                  value={<RiskScore severity={originalHostRisk} hideBackgroundColor />}
                />
              </>
            )}
          </>
        )}
      </EuiPanel>
    </>
  );
};
export const HostRiskSummary = React.memo(HostRiskSummaryComponent);
