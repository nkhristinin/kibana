/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiRadioGroup,
  EuiSpacer,
  EuiText,
} from '@elastic/eui';
import { useAutonomousMode } from './use_autonomous_mode';
import type { AutonomousMode } from './use_autonomous_mode';

interface Props {
  onClose: () => void;
}

const modeOptions = [
  { id: 'suggest', label: 'Suggestion mode — propose fixes and wait for approval' },
  { id: 'auto', label: 'Autonomous mode — apply proposed fixes automatically' },
];

export const AutonomousModeSettingsModal: React.FC<Props> = ({ onClose }) => {
  const { settings, isLoading, isSaving, error, save } = useAutonomousMode();

  const handleModeChange = (id: string) => {
    save({ mode: id as AutonomousMode });
  };

  return (
    <EuiModal onClose={onClose} data-test-subj="autonomous-mode-settings-modal">
      <EuiModalHeader>
        <EuiModalHeaderTitle>Detection automation settings</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        <EuiText size="s">
          <p>
            Controls how this space handles automated rule fix workflows. Applies to all
            rules. Workflows tagged <code>detection-engine</code> are automatically
            monitored for pending approvals and activity.
          </p>
        </EuiText>
        <EuiSpacer size="m" />
        {isLoading && <EuiLoadingSpinner size="m" />}
        {error && (
          <>
            <EuiCallOut color="danger" title="Failed to load/save settings">
              {error.message}
            </EuiCallOut>
            <EuiSpacer size="m" />
          </>
        )}
        {settings !== null && (
          <EuiFormRow label="Automation mode" fullWidth>
            <EuiRadioGroup
              options={modeOptions}
              idSelected={settings.mode}
              onChange={handleModeChange}
              name="autonomous-mode"
              data-test-subj="autonomous-mode-radio-group"
            />
          </EuiFormRow>
        )}
        {isSaving && (
          <>
            <EuiSpacer size="s" />
            <EuiText size="xs" color="subdued">
              Saving…
            </EuiText>
          </>
        )}
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={onClose}>Close</EuiButtonEmpty>
        <EuiButton onClick={onClose} fill>
          Done
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
};
