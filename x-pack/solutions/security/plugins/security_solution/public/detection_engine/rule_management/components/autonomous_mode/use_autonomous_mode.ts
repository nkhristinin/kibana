/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useCallback, useEffect, useState } from 'react';
import { INTERNAL_AUTONOMOUS_MODE_URL } from '../../../../../common/constants';
import { useHttp } from '../../../../common/lib/kibana';

export type AutonomousMode = 'auto' | 'suggest';

export interface AutonomousModeSettings {
  mode: AutonomousMode;
  monitoredWorkflowIds: string[];
}

interface UseAutonomousModeResult {
  settings: AutonomousModeSettings | null;
  isLoading: boolean;
  isSaving: boolean;
  error: Error | null;
  save: (next: Partial<AutonomousModeSettings>) => Promise<void>;
  refresh: () => Promise<void>;
}

export const useAutonomousMode = (): UseAutonomousModeResult => {
  const http = useHttp();
  const [settings, setSettings] = useState<AutonomousModeSettings | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await http.get<AutonomousModeSettings>(INTERNAL_AUTONOMOUS_MODE_URL, {
        version: '1',
      });
      setSettings(res);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [http]);

  const save = useCallback(
    async (next: Partial<AutonomousModeSettings>) => {
      setIsSaving(true);
      setError(null);
      try {
        const res = await http.put<AutonomousModeSettings>(INTERNAL_AUTONOMOUS_MODE_URL, {
          version: '1',
          body: JSON.stringify(next),
        });
        setSettings(res);
      } catch (err) {
        setError(err instanceof Error ? err : new Error(String(err)));
      } finally {
        setIsSaving(false);
      }
    },
    [http]
  );

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { settings, isLoading, isSaving, error, save, refresh };
};
