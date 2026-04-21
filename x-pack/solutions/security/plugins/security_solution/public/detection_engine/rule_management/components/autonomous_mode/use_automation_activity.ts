/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useCallback, useEffect, useState } from 'react';
import { INTERNAL_AUTOMATION_ACTIVITY_URL } from '../../../../../common/constants';
import { useHttp } from '../../../../common/lib/kibana';

export interface ActivityItem {
  executionId: string;
  workflowId?: string;
  workflowName?: string;
  status?: string;
  startedAt?: string;
  finishedAt?: string;
  createdBy?: string;
  ruleId?: string;
}

interface ActivityResponse {
  results: ActivityItem[];
  total: number;
}

export const useAutomationActivity = (enabled: boolean) => {
  const http = useHttp();
  const [items, setItems] = useState<ActivityItem[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await http.get<ActivityResponse>(INTERNAL_AUTOMATION_ACTIVITY_URL, {
        version: '1',
      });
      setItems(res.results);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [http]);

  useEffect(() => {
    if (enabled) refresh();
  }, [enabled, refresh]);

  return { items, total, isLoading, error, refresh };
};
