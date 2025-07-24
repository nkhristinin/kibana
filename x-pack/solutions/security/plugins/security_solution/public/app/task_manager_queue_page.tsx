/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useEffect, useState, useRef, useCallback } from 'react';
import {
  EuiBasicTable,
  EuiPage,
  EuiPageBody,
  EuiPageHeader,
  EuiPageHeaderSection,
  EuiTitle,
  EuiSpacer,
} from '@elastic/eui';
import { useKibana } from '@kbn/kibana-react-plugin/public';

interface Task {
  id: string;
  runAt: string;
  scheduledAt: string;
  taskType: string;
  status: string;
}

export const TaskManagerQueuePage: React.FC = () => {
  const { services } = useKibana();
  const http = services.http;
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const pollingRef = useRef<NodeJS.Timeout | null>(null);
  const [now, setNow] = useState<Date>(new Date());

  // Real-time clock updater
  useEffect(() => {
    const interval = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  // Fetch tasks function
  const fetchTasks = useCallback(async () => {
    setLoading(true);
    try {
      const data = await http.get<{ tasks: Task[] }>('/api/task_manager/queue');
      setTasks(data.tasks || []);
    } catch (e) {
      setTasks([]);
    }
    setLoading(false);
  }, [http]);

  useEffect(() => {
    fetchTasks();
    pollingRef.current = setInterval(fetchTasks, 100); //  polling
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [fetchTasks]);

  // Format time as HH:mm:ss
  const formatTime = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const columns = [
    // { field: 'id', name: 'ID', sortable: true },
    { field: 'taskType', name: 'Task Type', sortable: true },
    { field: 'status', name: 'Status', sortable: true },
    {
      field: 'scheduledAt',
      name: 'Scheduled At',
      render: (date: string) => formatTime(date),
    },
    { field: 'runAt', name: 'Run At', render: (date: string) => formatTime(date) },
  ];

  // Define your color map at the top of the component
  const TASK_TYPE_COLORS: Record<string, string> = {
    // light orange/yellow
    'ad_hoc_run-backfill': '#FFF7E6',

    // light blue
    'alerting:siem.queryRule': '#E6F7FF',
    // etc.
  };

  // Highlight specific task types and add border for running/overdue
  const rowProps = (task: Task) => {
    const color = TASK_TYPE_COLORS[task.taskType] ?? 'white';
    const nowTime = Date.now();
    const scheduledAtTime = new Date(task.scheduledAt).getTime();
    const runAtTime = new Date(task.runAt).getTime();
    const isRunning = task.status === 'running';
    const inFuture = scheduledAtTime > nowTime || runAtTime > nowTime;

    let border = '';
    let opacity = '1';
    if (isRunning) {
      border = '3px solid #21c21c'; // Green border
    }
    if (inFuture) {
      opacity = '0.5'; // Red border
    }

    return {
      style: {
        background: color,
        border,
        opacity,
      },
      'data-test-subj': `highlighted-task-row-${task.taskType}`,
    };
  };

  // --- Task summary calculations ---
  // Count by type and status
  const typeStatusCounts = tasks.reduce<Record<string, Record<string, number>>>((acc, task) => {
    if (!acc[task.taskType]) acc[task.taskType] = {};
    acc[task.taskType][task.status] = (acc[task.taskType][task.status] || 0) + 1;
    return acc;
  }, {});
  // Total by type
  const typeTotals = tasks.reduce<Record<string, number>>((acc, task) => {
    acc[task.taskType] = (acc[task.taskType] || 0) + 1;
    return acc;
  }, {});

  // Only show these types in the summary
  const summaryTypes = ['ad_hoc_run-backfill', 'alerting:siem.queryRule'];
  const filteredTypeTotals = Object.entries(typeTotals).filter(([type]) =>
    summaryTypes.includes(type)
  );
  // List of all statuses (for header display)
  const allStatuses = Array.from(new Set(tasks.map((t) => t.status)));
  // --- End summary calculations ---

  // --- Fixed summary bar at the bottom ---
  const summaryBar = (
    <div
      style={{
        position: 'fixed',
        left: 0,
        right: 0,
        bottom: 0,
        background: '#f5f7fa',
        borderTop: '2px solid #d3dae6',
        padding: '18px 32px 18px 32px',
        zIndex: 100,
        fontSize: 22,
        fontWeight: 600,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        boxShadow: '0 -2px 8px rgba(0,0,0,0.04)',
      }}
    >
      <div>
        {filteredTypeTotals.map(([type, total]) => (
          <span key={type} style={{ marginRight: 32 }}>
            <span style={{ fontWeight: 700 }}>{type}</span>
            {': '}
            <span>
              {'Total '}
              {total}
            </span>
            {allStatuses.map((status) =>
              typeStatusCounts[type][status] ? (
                <span key={status} style={{ marginLeft: 16 }}>
                  {status.charAt(0).toUpperCase() + status.slice(1)}{' '}
                  {typeStatusCounts[type][status]}
                </span>
              ) : null
            )}
          </span>
        ))}
      </div>
      <div style={{ fontWeight: 700, letterSpacing: 1, color: '#0077cc' }}>
        {now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
      </div>
    </div>
  );
  // --- End summary bar ---

  return (
    <EuiPage>
      <EuiPageBody>
        <div style={{ padding: '0 32px', paddingBottom: 80 /* space for summary bar */ }}>
          <EuiPageHeader>
            <EuiPageHeaderSection>
              <EuiTitle size="l">
                <h1>{'Task Manager Queue'}</h1>
              </EuiTitle>
            </EuiPageHeaderSection>
          </EuiPageHeader>
          <EuiSpacer size="l" />
          <EuiBasicTable items={tasks} columns={columns} rowHeader="id" rowProps={rowProps} />
        </div>
        {summaryBar}
      </EuiPageBody>
    </EuiPage>
  );
};
