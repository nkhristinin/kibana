/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useCallback, useEffect, useState } from 'react';
import { INTERNAL_AUTOMATION_ACTIVITY_URL } from '../../../../../common/constants';
import { useHttp } from '../../../../common/lib/kibana';

export interface PendingApproval {
  executionId: string;
  workflowId?: string;
  workflowName?: string;
  startedAt?: string;
  ruleId?: string;
}

/**
 * A rendered section in the expand row. One per recognized step in the
 * execution. The UI picks a renderer per `kind`.
 */
export type ExecutionSection =
  | {
      kind: 'agent_reasoning';
      stepId: string;
      reasoning: string;
      summary: string | null;
    }
  | {
      kind: 'proposed_changes';
      stepId: string;
      proposedChanges: Record<string, unknown>;
      summary: string | null;
    }
  | {
      kind: 'applied_changes';
      stepId: string;
      appliedChanges: Record<string, unknown>;
      summary: string | null;
    }
  | {
      kind: 'approval';
      stepId: string;
      approved: boolean;
      at?: string;
    }
  | {
      kind: 'failure';
      stepId: string;
      error: string;
    };

export interface ExecutionDetails {
  overallStatus: string | null;
  sections: ExecutionSection[];
}

interface ActivityResponseItem {
  executionId: string;
  workflowId?: string;
  workflowName?: string;
  status?: string;
  startedAt?: string;
  ruleId?: string;
}

interface ActivityResponse {
  results: ActivityResponseItem[];
  total: number;
}

interface StepExecution {
  stepId: string;
  stepType?: string;
  status: string;
  output?: unknown;
  error?: { message?: string } | string;
  startedAt?: string;
  finishedAt?: string;
}

interface ExecutionDetailResponse {
  id: string;
  status: string;
  workflowId?: string;
  stepExecutions?: StepExecution[];
  context?: Record<string, unknown>;
}

const AGENT_STEP_TYPE = 'ai.agent';
const APPLY_STEP_TYPE = 'security.rules.applyFix';
const PROPOSE_STEP_TYPE = 'security.rules.proposeFix';
const WAIT_FOR_INPUT_STEP_TYPE = 'waitForInput';

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Parse an ai.agent step's output into a reasoning + optional proposed changes.
 * The contract is: agent returns a single JSON object
 *   { reasoning, proposedChanges, summary }
 * If the agent breaks the contract (plain text), raw text becomes reasoning.
 */
const parseAgentOutput = (
  output: unknown
): {
  reasoning: string | null;
  proposedChanges: Record<string, unknown> | null;
  summary: string | null;
} => {
  if (!output) return { reasoning: null, proposedChanges: null, summary: null };

  const text =
    typeof output === 'string'
      ? output
      : isObject(output)
      ? (output.message as string | undefined) ??
        (output.result as string | undefined) ??
        (output.content as string | undefined) ??
        JSON.stringify(output, null, 2)
      : String(output);

  let parsed: Record<string, unknown> | null = null;
  try {
    const v = JSON.parse(text.trim());
    if (isObject(v)) parsed = v;
  } catch {
    // leave parsed null
  }

  if (!parsed) {
    return { reasoning: text, proposedChanges: null, summary: null };
  }

  const reasoning = typeof parsed.reasoning === 'string' ? (parsed.reasoning as string) : text;
  const proposedChanges = isObject(parsed.proposedChanges)
    ? (parsed.proposedChanges as Record<string, unknown>)
    : null;
  const summary = typeof parsed.summary === 'string' ? (parsed.summary as string) : null;

  return { reasoning, proposedChanges, summary };
};

const buildSections = (stepExecutions: StepExecution[]): ExecutionSection[] => {
  const sections: ExecutionSection[] = [];

  for (const step of stepExecutions) {
    // Agent step (propose) — produces reasoning + proposed changes via JSON contract.
    if (step.stepType === AGENT_STEP_TYPE) {
      const { reasoning, proposedChanges, summary } = parseAgentOutput(step.output);
      if (reasoning) {
        sections.push({
          kind: 'agent_reasoning',
          stepId: step.stepId,
          reasoning,
          summary,
        });
      }
      if (proposedChanges) {
        sections.push({
          kind: 'proposed_changes',
          stepId: step.stepId,
          proposedChanges,
          summary,
        });
      }
    }

    // Future dedicated proposal step.
    if (step.stepType === PROPOSE_STEP_TYPE && isObject(step.output)) {
      const proposedChanges = isObject(step.output.proposedChanges)
        ? (step.output.proposedChanges as Record<string, unknown>)
        : null;
      const reasoning = typeof step.output.reasoning === 'string' ? step.output.reasoning : null;
      const summary = typeof step.output.summary === 'string' ? step.output.summary : null;
      if (reasoning) {
        sections.push({ kind: 'agent_reasoning', stepId: step.stepId, reasoning, summary });
      }
      if (proposedChanges) {
        sections.push({
          kind: 'proposed_changes',
          stepId: step.stepId,
          proposedChanges,
          summary,
        });
      }
    }

    // Approval decision from waitForInput.
    if (step.stepType === WAIT_FOR_INPUT_STEP_TYPE && isObject(step.output)) {
      if (typeof step.output.approved === 'boolean') {
        sections.push({
          kind: 'approval',
          stepId: step.stepId,
          approved: step.output.approved,
          at: step.finishedAt,
        });
      }
    }

    // Deterministic apply step.
    if (step.stepType === APPLY_STEP_TYPE && isObject(step.output)) {
      const appliedChanges = isObject(step.output.appliedChanges)
        ? (step.output.appliedChanges as Record<string, unknown>)
        : null;
      const summary = typeof step.output.summary === 'string' ? step.output.summary : null;
      if (appliedChanges) {
        sections.push({
          kind: 'applied_changes',
          stepId: step.stepId,
          appliedChanges,
          summary,
        });
      }
    }

    // Failed steps of any type.
    if (step.status === 'failed') {
      const message =
        typeof step.error === 'string'
          ? step.error
          : step.error && typeof step.error.message === 'string'
          ? step.error.message
          : 'Step failed';
      sections.push({ kind: 'failure', stepId: step.stepId, error: message });
    }
  }

  return sections;
};

export const usePendingApprovals = (
  _unused?: string[]
): {
  approvals: PendingApproval[];
  isLoading: boolean;
  error: Error | null;
  refresh: () => Promise<void>;
  resume: (executionId: string, approved: boolean) => Promise<void>;
  fetchDetails: (executionId: string) => Promise<ExecutionDetails>;
} => {
  const http = useHttp();
  const [approvals, setApprovals] = useState<PendingApproval[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await http.get<ActivityResponse>(INTERNAL_AUTOMATION_ACTIVITY_URL, {
        version: '1',
        query: { statuses: 'waiting_for_input' },
      });
      setApprovals(
        res.results.map<PendingApproval>((r) => ({
          executionId: r.executionId,
          workflowId: r.workflowId,
          workflowName: r.workflowName,
          startedAt: r.startedAt,
          ruleId: r.ruleId,
        }))
      );
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [http]);

  const resume = useCallback(
    async (executionId: string, approved: boolean) => {
      await http.post(`/api/workflows/executions/${encodeURIComponent(executionId)}/resume`, {
        body: JSON.stringify({ input: { approved } }),
      });
      await refresh();
    },
    [http, refresh]
  );

  const fetchDetails = useCallback(
    async (executionId: string): Promise<ExecutionDetails> => {
      const res = await http.get<ExecutionDetailResponse>(
        `/api/workflows/executions/${encodeURIComponent(executionId)}`,
        { query: { includeOutput: true, includeInput: true } }
      );
      return {
        overallStatus: res.status ?? null,
        sections: buildSections(res.stepExecutions ?? []),
      };
    },
    [http]
  );

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { approvals, isLoading, error, refresh, resume, fetchDetails };
};
