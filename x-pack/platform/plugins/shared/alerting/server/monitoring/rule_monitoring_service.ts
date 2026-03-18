/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { getDefaultMonitoring, getExecutionDurationPercentiles } from '../lib/monitoring';
import type { RuleMonitoring, RuleMonitoringHistory, PublicRuleMonitoringService } from '../types';
import type { GapReason } from '../../common/constants';

export class RuleMonitoringService {
  private monitoring: RuleMonitoring = getDefaultMonitoring(new Date().toISOString());

  public setLastRunMetricsDuration(duration: number) {
    this.monitoring.run.last_run.metrics.duration = duration;
  }

  public setMonitoring(monitoringFromSO: RuleMonitoring | undefined) {
    if (monitoringFromSO) {
      this.monitoring = monitoringFromSO;
    }
  }

  public getMonitoring(): RuleMonitoring {
    return this.monitoring;
  }

  public addHistory({
    duration,
    hasError = true,
    runDate,
  }: {
    duration: number | undefined;
    hasError: boolean;
    runDate: Date;
  }) {
    const date = runDate ?? new Date();
    const monitoringHistory: RuleMonitoringHistory = {
      success: true,
      timestamp: date.getTime(),
    };
    if (null != duration) {
      monitoringHistory.duration = duration;
      this.setLastRunMetricsDuration(duration);
    }
    if (hasError) {
      monitoringHistory.success = false;
    }
    this.monitoring.run.last_run.timestamp = date.toISOString();
    this.monitoring.run.history.push(monitoringHistory);
    this.monitoring.run.calculated_metrics = {
      success_ratio: this.buildExecutionSuccessRatio(),
      ...this.buildExecutionDurationPercentiles(),
    };
  }

  public getLastRunMetricsSetters(): PublicRuleMonitoringService {
    return {
      setLastRunMetricsTotalSearchDurationMs:
        this.setLastRunMetricsTotalSearchDurationMs.bind(this),
      setLastRunMetricsTotalIndexingDurationMs:
        this.setLastRunMetricsTotalIndexingDurationMs.bind(this),
      setLastRunMetricsTotalAlertsDetected: this.setLastRunMetricsTotalAlertsDetected.bind(this),
      setLastRunMetricsTotalAlertsCreated: this.setLastRunMetricsTotalAlertsCreated.bind(this),
      setLastRunMetricsGapDurationS: this.setLastRunMetricsGapDurationS.bind(this),
      setLastRunMetricsGap: this.setLastRunMetricsGap.bind(this),
    };
  }

  private setLastRunMetricsTotalSearchDurationMs(totalSearchDurationMs: number) {
    this.monitoring.run.last_run.metrics.total_search_duration_ms = totalSearchDurationMs;
  }

  private setLastRunMetricsTotalIndexingDurationMs(totalIndexingDurationMs: number) {
    this.monitoring.run.last_run.metrics.total_indexing_duration_ms = totalIndexingDurationMs;
  }

  private setLastRunMetricsTotalAlertsDetected(totalAlertDetected: number) {
    this.monitoring.run.last_run.metrics.total_alerts_detected = totalAlertDetected;
  }

  private setLastRunMetricsTotalAlertsCreated(totalAlertCreated: number) {
    this.monitoring.run.last_run.metrics.total_alerts_created = totalAlertCreated;
  }

  private setLastRunMetricsGapDurationS(gapDurationS: number) {
    this.monitoring.run.last_run.metrics.gap_duration_s = gapDurationS;
  }

  private setLastRunMetricsGap(
    gap: { range: { gte: string; lte: string }; reason?: GapReason } | null
  ) {
    this.monitoring.run.last_run.metrics.gap_range = gap?.range ?? null;
    // Only write gap_reason when explicitly provided to avoid writing the field
    // before the feature flag is enabled (intermediate schema-only release).
    // Clear it if a previous run had set it to avoid stale values.
    if (gap?.reason) {
      this.monitoring.run.last_run.metrics.gap_reason = gap.reason as { type: string };
    } else if (this.monitoring.run.last_run.metrics.gap_reason) {
      this.monitoring.run.last_run.metrics.gap_reason = null;
    }
  }

  private buildExecutionSuccessRatio() {
    const { history } = this.monitoring.run;
    return history.filter(({ success }) => success).length / history.length;
  }

  private buildExecutionDurationPercentiles = () => {
    const { history } = this.monitoring.run;
    return getExecutionDurationPercentiles(history);
  };
}
