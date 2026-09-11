# Sub-project #3 — Telemetry & Monitoring Implementation Plan

> REQUIRED SUB-SKILL: superpowers:executing-plans. TDD, commit per task.

**Goal:** Each agent reports resource metrics (CPU, memory, disk) on an interval; the server stores them, evaluates threshold alert rules, and raises alerts; the console shows per-device metrics and an alerts list. This is the "send metrics back so we can make sure nothing weird is going on" capability.

**Architecture:** Agent collects a `metrics.Sample` and reports it via a new `ReportMetrics` Agent RPC. Server stores samples, and an alert engine evaluates enabled rules against the latest samples per device, raising/auto-resolving alerts. Metrics stored as plain rows (TimescaleDB hypertable optional; deferred). Everything server-side and the collector's math are unit-tested; live Windows perf counters are exercised on the dev machine (read-only, safe).

**Spec:** design doc roadmap item 3. **Depends on:** #1, #2 merged.

## Global constraints
- tenant_id on every table; store calls take tenantID first.
- Metrics are percentages 0–100 (float). Alert rule: metric in {cpu,mem,disk}, op in {gt,lt}, threshold, duration_seconds (sustained). Alerts auto-resolve when the condition clears.
- Windows collector uses GlobalMemoryStatusEx + GetDiskFreeSpaceEx + a short CPU sample; portable stub returns zeros so tests/off-Windows build.

## Tasks
1. `internal/agent/metrics`: `Sample{CPUPct,MemPct,DiskPct float64}`, `Collect() (Sample, error)` (windows real, other stub). Test: sample fields in [0,100] on the collector; portable stub returns zeroed sample without error.
2. store `metrics.go` (migration 0004): `device_metrics(tenant_id,device_id,at,cpu_pct,mem_pct,disk_pct)`; `alert_rules(id,tenant_id,name,metric,op,threshold,duration_seconds,enabled)`; `alerts(id,tenant_id,device_id,rule_id,metric,message,at,resolved_at)`. RecordMetrics, ListMetrics(device,since), CRUD rules, RaiseAlert, ResolveAlert, ListAlerts, OpenAlertFor(device,rule). Tests: record+list, rule CRUD, alert raise/resolve idempotence.
3. `internal/server/alerting`: `Service{Store}`; `Evaluate(ctx, tenantID, deviceID, sample, now)` → for each enabled rule, track breach start; raise when sustained ≥ duration, resolve when cleared. Breach state persisted in `alerts` (open alert = currently breaching). Simplify: raise immediately when threshold crossed if duration==0, else require prior sample breaching for duration (track via alert.at). Tests: gt/lt raise, resolve on clear, no duplicate open alert.
4. proto `ReportMetrics(MetricsRequest{cpu_pct,mem_pct,disk_pct}) returns Ack`; agentapi handler records metrics + runs alerting; runner reports metrics on a ticker. Test: enrolled client reports metrics → stored; breaching sample raises an alert.
5. httpapi: GET /api/devices/{id}/metrics?since=, alert rules CRUD (admin), GET /api/alerts. Tests: metrics query, rule create/list, alerts list, RBAC.
6. console: device metrics sparkline/chart section + Alerts nav page. Build.
7. finalize: vet, full test, build, commit.

## Deferred
- TimescaleDB hypertables; process/logon/network event streams (fold into a later expansion); anomaly detection beyond thresholds.
