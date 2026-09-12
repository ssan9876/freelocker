import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  api,
  ApiError,
  Command,
  ControlKey,
  DeviceControlsView,
  DeviceDetail as Detail,
  Group,
  MetricSample,
  Observation,
  Policy,
} from "../api";
import { useAuth } from "../auth";
import { StatusDot } from "../components/StatusDot";
import { Confirm } from "../components/Confirm";
import { Sparkline } from "../components/Sparkline";
import { useToast } from "../components/Toast";
import { fmtDate, fmtUptime, timeAgo } from "../components/util";

// metricSeries returns oldest→newest values for a sparkline (the API
// returns newest first).
function metricSeries(samples: MetricSample[], key: "cpu_pct" | "mem_pct" | "disk_pct"): number[] {
  return samples.map((s) => s[key]).reverse();
}

const COMMANDS: { type: string; label: string }[] = [
  { type: "ping", label: "Ping" },
  { type: "refresh_inventory", label: "Refresh inventory" },
  { type: "rotate_certificate", label: "Rotate certificate" },
  { type: "update_agent", label: "Update agent" },
];

const CONTROL_LABELS: { key: ControlKey; label: string }[] = [
  { key: "usb_storage_blocked", label: "USB storage" },
  { key: "network_blocked", label: "Network" },
  { key: "elevation_blocked", label: "Elevation" },
];

export function DeviceDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const { notify } = useToast();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [cmds, setCmds] = useState<Command[]>([]);
  const [obs, setObs] = useState<Observation[]>([]);
  const [samples, setSamples] = useState<MetricSample[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const { me } = useAuth();
  const canEdit = me?.role !== "readonly";
  const [ctl, setCtl] = useState<DeviceControlsView | null>(null);
  const [promoteTo, setPromoteTo] = useState("");
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = () => {
    api.get<Detail>(`/api/devices/${id}`).then(setDetail).catch(() => setDetail(null));
    api.get<Command[]>(`/api/devices/${id}/commands?limit=25`).then(setCmds).catch(() => {});
    api.get<Observation[]>(`/api/devices/${id}/observations?limit=100`).then(setObs).catch(() => {});
    api.get<MetricSample[]>(`/api/devices/${id}/metrics?limit=120`).then(setSamples).catch(() => {});
    api.get<DeviceControlsView>(`/api/devices/${id}/controls`).then(setCtl).catch(() => {});
  };

  useEffect(() => {
    api.get<Policy[]>("/api/policies").then(setPolicies).catch(() => {});
    api.get<Group[]>("/api/groups").then(setGroups).catch(() => {});
  }, []);

  const moveToGroup = async (groupId: string) => {
    try {
      await api.post(`/api/devices/${id}/group`, { group_id: groupId || null });
      notify(groupId ? "Moved to group" : "Removed from group");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not move device", "error");
    }
  };

  const setOverride = async (key: ControlKey, value: "inherit" | "allow" | "block") => {
    if (!ctl) return;
    const next = { ...ctl.overrides, [key]: value === "inherit" ? null : value === "block" };
    try {
      await api.post(`/api/devices/${id}/controls`, next);
      notify("Device controls updated");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not update controls", "error");
    }
  };

  const promote = async (sha256: string, description: string) => {
    if (!promoteTo) {
      notify("Choose a policy first", "error");
      return;
    }
    try {
      await api.post("/api/observations/promote", { policy_id: promoteTo, sha256, description });
      notify("Added to policy");
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not add rule", "error");
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const issue = async (type: string) => {
    try {
      await api.post(`/api/devices/${id}/commands`, { type });
      notify(`${type.replace("_", " ")} queued`);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Command failed", "error");
    }
  };

  const revoke = async () => {
    setBusy(true);
    try {
      await api.post(`/api/devices/${id}/revoke`);
      notify("Device revoked");
      setConfirmRevoke(false);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Revoke failed", "error");
    } finally {
      setBusy(false);
    }
  };

  if (!detail) return <div className="spin">Loading…</div>;
  const d = detail.device;

  return (
    <div>
      <div className="page-head">
        <h1>
          <a onClick={() => nav("/devices")} style={{ cursor: "pointer" }}>
            Devices
          </a>{" "}
          / <span className="mono">{d.hostname}</span>
        </h1>
        <StatusDot status={d.status} />
      </div>

      <div className="detail-grid">
        <div className="panel">
          <h2>Inventory</h2>
          <dl className="facts">
            <dt>Device ID</dt>
            <dd>{d.id}</dd>
            <dt>Hostname</dt>
            <dd>{d.hostname}</dd>
            <dt>Group</dt>
            <dd>
              <select aria-label="Group" value={d.group_id ?? ""} onChange={(e) => moveToGroup(e.target.value)}>
                <option value="">No group</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </dd>
            <dt>OS build</dt>
            <dd>{d.os_build || "—"}</dd>
            <dt>Agent version</dt>
            <dd>{d.agent_version || "—"}</dd>
            <dt>IP addresses</dt>
            <dd>{d.ip_addresses?.join(", ") || "—"}</dd>
            <dt>Logged-on user</dt>
            <dd>{d.logged_on_user || "—"}</dd>
            <dt>Uptime</dt>
            <dd>{fmtUptime(d.uptime_seconds)}</dd>
            <dt>Last seen</dt>
            <dd>{timeAgo(d.last_seen_at)}</dd>
            <dt>Cert expires</dt>
            <dd>{fmtDate(d.cert_expires_at)}</dd>
            <dt>Enrolled</dt>
            <dd>{fmtDate(d.enrolled_at)}</dd>
            {detail.uninstall_code && (
              <>
                <dt>Uninstall code</dt>
                <dd>{detail.uninstall_code}</dd>
              </>
            )}
          </dl>
        </div>

        <div className="panel">
          <h2>Actions</h2>
          <div className="btn-row" style={{ marginTop: 0 }}>
            {COMMANDS.map((c) => (
              <button key={c.type} onClick={() => issue(c.type)} disabled={d.status === "revoked"}>
                {c.label}
              </button>
            ))}
          </div>
          <div className="btn-row">
            <button
              className="danger"
              onClick={() => setConfirmRevoke(true)}
              disabled={d.status === "revoked"}
            >
              Revoke device
            </button>
          </div>
          {d.status === "revoked" && (
            <p className="err" style={{ color: "var(--muted)" }}>
              This device is revoked. It can no longer connect.
            </p>
          )}
        </div>
      </div>

      {ctl && (
        <div className="panel" style={{ marginTop: 20 }}>
          <h2>Device controls</h2>
          <p className="who" style={{ marginTop: -8 }}>
            Override this device's group. Inherit follows the group; Allow or Block applies to this device only.
          </p>
          <div className="table-wrap" style={{ border: "none" }}>
            <table>
              <thead>
                <tr>
                  <th>Control</th>
                  <th>Setting</th>
                  <th>Effective</th>
                </tr>
              </thead>
              <tbody>
                {CONTROL_LABELS.map(({ key, label }) => {
                  const o = ctl.overrides[key];
                  const setting = o === null ? "inherit" : o ? "block" : "allow";
                  const groupName = groups.find((g) => g.id === d.group_id)?.name;
                  const inherited = `Inherits: ${ctl.group[key] ? "Blocked" : "Allowed"} (${
                    groupName ? `group ${groupName}` : "no group"
                  })`;
                  return (
                    <tr key={key}>
                      <td>{label}</td>
                      <td>
                        {canEdit ? (
                          <select
                            aria-label={`${label} override`}
                            value={setting}
                            onChange={(e) => setOverride(key, e.target.value as "inherit" | "allow" | "block")}
                          >
                            <option value="inherit">{inherited}</option>
                            <option value="allow">Allow</option>
                            <option value="block">Block</option>
                          </select>
                        ) : setting === "inherit" ? (
                          inherited
                        ) : (
                          setting
                        )}
                      </td>
                      <td>
                        <span className={`badge ${ctl.effective[key] ? "fail" : "ok"}`}>
                          {ctl.effective[key] ? "Blocked" : "Allowed"}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="panel" style={{ marginTop: 20 }}>
        <h2>Recent commands</h2>
        {cmds.length === 0 ? (
          <div className="empty">No commands issued yet.</div>
        ) : (
          <div className="table-wrap" style={{ border: "none" }}>
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>State</th>
                  <th>Result</th>
                  <th>Issued</th>
                </tr>
              </thead>
              <tbody>
                {cmds.map((c) => (
                  <tr key={c.id}>
                    <td>{c.type.replace("_", " ")}</td>
                    <td>
                      <span className={`badge ${c.state === "succeeded" ? "ok" : c.state === "failed" ? "fail" : ""}`}>
                        {c.state}
                      </span>
                    </td>
                    <td className="mono">{c.result || "—"}</td>
                    <td>{timeAgo(c.issued_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel" style={{ marginTop: 20 }}>
        <h2>Resource metrics</h2>
        {samples.length === 0 ? (
          <div className="empty">No metrics reported yet.</div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 20 }}>
            <Sparkline label="CPU" values={metricSeries(samples, "cpu_pct")} />
            <Sparkline label="Memory" values={metricSeries(samples, "mem_pct")} />
            <Sparkline label="Disk" values={metricSeries(samples, "disk_pct")} />
          </div>
        )}
      </div>

      <div className="panel" style={{ marginTop: 20 }}>
        <h2>Observed applications</h2>
        <p className="who" style={{ marginTop: -8 }}>
          Programs this device has run (learning mode). Add one to a policy to allow it by hash.
        </p>
        {obs.length === 0 ? (
          <div className="empty">Nothing observed yet.</div>
        ) : (
          <>
            <div className="toolbar">
              <label style={{ margin: 0 }}>Add to policy</label>
              <select value={promoteTo} onChange={(e) => setPromoteTo(e.target.value)}>
                <option value="">Choose policy…</option>
                {policies.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="table-wrap" style={{ border: "none" }}>
              <table>
                <thead>
                  <tr>
                    <th>Path</th>
                    <th>SHA-256</th>
                    <th>Count</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {obs.map((o) => (
                    <tr key={o.sha256 + o.path}>
                      <td className="mono">{o.path}</td>
                      <td className="mono">{o.sha256.slice(0, 16)}…</td>
                      <td className="mono">{o.count}</td>
                      <td>
                        <button className="ghost" onClick={() => promote(o.sha256, o.path)}>
                          Add as rule
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      {confirmRevoke && (
        <Confirm
          title="Revoke this device?"
          confirmLabel="Revoke"
          danger
          busy={busy}
          onConfirm={revoke}
          onCancel={() => setConfirmRevoke(false)}
        >
          <p>
            <span className="mono">{d.hostname}</span> will be disconnected immediately and blocked from
            reconnecting. This cannot be undone.
          </p>
        </Confirm>
      )}
    </div>
  );
}
