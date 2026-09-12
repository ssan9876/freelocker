import { FormEvent, useEffect, useState } from "react";
import { api, Alert, AlertRule, ApiError } from "../api";
import { useToast } from "../components/Toast";
import { fmtDate } from "../components/util";

export function Alerts() {
  const { notify } = useToast();
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [name, setName] = useState("");
  const [metric, setMetric] = useState<"cpu" | "mem" | "disk">("cpu");
  const [op, setOp] = useState<"gt" | "lt">("gt");
  const [threshold, setThreshold] = useState("90");
  const [editing, setEditing] = useState<AlertRule | null>(null);

  const load = () => {
    api.get<Alert[]>("/api/alerts").then(setAlerts).catch(() => setAlerts([]));
    api.get<AlertRule[]>("/api/alert-rules").then(setRules).catch(() => {});
  };
  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const createRule = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.post("/api/alert-rules", { name, metric, op, threshold: Number(threshold) });
      setName("");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not create rule", "error");
    }
  };

  const update = async (r: AlertRule) => {
    try {
      const { id, ...body } = r;
      await api.patch(`/api/alert-rules/${id}`, body);
      setEditing(null);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not update rule", "error");
    }
  };

  const del = async (id: string) => {
    try {
      await api.del(`/api/alert-rules/${id}`);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not delete rule", "error");
    }
  };

  return (
    <div>
      <div className="page-head">
        <h1>Alerts</h1>
      </div>

      <div className="panel" style={{ marginBottom: 20 }}>
        <h2>Alert rules</h2>
        <form onSubmit={createRule}>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div>
              <label>Name</label>
              <input aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="High CPU" />
            </div>
            <div>
              <label>Metric</label>
              <select aria-label="Metric" value={metric} onChange={(e) => setMetric(e.target.value as typeof metric)}>
                <option value="cpu">CPU</option>
                <option value="mem">Memory</option>
                <option value="disk">Disk</option>
              </select>
            </div>
            <div>
              <label>Condition</label>
              <select aria-label="Condition" value={op} onChange={(e) => setOp(e.target.value as typeof op)}>
                <option value="gt">above</option>
                <option value="lt">below</option>
              </select>
            </div>
            <div>
              <label>Threshold %</label>
              <input
                aria-label="Threshold %"
                value={threshold}
                onChange={(e) => setThreshold(e.target.value.replace(/\D/g, ""))}
              />
            </div>
            <button className="primary" disabled={!name}>
              Add rule
            </button>
          </div>
        </form>
        {rules.length > 0 && (
          <div className="table-wrap" style={{ border: "none", marginTop: 8 }}>
            <table>
              <tbody>
                {rules.map((r) =>
                  editing?.id === r.id ? (
                    <tr key={r.id}>
                      <td>
                        <input aria-label="Rule name" value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
                      </td>
                      <td className="mono" style={{ whiteSpace: "nowrap" }}>
                        {r.metric} {r.op === "gt" ? ">" : "<"}{" "}
                        <input
                          aria-label="Threshold"
                          style={{ width: 60 }}
                          value={editing.threshold}
                          onChange={(e) => setEditing({ ...editing, threshold: Number(e.target.value.replace(/\D/g, "")) })}
                        />
                        % for{" "}
                        <input
                          aria-label="Duration seconds"
                          style={{ width: 60 }}
                          value={editing.duration_seconds}
                          onChange={(e) => setEditing({ ...editing, duration_seconds: Number(e.target.value.replace(/\D/g, "")) })}
                        />
                        s
                      </td>
                      <td style={{ whiteSpace: "nowrap" }}>
                        <button className="primary" disabled={!editing.name.trim()} onClick={() => update(editing)}>
                          Save
                        </button>
                        <button className="ghost" onClick={() => setEditing(null)}>
                          Cancel
                        </button>
                      </td>
                    </tr>
                  ) : (
                    <tr key={r.id}>
                      <td>{r.name}</td>
                      <td className="mono">
                        {r.metric} {r.op === "gt" ? ">" : "<"} {r.threshold}%
                        {r.duration_seconds > 0 && ` for ${r.duration_seconds}s`}
                      </td>
                      <td style={{ whiteSpace: "nowrap" }}>
                        <select
                          aria-label={`Rule ${r.name} state`}
                          value={r.enabled ? "on" : "off"}
                          onChange={(e) => update({ ...r, enabled: e.target.value === "on" })}
                        >
                          <option value="on">Enabled</option>
                          <option value="off">Disabled</option>
                        </select>
                        <button className="ghost" onClick={() => setEditing(r)}>
                          Edit
                        </button>
                        <button className="ghost" onClick={() => del(r.id)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  )
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {!alerts ? (
        <div className="spin">Loading…</div>
      ) : alerts.length === 0 ? (
        <div className="empty">No alerts. Define rules above; breaches will appear here.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Message</th>
                <th>Raised</th>
                <th>Resolved</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((al) => (
                <tr key={al.id}>
                  <td>
                    <span className={`badge ${al.resolved_at ? "" : "fail"}`}>
                      {al.resolved_at ? "Resolved" : "Active"}
                    </span>
                  </td>
                  <td>{al.message}</td>
                  <td>{fmtDate(al.at)}</td>
                  <td>{al.resolved_at ? fmtDate(al.resolved_at) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
