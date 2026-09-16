import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, Device, Group } from "../api";
import { ExportButton } from "../components/ExportButton";
import { StatusDot } from "../components/StatusDot";
import { timeAgo } from "../components/util";

const STATUSES = ["", "online", "offline", "unexpected_offline", "never_seen", "revoked"];

export function Devices() {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [status, setStatus] = useState("");
  const nav = useNavigate();

  // Fetched UNFILTERED, then filtered here for the table. The fleet summary
  // above must describe the whole fleet, not the current filter -- computing
  // it from a filtered list would show "2 offline" while the filter said
  // "online only", which reads as a bug in the product.
  const load = () => {
    api.get<Device[]>("/api/devices").then(setDevices).catch(() => setDevices([]));
  };

  useEffect(() => {
    api.get<Group[]>("/api/groups").then(setGroups).catch(() => setGroups([]));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const shown = (devices ?? []).filter((d) => !status || d.status === status);
  const count = (s: Device["status"]) => (devices ?? []).filter((d) => d.status === s).length;
  const offline = count("offline") + count("unexpected_offline");

  const groupName = (id: string | null) => groups.find((g) => g.id === id)?.name ?? "—";

  return (
    <div>
      <div className="page-head">
        <h1>Devices</h1>
        <ExportButton resource="devices" />
      </div>
      {devices && devices.length > 0 && (
        <div className="stats">
          <div className="stat">
            <div className="stat-label">Devices</div>
            <div className="stat-value">{devices.length}</div>
          </div>
          <div className="stat">
            <div className="stat-label">Online</div>
            <div className="stat-value ok">{count("online")}</div>
          </div>
          <div className="stat">
            <div className="stat-label">Offline</div>
            <div className={`stat-value ${count("unexpected_offline") > 0 ? "warn" : ""}`}>{offline}</div>
          </div>
          <div className="stat">
            <div className="stat-label">Revoked</div>
            <div className={`stat-value ${count("revoked") > 0 ? "bad" : ""}`}>{count("revoked")}</div>
          </div>
        </div>
      )}
      <div className="toolbar">
        <label style={{ margin: 0 }}>Status</label>
        <select aria-label="Status filter" value={status} onChange={(e) => setStatus(e.target.value)}>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s === "" ? "All" : s.replace("_", " ")}
            </option>
          ))}
        </select>
        <span className="who">{devices ? `${shown.length} shown` : ""}</span>
      </div>
      {!devices ? (
        <div className="spin">Loading…</div>
      ) : shown.length === 0 ? (
        <div className="empty">No devices match. Enroll a PC with an install token to see it here.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Status</th>
                <th>Agent</th>
                <th>Group</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((d) => (
                <tr key={d.id} className="row-link" onClick={() => nav(`/devices/${d.id}`)}>
                  <td className="mono">{d.hostname}</td>
                  <td>
                    <StatusDot status={d.status} />
                  </td>
                  <td className="mono">{d.agent_version || "—"}</td>
                  <td>{groupName(d.group_id)}</td>
                  <td>{timeAgo(d.last_seen_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
