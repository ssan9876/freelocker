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

  const load = () => {
    const q = status ? `?status=${status}` : "";
    api.get<Device[]>(`/api/devices${q}`).then(setDevices).catch(() => setDevices([]));
  };

  useEffect(() => {
    api.get<Group[]>("/api/groups").then(setGroups).catch(() => setGroups([]));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  const groupName = (id: string | null) => groups.find((g) => g.id === id)?.name ?? "—";

  return (
    <div>
      <div className="page-head">
        <h1>Devices</h1>
        <ExportButton resource="devices" />
      </div>
      <div className="toolbar">
        <label style={{ margin: 0 }}>Status</label>
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s === "" ? "All" : s.replace("_", " ")}
            </option>
          ))}
        </select>
        <span className="who">{devices ? `${devices.length} shown` : ""}</span>
      </div>
      {!devices ? (
        <div className="spin">Loading…</div>
      ) : devices.length === 0 ? (
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
              {devices.map((d) => (
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
