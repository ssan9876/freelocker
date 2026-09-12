import { useEffect, useState } from "react";
import { api } from "../api";
import { fmtDate } from "../components/util";

type DeviceEvent = { id: number; device_id: string; kind: string; summary: string; at: string };

const KINDS = [
  { value: "", label: "All activity" },
  { value: "process_launch", label: "Process launches" },
  { value: "logon", label: "Logons" },
];

export function Events() {
  const [events, setEvents] = useState<DeviceEvent[] | null>(null);
  const [kind, setKind] = useState("");

  useEffect(() => {
    const load = () => {
      const q = kind ? `?kind=${kind}` : "";
      api.get<DeviceEvent[]>(`/api/events${q}`).then(setEvents).catch(() => setEvents([]));
    };
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [kind]);

  return (
    <div>
      <div className="page-head">
        <h1>Activity</h1>
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          {KINDS.map((k) => (
            <option key={k.value} value={k.value}>
              {k.label}
            </option>
          ))}
        </select>
      </div>
      <p className="who" style={{ marginTop: -8, marginBottom: 14 }}>
        Process launches and logons reported by agents, so you can spot anything unusual.
      </p>
      {!events ? (
        <div className="spin">Loading…</div>
      ) : events.length === 0 ? (
        <div className="empty">No activity reported yet. (Process-creation auditing must be enabled on the endpoint.)</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Kind</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td>{fmtDate(e.at)}</td>
                  <td>{e.kind === "process_launch" ? "Process" : e.kind === "logon" ? "Logon" : e.kind}</td>
                  <td className="mono">{e.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
