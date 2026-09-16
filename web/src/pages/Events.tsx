import { useEffect, useState } from "react";
import { api } from "../api";
import { fmtDate } from "../components/util";

type DeviceEvent = { id: number; device_id: string; kind: string; summary: string; at: string };

const KINDS = [
  { value: "", label: "All activity" },
  { value: "process_launch", label: "Process launches" },
  { value: "logon", label: "Logons" },
  { value: "elevation", label: "Elevations" },
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
        <select aria-label="Activity kind filter" value={kind} onChange={(e) => setKind(e.target.value)}>
          {KINDS.map((k) => (
            <option key={k.value} value={k.value}>
              {k.label}
            </option>
          ))}
        </select>
      </div>
      <p className="who" style={{ marginTop: -8, marginBottom: 14 }}>
        Process launches, logons and elevations reported by agents, so you can spot anything unusual. An elevation is a process that received a full administrator token.
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
                  <td>
                    {e.kind === "elevation" ? (
                      // Badged because this is the one kind worth picking out
                      // of a feed that is otherwise mostly routine launches.
                      <span className="badge fail" title="Ran with a full administrator token">
                        Elevation
                      </span>
                    ) : e.kind === "process_launch" ? (
                      "Process"
                    ) : e.kind === "logon" ? (
                      "Logon"
                    ) : (
                      e.kind
                    )}
                  </td>
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
