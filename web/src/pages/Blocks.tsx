import { useEffect, useState } from "react";
import { api, BlockEvent } from "../api";
import { fmtDate } from "../components/util";

export function Blocks() {
  const [events, setEvents] = useState<BlockEvent[] | null>(null);

  useEffect(() => {
    const load = () => api.get<BlockEvent[]>("/api/blocks").then(setEvents).catch(() => setEvents([]));
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  return (
    <div>
      <div className="page-head">
        <h1>Blocked programs</h1>
      </div>
      <p className="who" style={{ marginTop: -8, marginBottom: 14 }}>
        Programs a policy blocked, or — in audit mode — would have blocked.
      </p>
      {!events ? (
        <div className="spin">Loading…</div>
      ) : events.length === 0 ? (
        <div className="empty">No block events reported yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Path</th>
                <th>SHA-256</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td>{fmtDate(e.at)}</td>
                  <td className="mono">{e.path || "—"}</td>
                  <td className="mono">{e.sha256 ? e.sha256.slice(0, 16) + "…" : "—"}</td>
                  <td>
                    <span className={`badge ${e.blocked ? "fail" : ""}`}>
                      {e.blocked ? "Blocked" : "Would block (audit)"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
