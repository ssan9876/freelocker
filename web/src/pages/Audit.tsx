import { useEffect, useState } from "react";
import { api, Audit as Entry } from "../api";
import { ExportButton } from "../components/ExportButton";
import { fmtDate } from "../components/util";

export function Audit() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [before, setBefore] = useState<number | null>(null);
  const [more, setMore] = useState(true);
  const [loading, setLoading] = useState(false);

  const load = (cursor: number | null) => {
    setLoading(true);
    const q = cursor ? `?limit=50&before=${cursor}` : "?limit=50";
    api
      .get<Entry[]>(`/api/audit${q}`)
      .then((rows) => {
        setEntries((prev) => (cursor ? [...prev, ...rows] : rows));
        setMore(rows.length === 50);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load(null);
  }, []);

  return (
    <div>
      <div className="page-head">
        <h1>Unified Audit</h1>
        <ExportButton resource="audit" />
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Result</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td>{fmtDate(e.created_at)}</td>
                <td className="mono">{e.actor}</td>
                <td>{e.action}</td>
                <td className="mono">{e.target_type ? `${e.target_type}:${e.target_id.slice(0, 8)}` : "—"}</td>
                <td>
                  <span className={`badge ${e.result === "success" ? "ok" : "fail"}`}>{e.result}</span>
                </td>
                <td className="mono">{e.ip || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {more && (
        <div className="btn-row">
          <button
            className="ghost"
            disabled={loading}
            onClick={() => {
              const last = entries[entries.length - 1];
              if (last) {
                setBefore(last.id);
                load(last.id);
              }
            }}
          >
            {loading ? "Loading…" : "Load more"}
          </button>
          {before !== null && <span className="who" style={{ alignSelf: "center" }}>{entries.length} entries</span>}
        </div>
      )}
    </div>
  );
}
