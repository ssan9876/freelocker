import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError, Ringfence, RingfenceDetail } from "../api";
import { useToast } from "../components/Toast";

export function Ringfences() {
  const { notify } = useToast();
  const nav = useNavigate();
  const [ringfences, setRingfences] = useState<Ringfence[] | null>(null);
  const [programCounts, setProgramCounts] = useState<Record<string, number>>({});
  const [name, setName] = useState("");

  const load = () =>
    api
      .get<Ringfence[]>("/api/ringfences")
      .then((rfs) => {
        setRingfences(rfs);
        rfs.forEach((rf) =>
          api
            .get<RingfenceDetail>(`/api/ringfences/${rf.id}`)
            .then((d) => setProgramCounts((prev) => ({ ...prev, [rf.id]: d.programs.length })))
            .catch(() => {})
        );
      })
      .catch(() => setRingfences([]));

  useEffect(() => {
    load();
  }, []);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.post("/api/ringfences", { name });
      setName("");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not create ringfence", "error");
    }
  };

  return (
    <div>
      <div className="page-head">
        <h1>Ringfencing</h1>
      </div>
      <div className="panel" style={{ marginBottom: 20 }}>
        <p className="who" style={{ marginTop: 0, marginBottom: 10 }}>
          Ringfences constrain what an allowed application may do — block its network access, or stop
          Office/scripting from spawning it. New ringfences start in <b>audit mode</b>, which reports what
          would be blocked without blocking anything. Switch to enforce from the ringfence's detail page
          only after reviewing.
        </p>
        <form onSubmit={create}>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div>
              <label>Ringfence name</label>
              <input
                aria-label="Ringfence name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Browsers"
              />
            </div>
            <button className="primary" disabled={!name}>
              Create ringfence
            </button>
          </div>
        </form>
      </div>
      {!ringfences ? (
        <div className="spin">Loading…</div>
      ) : ringfences.length === 0 ? (
        <div className="empty">No ringfences yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Mode</th>
                <th>Programs</th>
                <th>Applied to</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {ringfences.map((rf) => (
                <tr key={rf.id}>
                  <td>
                    <a onClick={() => nav(`/ringfences/${rf.id}`)} style={{ cursor: "pointer" }}>
                      {rf.name}
                    </a>
                  </td>
                  <td>
                    <span className={`badge ${rf.mode === "enforce" ? "fail" : "role"}`}>{rf.mode}</span>
                  </td>
                  <td className="mono">{programCounts[rf.id] ?? "—"}</td>
                  <td>
                    {rf.groups.length === 0 ? (
                      <span className="who">Not assigned</span>
                    ) : (
                      rf.groups.join(", ")
                    )}
                  </td>
                  <td>
                    <button className="ghost" onClick={() => nav(`/ringfences/${rf.id}`)}>
                      Edit
                    </button>
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
