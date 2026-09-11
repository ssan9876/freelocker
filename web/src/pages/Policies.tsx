import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError, Group, Policy } from "../api";
import { useToast } from "../components/Toast";

export function Policies() {
  const { notify } = useToast();
  const nav = useNavigate();
  const [policies, setPolicies] = useState<Policy[] | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [name, setName] = useState("");

  const load = () => api.get<Policy[]>("/api/policies").then(setPolicies).catch(() => setPolicies([]));
  useEffect(() => {
    load();
    api.get<Group[]>("/api/groups").then(setGroups).catch(() => {});
  }, []);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.post("/api/policies", { name });
      setName("");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not create policy", "error");
    }
  };

  const setMode = async (id: string, mode: string) => {
    try {
      await api.post(`/api/policies/${id}/mode`, { mode });
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not set mode", "error");
    }
  };

  const assign = async (id: string, groupId: string) => {
    if (!groupId) return;
    try {
      await api.post(`/api/policies/${id}/assign`, { group_id: groupId });
      notify("Policy assigned");
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not assign", "error");
    }
  };

  return (
    <div>
      <div className="page-head">
        <h1>Policies</h1>
      </div>
      <div className="panel" style={{ marginBottom: 20 }}>
        <p className="who" style={{ marginTop: 0, marginBottom: 10 }}>
          Policies are default-deny allowlists. New policies start in <b>audit mode</b>, which reports
          would-be blocks without blocking anything. Switch to enforce only after reviewing.
        </p>
        <form onSubmit={create}>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div>
              <label>New policy name</label>
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Baseline" />
            </div>
            <button className="primary" disabled={!name}>
              Create policy
            </button>
          </div>
        </form>
      </div>
      {!policies ? (
        <div className="spin">Loading…</div>
      ) : policies.length === 0 ? (
        <div className="empty">No policies yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Mode</th>
                <th>Assign to group</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id}>
                  <td>
                    <a onClick={() => nav(`/policies/${p.id}`)} style={{ cursor: "pointer" }}>
                      {p.name}
                    </a>
                  </td>
                  <td>
                    <select value={p.mode} onChange={(e) => setMode(p.id, e.target.value)}>
                      <option value="audit">Audit</option>
                      <option value="enforce">Enforce</option>
                    </select>
                  </td>
                  <td>
                    <select defaultValue="" onChange={(e) => assign(p.id, e.target.value)}>
                      <option value="">Choose group…</option>
                      {groups.map((g) => (
                        <option key={g.id} value={g.id}>
                          {g.name}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <button className="ghost" onClick={() => nav(`/policies/${p.id}`)}>
                      Edit rules
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
