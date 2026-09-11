import { FormEvent, useEffect, useState } from "react";
import { api, ApiError, Group } from "../api";
import { useToast } from "../components/Toast";

export function Groups() {
  const { notify } = useToast();
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [name, setName] = useState("");

  const load = () => api.get<Group[]>("/api/groups").then(setGroups).catch(() => setGroups([]));
  useEffect(() => {
    load();
  }, []);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.post("/api/groups", { name });
      setName("");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not create group", "error");
    }
  };

  return (
    <div>
      <div className="page-head">
        <h1>Groups</h1>
      </div>
      <div className="panel" style={{ marginBottom: 20 }}>
        <form onSubmit={create}>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div>
              <label>New group name</label>
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Workstations" />
            </div>
            <button className="primary" disabled={!name}>
              Add group
            </button>
          </div>
        </form>
      </div>
      {!groups ? (
        <div className="spin">Loading…</div>
      ) : groups.length === 0 ? (
        <div className="empty">No groups yet. Groups let a token assign new devices automatically.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th className="mono">ID</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => (
                <tr key={g.id}>
                  <td>{g.name}</td>
                  <td className="mono">{g.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
