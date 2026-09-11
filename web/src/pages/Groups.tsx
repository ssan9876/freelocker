import { FormEvent, useEffect, useState } from "react";
import { api, ApiError, Group } from "../api";
import { useToast } from "../components/Toast";

type Controls = { usb_storage_blocked: boolean };

export function Groups() {
  const { notify } = useToast();
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [controls, setControls] = useState<Record<string, boolean>>({});
  const [name, setName] = useState("");

  const load = () =>
    api
      .get<Group[]>("/api/groups")
      .then((gs) => {
        setGroups(gs);
        gs.forEach((g) =>
          api
            .get<Controls>(`/api/groups/${g.id}/controls`)
            .then((c) => setControls((prev) => ({ ...prev, [g.id]: c.usb_storage_blocked })))
            .catch(() => {})
        );
      })
      .catch(() => setGroups([]));
  useEffect(() => {
    load();
  }, []);

  const toggleUSB = async (id: string, blocked: boolean) => {
    try {
      await api.post(`/api/groups/${id}/controls`, { usb_storage_blocked: blocked });
      setControls((prev) => ({ ...prev, [id]: blocked }));
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not update controls", "error");
    }
  };

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
                <th>USB storage</th>
                <th className="mono">ID</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => (
                <tr key={g.id}>
                  <td>{g.name}</td>
                  <td>
                    <select
                      value={controls[g.id] ? "block" : "allow"}
                      onChange={(e) => toggleUSB(g.id, e.target.value === "block")}
                    >
                      <option value="allow">Allowed</option>
                      <option value="block">Blocked</option>
                    </select>
                  </td>
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
