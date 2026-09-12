import { FormEvent, useEffect, useState } from "react";
import { api, ApiError, Group } from "../api";
import { Confirm } from "../components/Confirm";
import { useToast } from "../components/Toast";

type Controls = { usb_storage_blocked: boolean; network_blocked: boolean; elevation_blocked: boolean };

const NO_CONTROLS: Controls = { usb_storage_blocked: false, network_blocked: false, elevation_blocked: false };

export function Groups() {
  const { notify } = useToast();
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [controls, setControls] = useState<Record<string, Controls>>({});
  const [name, setName] = useState("");
  const [editing, setEditing] = useState<{ id: string; name: string } | null>(null);
  const [deleting, setDeleting] = useState<Group | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () =>
    api
      .get<Group[]>("/api/groups")
      .then((gs) => {
        setGroups(gs);
        gs.forEach((g) =>
          api
            .get<Controls>(`/api/groups/${g.id}/controls`)
            .then((c) => setControls((prev) => ({ ...prev, [g.id]: c })))
            .catch(() => {})
        );
      })
      .catch(() => setGroups([]));
  useEffect(() => {
    load();
  }, []);

  const setControl = async (id: string, patch: Partial<Controls>) => {
    const next = { ...(controls[id] ?? NO_CONTROLS), ...patch };
    try {
      await api.post(`/api/groups/${id}/controls`, next);
      setControls((prev) => ({ ...prev, [id]: next }));
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

  const rename = async (e: FormEvent) => {
    e.preventDefault();
    if (!editing) return;
    try {
      await api.patch(`/api/groups/${editing.id}`, { name: editing.name });
      setEditing(null);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not rename group", "error");
    }
  };

  const remove = async () => {
    if (!deleting) return;
    setBusy(true);
    try {
      await api.del(`/api/groups/${deleting.id}`);
      notify("Group deleted");
      setDeleting(null);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not delete group", "error");
    } finally {
      setBusy(false);
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
              <input
                aria-label="New group name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Workstations"
              />
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
                <th>Network</th>
                <th>Elevation</th>
                <th className="mono">ID</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => {
                const c = controls[g.id] ?? NO_CONTROLS;
                const toggle = (label: string, blocked: boolean, patch: (v: boolean) => Partial<Controls>) => (
                  <select value={blocked ? "block" : "allow"} onChange={(e) => setControl(g.id, patch(e.target.value === "block"))} aria-label={label}>
                    <option value="allow">Allowed</option>
                    <option value="block">Blocked</option>
                  </select>
                );
                return (
                  <tr key={g.id}>
                    <td>
                      {editing?.id === g.id ? (
                        <form onSubmit={rename} style={{ display: "flex", gap: 6 }}>
                          <input
                            autoFocus
                            aria-label="Group name"
                            value={editing.name}
                            onChange={(e) => setEditing({ id: g.id, name: e.target.value })}
                          />
                          <button className="primary" disabled={!editing.name.trim()}>
                            Save
                          </button>
                          <button type="button" className="ghost" onClick={() => setEditing(null)}>
                            Cancel
                          </button>
                        </form>
                      ) : (
                        g.name
                      )}
                    </td>
                    <td>{toggle("USB storage", c.usb_storage_blocked, (v) => ({ usb_storage_blocked: v }))}</td>
                    <td>{toggle("Network", c.network_blocked, (v) => ({ network_blocked: v }))}</td>
                    <td>{toggle("Elevation", c.elevation_blocked, (v) => ({ elevation_blocked: v }))}</td>
                    <td className="mono">{g.id}</td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      <button className="ghost" onClick={() => setEditing({ id: g.id, name: g.name })}>
                        Rename
                      </button>
                      <button className="ghost" onClick={() => setDeleting(g)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {deleting && (
        <Confirm
          title={`Delete group “${deleting.name}”?`}
          confirmLabel="Delete"
          danger
          busy={busy}
          onConfirm={remove}
          onCancel={() => setDeleting(null)}
        >
          <p>
            Its devices and install tokens become ungrouped. Those devices lose this group's policy
            assignments and device controls.
          </p>
        </Confirm>
      )}
    </div>
  );
}
