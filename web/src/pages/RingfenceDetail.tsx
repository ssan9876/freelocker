import { FormEvent, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, ApiError, Group, RingfenceDetail as Detail } from "../api";
import { ASR_RULES } from "../asr";
import { Confirm } from "../components/Confirm";
import { useToast } from "../components/Toast";


export function RingfenceDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const { notify } = useToast();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  // Defaults to checked: an unchecked program is completely inert (no
  // firewall rule AND excluded from the WFP match set), which is a dead row
  // for the natural "add the program, then decide" flow. Matches the
  // schema's DEFAULT true (0020_ringfencing.sql) and the API default.
  const [networkBlocked, setNetworkBlocked] = useState(true);
  const [note, setNote] = useState("");
  const [assignGroup, setAssignGroup] = useState("");
  const [confirmEnforce, setConfirmEnforce] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [busy, setBusy] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const load = () =>
    api
      .get<Detail>(`/api/ringfences/${id}`)
      .then((d) => {
        setDetail(d);
        setName(d.ringfence.name);
      })
      .catch(() => setDetail(null));

  useEffect(() => {
    load();
    api.get<Group[]>("/api/groups").then(setGroups).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const rename = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.patch(`/api/ringfences/${id}`, { name });
      notify("Ringfence renamed");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not rename ringfence", "error");
    }
  };

  const applyMode = async (mode: "audit" | "enforce") => {
    setBusy(true);
    try {
      await api.post(`/api/ringfences/${id}/mode`, { mode });
      notify(mode === "enforce" ? "Ringfence switched to enforce" : "Ringfence switched to audit");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not change mode", "error");
    } finally {
      setBusy(false);
      setConfirmEnforce(false);
    }
  };

  const onModeSelect = (mode: string) => {
    if (!detail) return;
    if (mode === "enforce" && detail.ringfence.mode !== "enforce") {
      setConfirmEnforce(true);
    } else if (mode === "audit" && detail.ringfence.mode !== "audit") {
      applyMode("audit");
    }
  };

  const addProgram = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.post(`/api/ringfences/${id}/programs`, { path, network_blocked: networkBlocked, note });
      setPath("");
      setNetworkBlocked(true);
      setNote("");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not add program", "error");
    }
  };

  const deleteProgram = async (programId: string) => {
    try {
      await api.del(`/api/ringfences/${id}/programs/${programId}`);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not remove program", "error");
    }
  };

  const setProtection = async (asrRule: string, action: "off" | "audit" | "block") => {
    try {
      await api.put(`/api/ringfences/${id}/protections`, { asr_rule: asrRule, action });
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not update protection", "error");
    }
  };

  const assign = async () => {
    if (!assignGroup) return;
    try {
      await api.post(`/api/ringfences/${id}/assign`, { group_id: assignGroup });
      notify("Ringfence assigned to group");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not assign ringfence", "error");
    }
  };

  const unassign = async () => {
    if (!assignGroup) return;
    try {
      // The server is authoritative on what is currently assigned: pass
      // this ringfence's own id so a group that has since been reassigned
      // to a different ringfence is not silently detached from that one
      // instead (409 Conflict), surfaced through the normal notify path.
      await api.del(`/api/groups/${assignGroup}/ringfence?ringfence_id=${id}`);
      notify("Ringfence unassigned from group");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not unassign ringfence", "error");
    }
  };

  const deleteRingfence = async () => {
    setDeleteBusy(true);
    try {
      await api.del(`/api/ringfences/${id}`);
      notify("Ringfence deleted");
      nav("/ringfences");
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not delete ringfence", "error");
      setDeleteBusy(false);
      setConfirmDelete(false);
    }
  };

  if (!detail) return <div className="spin">Loading…</div>;
  const mode = detail.ringfence.mode;
  const protectionFor = (ruleId: string) => detail.protections.find((p) => p.asr_rule === ruleId)?.action ?? "off";

  return (
    <div>
      <div className="page-head">
        <h1>
          <a onClick={() => nav("/ringfences")} style={{ cursor: "pointer" }}>
            Ringfences
          </a>{" "}
          / {detail.ringfence.name}
        </h1>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className={`badge ${mode === "enforce" ? "fail" : "role"}`}>{mode}</span>
          <button className="ghost" aria-label="Delete ringfence" onClick={() => setConfirmDelete(true)}>
            Delete ringfence
          </button>
        </div>
      </div>

      <div className="detail-grid">
        <div className="panel">
          <h2>Rename</h2>
          <form onSubmit={rename}>
            <div className="toolbar" style={{ alignItems: "flex-end" }}>
              <div style={{ flex: 1, minWidth: 200 }}>
                <label>Ringfence name</label>
                <input aria-label="Ringfence name" value={name} onChange={(e) => setName(e.target.value)} />
              </div>
              <button className="primary" disabled={!name.trim()}>
                Save
              </button>
            </div>
          </form>
        </div>

        <div className="panel">
          <h2>Mode</h2>
          <p className="who" style={{ marginTop: -8 }}>
            Audit reports what would be blocked without blocking anything. Enforce actually blocks network
            access and applies the ASR rules below — switch only after reviewing audit events.
          </p>
          <label>Ringfence mode</label>
          <select aria-label="Ringfence mode" value={mode} onChange={(e) => onModeSelect(e.target.value)}>
            <option value="audit">Audit</option>
            <option value="enforce">Enforce</option>
          </select>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 20 }}>
        <h2>Add program</h2>
        <form onSubmit={addProgram}>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div style={{ flex: 1, minWidth: 260 }}>
              <label>Program path</label>
              <input
                aria-label="Program path"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder={`C:\\Program Files\\App\\app.exe`}
              />
            </div>
            <div>
              <label>
                <input
                  aria-label="Network blocked"
                  type="checkbox"
                  checked={networkBlocked}
                  onChange={(e) => setNetworkBlocked(e.target.checked)}
                  style={{ marginRight: 6 }}
                />
                Network blocked
              </label>
            </div>
            <div>
              <label>Note</label>
              <input aria-label="Program note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="optional" />
            </div>
            <button className="primary" disabled={!path}>
              Add program
            </button>
          </div>
        </form>
      </div>

      {detail.programs.length === 0 ? (
        <div className="empty">No programs in this ringfence yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th>Network</th>
                <th>Note</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {detail.programs.map((p) => (
                <tr key={p.id}>
                  <td className="mono">{p.path}</td>
                  <td>
                    <span className={`badge ${p.network_blocked ? "fail" : "ok"}`}>
                      {p.network_blocked ? "Blocked" : "Allowed"}
                    </span>
                  </td>
                  <td>{p.note || "—"}</td>
                  <td>
                    <button className="ghost" onClick={() => deleteProgram(p.id)}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="panel" style={{ marginTop: 20 }}>
        <h2>Attack surface reduction</h2>
        <p className="who" style={{ marginTop: -8 }}>
          Each rule can be off, reported in audit only, or blocked. These apply through Windows Defender —
          if Defender is inactive on a device, enforce does nothing there.
        </p>
        <div className="table-wrap" style={{ border: "none" }}>
          <table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {ASR_RULES.map((rule) => (
                <tr key={rule.id}>
                  <td>{rule.description}</td>
                  <td>
                    <select
                      aria-label={rule.description}
                      value={protectionFor(rule.id)}
                      onChange={(e) => setProtection(rule.id, e.target.value as "off" | "audit" | "block")}
                    >
                      <option value="off">Off</option>
                      <option value="audit">Audit</option>
                      <option value="block">Block</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 20 }}>
        <h2>Group assignment</h2>
        <p className="who" style={{ marginTop: -8 }}>
          A group has at most one ringfence. Assigning replaces any ringfence already assigned to that group.
        </p>
        <div className="toolbar" style={{ alignItems: "flex-end" }}>
          <div>
            <label>Assign to group</label>
            <select aria-label="Assign to group" value={assignGroup} onChange={(e) => setAssignGroup(e.target.value)}>
              <option value="">Choose group…</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
          <button className="primary" disabled={!assignGroup} onClick={assign}>
            Assign
          </button>
          <button className="ghost" disabled={!assignGroup} onClick={unassign}>
            Unassign
          </button>
        </div>
      </div>

      {confirmEnforce && (
        <Confirm
          title="Switch to enforce?"
          confirmLabel="Switch to enforce"
          danger
          busy={busy}
          onConfirm={() => applyMode("enforce")}
          onCancel={() => setConfirmEnforce(false)}
        >
          <p>
            Devices with this ringfence assigned will start blocking network access and applying the ASR
            rules set to <b>Block</b>. Review the audit events first if you have not already.
          </p>
        </Confirm>
      )}

      {confirmDelete && (
        <Confirm
          title={`Delete ringfence “${detail.ringfence.name}”?`}
          confirmLabel="Delete"
          danger
          busy={deleteBusy}
          onConfirm={deleteRingfence}
          onCancel={() => setConfirmDelete(false)}
        >
          <p>
            This unassigns it from every group and permanently deletes its programs and protections. This
            cannot be undone.
          </p>
        </Confirm>
      )}
    </div>
  );
}
