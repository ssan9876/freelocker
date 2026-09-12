import { FormEvent, useEffect, useState } from "react";
import { api, ApiError, Admin } from "../api";
import { useAuth } from "../auth";
import { useToast } from "../components/Toast";
import { fmtDate } from "../components/util";

export function Admins() {
  const { me } = useAuth();
  const { notify } = useToast();
  const [admins, setAdmins] = useState<Admin[] | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("readonly");

  const load = () => api.get<Admin[]>("/api/admins").then(setAdmins).catch(() => setAdmins([]));
  useEffect(() => {
    load();
  }, []);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.post("/api/admins", { email, password, role });
      setEmail("");
      setPassword("");
      notify("Admin created");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not create admin", "error");
    }
  };

  const act = async (path: string, body: unknown, done: string) => {
    try {
      await api.post(path, body);
      notify(done);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not update admin", "error");
    }
  };

  return (
    <div>
      <div className="page-head">
        <h1>Admins</h1>
      </div>
      <div className="panel" style={{ marginBottom: 20 }}>
        <h2>Add an admin</h2>
        <form onSubmit={create}>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div>
              <label>Email</label>
              <input aria-label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div>
              <label>Temporary password</label>
              <input
                aria-label="Temporary password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="12+ characters"
              />
            </div>
            <div>
              <label>Role</label>
              <select aria-label="Role" value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="readonly">Read-only</option>
                <option value="admin">Admin</option>
                <option value="owner">Owner</option>
              </select>
            </div>
            <button className="primary" disabled={!email || !password}>
              Add admin
            </button>
          </div>
        </form>
      </div>
      {!admins ? (
        <div className="spin">Loading…</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Role</th>
                <th>MFA</th>
                <th>Status</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {admins.map((a) => (
                <tr key={a.id}>
                  <td>{a.email}</td>
                  <td>
                    {a.id === me?.id ? (
                      <span className="badge role">{a.role}</span>
                    ) : (
                      <select
                        aria-label={`Role for ${a.email}`}
                        value={a.role}
                        onChange={(e) => act(`/api/admins/${a.id}/role`, { role: e.target.value }, "Role updated")}
                      >
                        <option value="readonly">Read-only</option>
                        <option value="admin">Admin</option>
                        <option value="owner">Owner</option>
                      </select>
                    )}
                  </td>
                  <td>{a.mfa_enrolled ? "Enrolled" : "—"}</td>
                  <td>{a.disabled ? <span className="badge fail">Disabled</span> : <span className="badge ok">Active</span>}</td>
                  <td>{fmtDate(a.created_at)}</td>
                  <td>
                    {a.id !== me?.id &&
                      (a.disabled ? (
                        <button className="ghost" onClick={() => act(`/api/admins/${a.id}/enable`, undefined, "Admin enabled")}>
                          Enable
                        </button>
                      ) : (
                        <button className="ghost" onClick={() => act(`/api/admins/${a.id}/disable`, undefined, "Admin disabled")}>
                          Disable
                        </button>
                      ))}
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
