import { FormEvent, useEffect, useState } from "react";
import { api, ApiError, Tenant } from "../api";
import { useAuth } from "../auth";
import { Confirm } from "../components/Confirm";
import { useToast } from "../components/Toast";
import { fmtDate } from "../components/util";

// Provider-only view: create and list the tenants on this deployment. Each new
// tenant gets its own CA and a login-ready owner. Ordinary admins never see it.
export function Tenants() {
  const { notify } = useToast();
  const [tenants, setTenants] = useState<Tenant[] | null>(null);
  const [orgName, setOrgName] = useState("");
  const [ownerEmail, setOwnerEmail] = useState("");
  const [ownerPassword, setOwnerPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<{ id: string; name: string } | null>(null);
  const [suspending, setSuspending] = useState<Tenant | null>(null);
  const { me } = useAuth();
  // The provider's own tenant is the oldest one (created at setup); the
  // server refuses to suspend it, so the console hides the control.
  const ownTenantId = tenants?.[0]?.id;

  const patch = async (id: string, body: { name?: string; suspended?: boolean }, done: string) => {
    try {
      await api.patch(`/api/provider/tenants/${id}`, body);
      notify(done);
      setEditing(null);
      setSuspending(null);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not update tenant", "error");
    }
  };

  const load = () =>
    api.get<Tenant[]>("/api/provider/tenants").then(setTenants).catch(() => setTenants([]));
  useEffect(() => {
    load();
  }, []);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post("/api/provider/tenants", {
        org_name: orgName,
        owner_email: ownerEmail,
        owner_password: ownerPassword,
      });
      setOrgName("");
      setOwnerEmail("");
      setOwnerPassword("");
      notify("Tenant created");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not create tenant", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="page-head">
        <h1>Tenants</h1>
      </div>
      <div className="panel" style={{ marginBottom: 20 }}>
        <h2>Create a tenant</h2>
        <p style={{ marginTop: 0, color: "var(--muted)", fontSize: 13 }}>
          A new tenant gets its own certificate authority. Its owner signs in with the email below.
        </p>
        <form onSubmit={create}>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div>
              <label>Organization name</label>
              <input aria-label="Organization name" value={orgName} onChange={(e) => setOrgName(e.target.value)} />
            </div>
            <div>
              <label>Owner email</label>
              <input
                aria-label="Owner email"
                type="email"
                value={ownerEmail}
                onChange={(e) => setOwnerEmail(e.target.value)}
              />
            </div>
            <div>
              <label>Owner password</label>
              <input
                aria-label="Owner password"
                type="password"
                value={ownerPassword}
                onChange={(e) => setOwnerPassword(e.target.value)}
                placeholder="12+ characters"
              />
            </div>
            <button className="primary" disabled={busy || !orgName || !ownerEmail || !ownerPassword}>
              Create tenant
            </button>
          </div>
        </form>
      </div>
      {!tenants ? (
        <div className="spin">Loading…</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Organization</th>
                <th>Status</th>
                <th>Tenant ID</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {tenants.map((t) => (
                <tr key={t.id}>
                  <td>
                    {editing?.id === t.id ? (
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          patch(t.id, { name: editing.name }, "Tenant renamed");
                        }}
                        style={{ display: "flex", gap: 6 }}
                      >
                        <input
                          autoFocus
                          aria-label="Organization name"
                          value={editing.name}
                          onChange={(e) => setEditing({ id: t.id, name: e.target.value })}
                        />
                        <button className="primary" disabled={!editing.name.trim()}>
                          Save
                        </button>
                        <button type="button" className="ghost" onClick={() => setEditing(null)}>
                          Cancel
                        </button>
                      </form>
                    ) : (
                      t.name
                    )}
                  </td>
                  <td>
                    {t.suspended ? <span className="badge fail">Suspended</span> : <span className="badge ok">Active</span>}
                  </td>
                  <td>
                    <code>{t.id}</code>
                  </td>
                  <td>{fmtDate(t.created_at)}</td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    <button className="ghost" onClick={() => setEditing({ id: t.id, name: t.name })}>
                      Rename
                    </button>
                    {t.id !== ownTenantId &&
                      me?.provider &&
                      (t.suspended ? (
                        <button className="ghost" onClick={() => patch(t.id, { suspended: false }, "Tenant restored")}>
                          Unsuspend
                        </button>
                      ) : (
                        <button className="ghost" onClick={() => setSuspending(t)}>
                          Suspend
                        </button>
                      ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {suspending && (
        <Confirm
          title={`Suspend “${suspending.name}”?`}
          confirmLabel="Suspend"
          danger
          busy={false}
          onConfirm={() => patch(suspending.id, { suspended: true }, "Tenant suspended")}
          onCancel={() => setSuspending(null)}
        >
          <p>
            Its admins are signed out and can't sign in, its agents are refused until you unsuspend, and
            its install tokens stop enrolling devices. No data is deleted; endpoints keep their last
            policy.
          </p>
        </Confirm>
      )}
    </div>
  );
}
