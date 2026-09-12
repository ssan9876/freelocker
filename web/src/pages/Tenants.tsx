import { FormEvent, useEffect, useState } from "react";
import { api, ApiError, Tenant } from "../api";
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
              <input value={orgName} onChange={(e) => setOrgName(e.target.value)} />
            </div>
            <div>
              <label>Owner email</label>
              <input
                type="email"
                value={ownerEmail}
                onChange={(e) => setOwnerEmail(e.target.value)}
              />
            </div>
            <div>
              <label>Owner password</label>
              <input
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
                <th>Tenant ID</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {tenants.map((t) => (
                <tr key={t.id}>
                  <td>{t.name}</td>
                  <td>
                    <code>{t.id}</code>
                  </td>
                  <td>{fmtDate(t.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
