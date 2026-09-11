import { FormEvent, useState } from "react";
import { api, ApiError } from "../api";

export function Setup({ onDone }: { onDone: () => void }) {
  const [org, setOrg] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      await api.post("/api/setup", { org_name: org, email, password });
      onDone();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Setup failed");
      setBusy(false);
    }
  };

  return (
    <div className="auth-wrap">
      <form className="auth-card" onSubmit={submit}>
        <h1 className="brand">
          <span className="lock">▣</span> FreeLocker
        </h1>
        <p className="auth-sub">Create your organization and the first owner account.</p>
        <label>Organization name</label>
        <input value={org} onChange={(e) => setOrg(e.target.value)} autoFocus />
        <label>Owner email</label>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <label>Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="At least 12 characters"
        />
        {err && <p className="err">{err}</p>}
        <div className="btn-row">
          <button className="primary" disabled={busy}>
            {busy ? "Creating…" : "Create organization"}
          </button>
        </div>
      </form>
    </div>
  );
}
