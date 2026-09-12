import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError, LoginResult } from "../api";
import { useAuth } from "../auth";

export function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const { onLogin } = useAuth();
  const nav = useNavigate();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      const r = await api.post<LoginResult>("/api/login", { email, password });
      sessionStorage.setItem("fl-mfa-enrolled", r.mfa_enrolled ? "1" : "0");
      onLogin(r.csrf_token);
      nav("/mfa", { replace: true });
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Login failed");
      setBusy(false);
    }
  };

  return (
    <div className="auth-wrap">
      <form className="auth-card" onSubmit={submit}>
        <h1 className="brand">
          <span className="lock">▣</span> FreeLocker
        </h1>
        <p className="auth-sub">Sign in to the management console.</p>
        <label>Email</label>
        <input aria-label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
        <label>Password</label>
        <input aria-label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        {err && <p className="err">{err}</p>}
        <div className="btn-row">
          <button className="primary" disabled={busy}>
            {busy ? "Signing in…" : "Continue"}
          </button>
        </div>
      </form>
    </div>
  );
}
