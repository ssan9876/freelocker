import { FormEvent, useEffect, useRef, useState } from "react";
import { api, ApiError, Release } from "../api";
import { useToast } from "../components/Toast";
import { fmtDate } from "../components/util";

export function Releases() {
  const { notify } = useToast();
  const [releases, setReleases] = useState<Release[] | null>(null);
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const load = () => api.get<Release[]>("/api/releases").then(setReleases).catch(() => setReleases([]));
  useEffect(() => {
    load();
  }, []);

  const upload = async (e: FormEvent) => {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file || !version) return;
    const form = new FormData();
    form.append("version", version);
    form.append("file", file);
    setBusy(true);
    try {
      await api.upload("/api/releases", form);
      notify(`Uploaded ${version}`);
      setVersion("");
      if (fileRef.current) fileRef.current.value = "";
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Upload failed", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="page-head">
        <h1>Agent releases</h1>
      </div>
      <div className="panel" style={{ marginBottom: 20 }}>
        <h2>Upload a build</h2>
        <p className="who" style={{ marginTop: -6, marginBottom: 10 }}>
          The server signs each build; agents verify the hash and signature before installing.
        </p>
        <form onSubmit={upload}>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div>
              <label>Version</label>
              <input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="0.2.0" />
            </div>
            <div>
              <label>Agent binary</label>
              <input type="file" ref={fileRef} />
            </div>
            <button className="primary" disabled={busy || !version}>
              {busy ? "Uploading…" : "Upload"}
            </button>
          </div>
        </form>
      </div>
      {!releases ? (
        <div className="spin">Loading…</div>
      ) : releases.length === 0 ? (
        <div className="empty">No releases uploaded yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>SHA-256</th>
                <th>Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {releases.map((r) => (
                <tr key={r.version}>
                  <td className="mono">{r.version}</td>
                  <td className="mono">{r.sha256.slice(0, 24)}…</td>
                  <td>{fmtDate(r.uploaded_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
