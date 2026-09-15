import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, Group, Release, Rollout, RolloutDetail } from "../api";
import { useToast } from "../components/Toast";
import { fmtDate } from "../components/util";

const OPEN = (r: Rollout) => r.state === "active" || r.state === "paused";

export function Releases() {
  const { notify } = useToast();
  const [releases, setReleases] = useState<Release[] | null>(null);
  const [rollouts, setRollouts] = useState<Rollout[] | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const load = useCallback(() => {
    api.get<Release[]>("/api/releases").then(setReleases).catch(() => setReleases([]));
    api.get<Rollout[]>("/api/rollouts").then(setRollouts).catch(() => setRollouts([]));
    api.get<Group[]>("/api/groups").then(setGroups).catch(() => setGroups([]));
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const open = rollouts?.find(OPEN) ?? null;
  // Poll while a rollout is open so progress moves without a reload.
  useEffect(() => {
    if (!open) return;
    const t = setInterval(() => api.get<Rollout[]>("/api/rollouts").then(setRollouts).catch(() => {}), 10_000);
    return () => clearInterval(t);
  }, [open?.id]);

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
              <input aria-label="Release version" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="0.2.0" />
            </div>
            <div>
              <label>Agent binary</label>
              <input aria-label="Agent binary" type="file" ref={fileRef} />
            </div>
            <button className="primary" disabled={busy || !version}>
              {busy ? "Uploading…" : "Upload"}
            </button>
          </div>
        </form>
      </div>

      <h2>Rollouts</h2>
      {!rollouts ? (
        <div className="spin">Loading…</div>
      ) : open ? (
        <RolloutCard rollout={open} releases={releases ?? []} groups={groups} onChange={load} />
      ) : (
        <div className="empty">No rollout in progress.</div>
      )}
      {rollouts && rollouts.some((r) => !OPEN(r)) && (
        <div className="table-wrap" style={{ marginTop: 12, marginBottom: 20 }}>
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>State</th>
                <th>Updated</th>
                <th>Failed</th>
                <th>Finished</th>
              </tr>
            </thead>
            <tbody>
              {rollouts.filter((r) => !OPEN(r)).map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.version}</td>
                  <td>{r.state}</td>
                  <td>{r.summary.updated}</td>
                  <td>{r.summary.failed}</td>
                  <td>{r.finished_at ? fmtDate(r.finished_at) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2 style={{ marginTop: 20 }}>Uploaded builds</h2>
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
                <th></th>
              </tr>
            </thead>
            <tbody>
              {releases.map((r) => (
                <ReleaseRow key={r.version} release={r} groups={groups} disabled={!!open} onStarted={load} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ReleaseRow({ release, groups, disabled, onStarted }: { release: Release; groups: Group[]; disabled: boolean; onStarted: () => void }) {
  const { notify } = useToast();
  const [openForm, setOpenForm] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [batch, setBatch] = useState(10);
  const [maxFail, setMaxFail] = useState(3);
  const [busy, setBusy] = useState(false);

  const start = async () => {
    setBusy(true);
    try {
      await api.post("/api/rollouts", { version: release.version, group_ids: selected, batch_size: batch, max_failures: maxFail });
      notify(`Rollout of ${release.version} started`);
      setOpenForm(false);
      onStarted();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not start rollout", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <tr>
        <td className="mono">{release.version}</td>
        <td className="mono">{release.sha256.slice(0, 24)}…</td>
        <td>{fmtDate(release.uploaded_at)}</td>
        <td style={{ textAlign: "right" }}>
          <button disabled={disabled} onClick={() => setOpenForm((v) => !v)} aria-label={`Start rollout of ${release.version}`}>
            Start rollout
          </button>
        </td>
      </tr>
      {openForm && (
        <tr>
          <td colSpan={4}>
            <div className="toolbar" style={{ alignItems: "flex-end" }}>
              <div>
                <label>Groups (none = all devices)</label>
                <select
                  aria-label="Rollout groups"
                  multiple
                  value={selected}
                  onChange={(e) => setSelected(Array.from(e.target.selectedOptions).map((o) => o.value))}
                >
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label>Batch size</label>
                <input aria-label="Batch size" type="number" min={1} value={batch} onChange={(e) => setBatch(Number(e.target.value))} />
              </div>
              <div>
                <label>Pause after failures (0 = never)</label>
                <input aria-label="Max failures" type="number" min={0} value={maxFail} onChange={(e) => setMaxFail(Number(e.target.value))} />
              </div>
              <button className="primary" disabled={busy || batch < 1 || maxFail < 0} onClick={start}>
                {busy ? "Starting…" : "Start"}
              </button>
              <button onClick={() => setOpenForm(false)}>Cancel</button>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function RolloutCard({ rollout, releases, groups, onChange }: { rollout: Rollout; releases: Release[]; groups: Group[]; onChange: () => void }) {
  const { notify } = useToast();
  const [detail, setDetail] = useState<RolloutDetail | null>(null);
  const [showDevices, setShowDevices] = useState(false);
  const [rollbackTo, setRollbackTo] = useState("");
  const [busy, setBusy] = useState(false);
  const s = rollout.summary;
  const inScope = s.targeted - s.already_current;
  const pct = inScope > 0 ? Math.round((s.updated / inScope) * 100) : 100;
  const others = releases.filter((r) => r.version !== rollout.version);
  const groupNames = rollout.group_ids.length === 0 ? "all devices" : rollout.group_ids.map((id) => groups.find((g) => g.id === id)?.name ?? "deleted group").join(", ");

  useEffect(() => {
    if (!showDevices) return;
    const fetch = () => api.get<RolloutDetail>(`/api/rollouts/${rollout.id}`).then(setDetail).catch(() => {});
    fetch();
    const t = setInterval(fetch, 10_000);
    return () => clearInterval(t);
  }, [showDevices, rollout.id, rollout.updated_at]);

  useEffect(() => {
    if (!rollbackTo && others.length > 0) setRollbackTo(others[0].version);
  }, [others.length]);

  const act = async (path: string, body?: unknown, ok?: string) => {
    setBusy(true);
    try {
      await api.post(`/api/rollouts/${rollout.id}/${path}`, body);
      if (ok) notify(ok);
      onChange();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Request failed", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel" data-testid="rollout-card">
      <div className="toolbar" style={{ justifyContent: "space-between" }}>
        <div>
          <strong className="mono">{rollout.version}</strong> → {groupNames} · <span aria-label="Rollout state">{rollout.state}</span>
        </div>
        <div className="toolbar">
          {rollout.state === "active" && (
            <button disabled={busy} onClick={() => act("pause", undefined, "Rollout paused")}>
              Pause
            </button>
          )}
          {rollout.state === "paused" && (
            <button disabled={busy} onClick={() => act("resume", undefined, "Rollout resumed")}>
              Resume
            </button>
          )}
          <button disabled={busy} onClick={() => act("cancel", undefined, "Rollout cancelled")}>
            Cancel rollout
          </button>
        </div>
      </div>
      <div style={{ margin: "10px 0" }}>
        <div style={{ height: 8, background: "var(--border, #333)", borderRadius: 4, overflow: "hidden" }}>
          <div style={{ width: `${pct}%`, height: "100%", background: "var(--accent, #3a6)" }} role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} />
        </div>
        <p className="who" style={{ marginTop: 6 }}>
          {s.updated} updated · {s.issued} in flight · {s.failed} failed · {s.remaining} remaining · {s.already_current} already current · {s.targeted} targeted ·
          batch {rollout.batch_size} · pause after {rollout.max_failures || "∞"} failures
        </p>
      </div>
      {others.length > 0 && (
        <div className="toolbar" style={{ alignItems: "flex-end" }}>
          <div>
            <label>Roll back to</label>
            <select aria-label="Rollback version" value={rollbackTo} onChange={(e) => setRollbackTo(e.target.value)}>
              {others.map((r) => (
                <option key={r.version} value={r.version}>
                  {r.version}
                </option>
              ))}
            </select>
          </div>
          <button disabled={busy || !rollbackTo} onClick={() => act("rollback", { version: rollbackTo }, `Rolling back to ${rollbackTo}`)}>
            Roll back
          </button>
        </div>
      )}
      <button style={{ marginTop: 10 }} onClick={() => setShowDevices((v) => !v)}>
        {showDevices ? "Hide devices" : "Show devices"}
      </button>
      {showDevices && detail && (
        <div className="table-wrap" style={{ marginTop: 10 }}>
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>State</th>
                <th>Detail</th>
                <th>Issued</th>
                <th>Resolved</th>
              </tr>
            </thead>
            <tbody>
              {detail.devices.length === 0 ? (
                <tr>
                  <td colSpan={5} className="who">
                    No devices issued yet. Only online devices are updated; offline ones are picked up when they connect.
                  </td>
                </tr>
              ) : (
                detail.devices.map((d) => (
                  <tr key={d.device_id}>
                    <td>{d.hostname}</td>
                    <td>{d.state}</td>
                    <td className="who">{d.detail}</td>
                    <td>{fmtDate(d.issued_at)}</td>
                    <td>{d.resolved_at ? fmtDate(d.resolved_at) : "—"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
