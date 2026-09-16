import { useEffect, useState } from "react";
import { api, ApiError, ApprovalRequest, ApprovalStatus } from "../api";
import { useAuth } from "../auth";
import { useToast } from "../components/Toast";
import { fmtDate } from "../components/util";

export function Approvals() {
  const { me } = useAuth();
  const { notify } = useToast();
  const [status, setStatus] = useState<ApprovalStatus>("pending");
  const [reqs, setReqs] = useState<ApprovalRequest[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const canDecide = me?.role !== "readonly";

  const load = () =>
    api
      .get<ApprovalRequest[]>(`/api/approvals?status=${status}`)
      .then(setReqs)
      .catch(() => setReqs([]));

  useEffect(() => {
    setReqs(null);
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [status]);

  const decide = async (r: ApprovalRequest, action: "approve" | "deny", kind?: "hash" | "path" | "publisher") => {
    if (action === "deny" && !window.confirm(`Deny ${r.path || r.sha256}? It will stop appearing as pending.`)) return;
    setBusy(r.id);
    try {
      await api.post(`/api/approvals/${r.id}/${action}`, action === "approve" ? { kind: kind ?? "hash" } : undefined);
      notify(action === "approve" ? `Approved as ${kind ?? "hash"} — added to ${r.policy_name}` : "Denied");
    } catch (e) {
      notify(e instanceof ApiError ? e.message : `Could not ${action}`, "error");
    } finally {
      setBusy(null);
      load();
    }
  };

  return (
    <div>
      <div className="page-head">
        <h1>Approvals</h1>
        <select
          aria-label="Approval status filter"
          value={status}
          onChange={(e) => setStatus(e.target.value as ApprovalStatus)}
        >
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="denied">Denied</option>
          <option value="expired">Expired</option>
        </select>
      </div>
      <p className="who" style={{ marginTop: -8, marginBottom: 14 }}>
        Programs a policy blocked or would have blocked. Approving adds the file's hash — or its path or
        publisher — to that policy's allowlist.
      </p>
      {!reqs ? (
        <div className="spin">Loading…</div>
      ) : reqs.length === 0 ? (
        <div className="empty">No {status} requests.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Last seen</th>
                <th>Path</th>
                <th>Signer</th>
                <th>SHA-256</th>
                <th>Policy</th>
                <th>Devices</th>
                <th>Events</th>
                <th>{status === "pending" ? "" : "Decided"}</th>
              </tr>
            </thead>
            <tbody>
              {reqs.map((r) => (
                <tr key={r.id}>
                  <td>{fmtDate(r.last_seen)}</td>
                  <td className="mono">{r.path || "—"}</td>
                  <td>
                    {r.signer_verified ? (
                      r.signer || "Signed"
                    ) : r.signer || r.signer_tbs ? (
                      <span title="Windows could not verify this signature">{r.signer || "Unknown"} (unverified)</span>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="mono" title={r.sha256}>
                    {r.sha256.slice(0, 16)}…
                  </td>
                  <td>{r.policy_name}</td>
                  <td>{r.device_count}</td>
                  <td>{r.event_count}</td>
                  <td>
                    {r.status !== "pending" ? (
                      r.decided_at ? fmtDate(r.decided_at) : "—"
                    ) : canDecide ? (
                      <div className="toolbar" style={{ margin: 0, flexWrap: "nowrap" }}>
                        <button className="primary" disabled={busy === r.id} onClick={() => decide(r, "approve", "hash")}>
                          Approve
                        </button>
                        {r.path && (
                          <button className="ghost" disabled={busy === r.id} onClick={() => decide(r, "approve", "path")} title={`Allow anything at ${r.path}`}>
                            Approve by path
                          </button>
                        )}
                        <button
                          className="ghost"
                          disabled={busy === r.id || !r.signer_verified || !r.signer_tbs}
                          title={
                            r.signer_verified && r.signer_tbs
                              ? `Allow everything signed by ${r.signer || "this publisher"}`
                              : "Needs a signature Windows can verify"
                          }
                          onClick={() => decide(r, "approve", "publisher")}
                        >
                          Approve publisher
                        </button>
                        <button className="ghost" disabled={busy === r.id} onClick={() => decide(r, "deny")}>
                          Deny
                        </button>
                      </div>
                    ) : null}
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
