import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, ApiError, NotificationChannel, NotificationDelivery, NotificationStatus } from "../api";
import { useToast } from "../components/Toast";
import { fmtDate } from "../components/util";

const EVENT_LABELS: Record<string, string> = {
  "alert.raised": "Alert raised",
  "alert.resolved": "Alert resolved",
  "approval.new": "New approval request",
  "rollout.auto_paused": "Rollout auto-paused",
  "rollout.completed": "Rollout completed",
};

export function Notifications() {
  const { notify } = useToast();
  const [status, setStatus] = useState<NotificationStatus | null>(null);
  const [channels, setChannels] = useState<NotificationChannel[] | null>(null);
  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([]);
  const [kind, setKind] = useState<"webhook" | "email">("webhook");
  const [name, setName] = useState("");
  const [recipients, setRecipients] = useState("");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [events, setEvents] = useState<string[]>(["alert.raised", "approval.new", "rollout.auto_paused"]);
  const [busy, setBusy] = useState(false);
  const [testResult, setTestResult] = useState<Record<string, string>>({});

  const load = useCallback(() => {
    api.get<NotificationStatus>("/api/notifications/status").then(setStatus).catch(() => {});
    api.get<NotificationChannel[]>("/api/notification-channels").then(setChannels).catch(() => setChannels([]));
    api.get<NotificationDelivery[]>("/api/notification-deliveries?limit=50").then(setDeliveries).catch(() => {});
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(() => api.get<NotificationDelivery[]>("/api/notification-deliveries?limit=50").then(setDeliveries).catch(() => {}), 15_000);
    return () => clearInterval(t);
  }, [load]);

  const toggleEvent = (k: string) => setEvents((cur) => (cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k]));

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const body: Record<string, unknown> = { kind, name, events };
      if (kind === "webhook") {
        body.url = url;
        if (secret) body.secret = secret;
      } else {
        body.recipients = recipients.split(",").map((s) => s.trim()).filter(Boolean);
      }
      await api.post("/api/notification-channels", body);
      notify(`Added ${name}`);
      setName("");
      setUrl("");
      setSecret("");
      setRecipients("");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not add channel", "error");
    } finally {
      setBusy(false);
    }
  };

  const setEnabled = async (c: NotificationChannel, enabled: boolean) => {
    setChannels((cur) => cur?.map((x) => (x.id === c.id ? { ...x, enabled } : x)) ?? cur);
    try {
      await api.patch(`/api/notification-channels/${c.id}`, { enabled });
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not update channel", "error");
      load();
    }
  };

  const test = async (c: NotificationChannel) => {
    setTestResult((r) => ({ ...r, [c.id]: "Sending…" }));
    try {
      const res = await api.post<{ ok: boolean; error?: string }>(`/api/notification-channels/${c.id}/test`);
      setTestResult((r) => ({ ...r, [c.id]: res.ok ? "Delivered" : `Failed: ${res.error}` }));
    } catch (e) {
      setTestResult((r) => ({ ...r, [c.id]: e instanceof ApiError ? e.message : "Request failed" }));
    }
  };

  const del = async (c: NotificationChannel) => {
    try {
      await api.del(`/api/notification-channels/${c.id}`);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not delete channel", "error");
    }
  };

  const smtp = status?.smtp_configured ?? false;

  return (
    <div>
      <div className="page-head">
        <h1>Notifications</h1>
      </div>
      <p className="who" style={{ marginTop: -6 }}>
        Email delivery: {status ? (smtp ? "configured" : "not configured on this server (set smtp in the server config)") : "…"}
      </p>

      <div className="panel" style={{ marginBottom: 20 }}>
        <h2>Add channel</h2>
        <form onSubmit={create}>
          <div className="toolbar" style={{ alignItems: "flex-end", flexWrap: "wrap" }}>
            <div>
              <label>Kind</label>
              <select aria-label="Channel kind" value={kind} onChange={(e) => setKind(e.target.value as "webhook" | "email")}>
                <option value="webhook">Webhook</option>
                <option value="email" disabled={!smtp}>
                  Email{smtp ? "" : " (SMTP not configured)"}
                </option>
              </select>
            </div>
            <div>
              <label>Name</label>
              <input aria-label="Channel name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Ops Slack" />
            </div>
            {kind === "webhook" ? (
              <>
                <div>
                  <label>URL</label>
                  <input aria-label="Webhook URL" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.example.com/…" />
                </div>
                <div>
                  <label>Signing secret (optional)</label>
                  <input aria-label="Webhook secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} />
                </div>
              </>
            ) : (
              <div>
                <label>Recipients (comma-separated)</label>
                <input aria-label="Recipients" value={recipients} onChange={(e) => setRecipients(e.target.value)} placeholder="ops@example.com" />
              </div>
            )}
          </div>
          <div className="toolbar" style={{ flexWrap: "wrap", marginTop: 10 }}>
            {(status?.event_kinds ?? Object.keys(EVENT_LABELS)).map((k) => (
              <label key={k} style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <input type="checkbox" aria-label={`Event ${k}`} checked={events.includes(k)} onChange={() => toggleEvent(k)} />
                {EVENT_LABELS[k] ?? k}
              </label>
            ))}
          </div>
          <button className="primary" style={{ marginTop: 10 }} disabled={busy || !name || events.length === 0 || (kind === "webhook" ? !url : !recipients)}>
            Add channel
          </button>
        </form>
      </div>

      <h2>Channels</h2>
      {!channels ? (
        <div className="spin">Loading…</div>
      ) : channels.length === 0 ? (
        <div className="empty">No channels yet.</div>
      ) : (
        <div className="table-wrap" style={{ marginBottom: 20 }}>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Target</th>
                <th>Events</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {channels.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{c.kind}</td>
                  <td className="mono">{c.kind === "webhook" ? c.url + (c.has_secret ? " (signed)" : "") : c.recipients.join(", ")}</td>
                  <td>{c.events.map((k) => EVENT_LABELS[k] ?? k).join(", ")}</td>
                  <td>
                    <input type="checkbox" aria-label={`Channel ${c.name} enabled`} checked={c.enabled} onChange={(e) => setEnabled(c, e.target.checked)} />
                  </td>
                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    <button onClick={() => test(c)} aria-label={`Test ${c.name}`}>
                      Test
                    </button>{" "}
                    <button onClick={() => del(c)} aria-label={`Delete ${c.name}`}>
                      Delete
                    </button>
                    {testResult[c.id] && (
                      <div className="who" aria-label={`Test result ${c.name}`}>
                        {testResult[c.id]}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2>Recent deliveries</h2>
      {deliveries.length === 0 ? (
        <div className="empty">No deliveries yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Channel</th>
                <th>Event</th>
                <th>Title</th>
                <th>State</th>
                <th>Attempts</th>
                <th>Last error</th>
              </tr>
            </thead>
            <tbody>
              {deliveries.map((d) => (
                <tr key={d.id}>
                  <td>{fmtDate(d.created_at)}</td>
                  <td>{d.channel_name || "(deleted)"}</td>
                  <td>{EVENT_LABELS[d.event_kind] ?? d.event_kind}</td>
                  <td>{d.title}</td>
                  <td>
                    <span className={`badge ${d.state === "sent" ? "ok" : d.state === "failed" ? "fail" : ""}`}>{d.state}</span>
                  </td>
                  <td>{d.attempts}</td>
                  <td className="who">{d.last_error}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
