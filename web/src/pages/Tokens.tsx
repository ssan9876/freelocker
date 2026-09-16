import { FormEvent, useEffect, useState } from "react";
import { api, ApiError, Group, Token } from "../api";
import { useToast } from "../components/Toast";
import { fmtDate } from "../components/util";

export function Tokens() {
  const { notify } = useToast();
  const [tokens, setTokens] = useState<Token[] | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [name, setName] = useState("");
  const [groupId, setGroupId] = useState("");
  const [hours, setHours] = useState("");
  const [maxUses, setMaxUses] = useState("");
  const [created, setCreated] = useState("");

  const load = () => api.get<Token[]>("/api/tokens").then(setTokens).catch(() => setTokens([]));
  useEffect(() => {
    load();
    api.get<Group[]>("/api/groups").then(setGroups).catch(() => {});
  }, []);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    const body: Record<string, unknown> = { name };
    if (groupId) body.group_id = groupId;
    if (hours) body.expires_in_hours = Number(hours);
    if (maxUses) body.max_uses = Number(maxUses);
    try {
      const r = await api.post<{ id: string; token: string }>("/api/tokens", body);
      setCreated(r.token);
      setName("");
      setHours("");
      setMaxUses("");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not create token", "error");
    }
  };

  const revoke = async (id: string) => {
    try {
      await api.post(`/api/tokens/${id}/revoke`);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Revoke failed", "error");
    }
  };

  const groupName = (id: string | null) => groups.find((g) => g.id === id)?.name ?? "—";

  return (
    <div>
      <div className="page-head">
        <h1>Install tokens</h1>
      </div>

      <div className="panel" style={{ marginBottom: 20 }}>
        <h2>Create a token</h2>
        <form onSubmit={create}>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div>
              <label>Name</label>
              <input
                aria-label="Token name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="HQ rollout"
              />
            </div>
            <div>
              <label>Group</label>
              <select aria-label="Token group" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
                <option value="">None</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label>Expires (hours)</label>
              <input
                aria-label="Expires (hours)"
                value={hours}
                onChange={(e) => setHours(e.target.value.replace(/\D/g, ""))}
                placeholder="∞"
              />
            </div>
            <div>
              <label>Max uses</label>
              <input
                aria-label="Max uses"
                value={maxUses}
                onChange={(e) => setMaxUses(e.target.value.replace(/\D/g, ""))}
                placeholder="∞"
              />
            </div>
            <button className="primary" disabled={!name}>
              Create token
            </button>
          </div>
        </form>
        {created && (
          <div style={{ marginTop: 12 }}>
            <label>Token — copy it now, it won’t be shown again</label>
            <div className="copybox">
              <input
                aria-label="Install token"
                readOnly
                value={created}
                onFocus={(e) => e.target.select()}
              />
              <button type="button" className="ghost" onClick={() => navigator.clipboard?.writeText(created)}>
                Copy
              </button>
            </div>
          </div>
        )}
      </div>

      {!tokens ? (
        <div className="spin">Loading…</div>
      ) : tokens.length === 0 ? (
        <div className="empty">No install tokens yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Group</th>
                <th>Uses</th>
                <th>Expires</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.id}>
                  <td>{t.name}</td>
                  <td>{groupName(t.group_id)}</td>
                  <td className="mono">
                    {t.uses}
                    {t.max_uses ? ` / ${t.max_uses}` : ""}
                  </td>
                  <td>{t.expires_at ? fmtDate(t.expires_at) : "Never"}</td>
                  <td>{fmtDate(t.created_at)}</td>
                  <td>
                    {t.revoked ? (
                      <span className="badge fail">Revoked</span>
                    ) : (
                      <button className="ghost" onClick={() => revoke(t.id)}>
                        Revoke
                      </button>
                    )}
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
