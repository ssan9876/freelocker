import { FormEvent, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, ApiError, PolicyDetail as Detail } from "../api";
import { useToast } from "../components/Toast";

export function PolicyDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const { notify } = useToast();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [kind, setKind] = useState<"hash" | "publisher" | "path">("hash");
  const [value, setValue] = useState("");
  const [publisher, setPublisher] = useState("");
  const [description, setDescription] = useState("");

  const load = () => api.get<Detail>(`/api/policies/${id}`).then(setDetail).catch(() => setDetail(null));
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const addRule = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.post(`/api/policies/${id}/rules`, {
        kind,
        value,
        publisher_name: publisher,
        description,
      });
      setValue("");
      setPublisher("");
      setDescription("");
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not add rule", "error");
    }
  };

  const del = async (ruleId: string) => {
    try {
      await api.del(`/api/policies/${id}/rules/${ruleId}`);
      load();
    } catch (e) {
      notify(e instanceof ApiError ? e.message : "Could not delete rule", "error");
    }
  };

  if (!detail) return <div className="spin">Loading…</div>;

  const placeholder =
    kind === "hash"
      ? "SHA-256 (64 hex characters)"
      : kind === "publisher"
        ? "Certificate TBS hash (64 hex characters)"
        : `C:\\Program Files\\App\\app.exe`;

  return (
    <div>
      <div className="page-head">
        <h1>
          <a onClick={() => nav("/policies")} style={{ cursor: "pointer" }}>
            Policies
          </a>{" "}
          / {detail.policy.name}
        </h1>
        <span className="badge role">{detail.policy.mode}</span>
      </div>

      <div className="panel" style={{ marginBottom: 20 }}>
        <h2>Add allow rule</h2>
        <form onSubmit={addRule}>
          <div className="toolbar" style={{ alignItems: "flex-end" }}>
            <div>
              <label>Kind</label>
              <select
                aria-label="Rule kind"
                value={kind}
                onChange={(e) => setKind(e.target.value as typeof kind)}
              >
                <option value="hash">File hash</option>
                <option value="publisher">Publisher</option>
                <option value="path">Path</option>
              </select>
            </div>
            <div style={{ flex: 1, minWidth: 260 }}>
              <label>Value</label>
              <input
                aria-label="Rule value"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={placeholder}
              />
            </div>
            {kind === "publisher" && (
              <div>
                <label>Publisher name</label>
                <input
                  aria-label="Publisher name"
                  value={publisher}
                  onChange={(e) => setPublisher(e.target.value)}
                  placeholder="Acme Corp"
                />
              </div>
            )}
            <div>
              <label>Description</label>
              <input
                aria-label="Rule description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="optional"
              />
            </div>
            <button className="primary" disabled={!value}>
              Add rule
            </button>
          </div>
        </form>
        {detail.version && (
          <p className="who" style={{ marginBottom: 0 }}>
            Compiled version <code>{detail.version.slice(0, 16)}…</code>
          </p>
        )}
      </div>

      {detail.rules.length === 0 ? (
        <div className="empty">No rules yet. A policy with no rules blocks everything (default-deny).</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Kind</th>
                <th>Value</th>
                <th>Description</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {detail.rules.map((r) => (
                <tr key={r.id}>
                  <td>{r.kind}</td>
                  <td className="mono">
                    {r.value}
                    {r.publisher_name ? ` (${r.publisher_name})` : ""}
                  </td>
                  <td>{r.description || "—"}</td>
                  <td>
                    <button className="ghost" onClick={() => del(r.id)}>
                      Remove
                    </button>
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
