import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { useTheme } from "./util";

const NAV = [
  { to: "/devices", label: "Devices" },
  { to: "/policies", label: "Policies" },
  { to: "/ringfences", label: "Ringfences" },
  { to: "/blocks", label: "Blocked programs" },
  { to: "/approvals", label: "Approvals" },
  { to: "/alerts", label: "Alerts" },
  { to: "/notifications", label: "Notifications" },
  { to: "/activity", label: "Activity" },
  { to: "/tokens", label: "Install tokens" },
  { to: "/groups", label: "Groups" },
  { to: "/admins", label: "Admins" },
  { to: "/releases", label: "Agent releases" },
  { to: "/audit", label: "Audit log" },
];

// Shown only to a provider (the MSP operator) who manages tenants.
const PROVIDER_NAV = [{ to: "/tenants", label: "Tenants" }];

export function Layout() {
  const { me, logout } = useAuth();
  const theme = useTheme();
  const current = theme.get();
  const next = current === "dark" ? "light" : "dark";
  const [pending, setPending] = useState(0);
  useEffect(() => {
    const load = () =>
      api
        .get<{ pending: number }>("/api/approvals/count")
        .then((c) => setPending(c.pending))
        .catch(() => {});
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">
          <span className="lock">▣</span> FreeLocker
        </div>
        {[...NAV, ...(me?.provider ? PROVIDER_NAV : [])].map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
          >
            {n.label}
            {n.to === "/approvals" && pending > 0 && (
              <span className="badge fail" style={{ marginLeft: 6 }}>
                {pending}
              </span>
            )}
          </NavLink>
        ))}
      </nav>
      <div className="main">
        <div className="topbar">
          <div className="who">
            Signed in as <b>{me?.email}</b> <span className="badge role">{me?.role}</span>
          </div>
          <div className="topbar-actions">
            <button className="ghost iconbtn" onClick={() => theme.apply(next)} title="Toggle theme">
              {next === "dark" ? "◐ Dark" : "◑ Light"}
            </button>
            <button className="ghost" onClick={logout}>
              Sign out
            </button>
          </div>
        </div>
        <div className="content">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
