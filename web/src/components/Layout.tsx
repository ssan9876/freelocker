import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth";
import { useTheme } from "./util";

const NAV = [
  { to: "/devices", label: "Devices" },
  { to: "/tokens", label: "Install tokens" },
  { to: "/groups", label: "Groups" },
  { to: "/admins", label: "Admins" },
  { to: "/releases", label: "Agent releases" },
  { to: "/audit", label: "Audit log" },
];

export function Layout() {
  const { me, logout } = useAuth();
  const theme = useTheme();
  const current = theme.get();
  const next = current === "dark" ? "light" : "dark";

  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">
          <span className="lock">▣</span> FreeLocker
        </div>
        {NAV.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
          >
            {n.label}
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
