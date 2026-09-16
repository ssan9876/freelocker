import { ComponentType, useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import {
  BrandMark,
  IconActivity,
  IconAdmins,
  IconAlerts,
  IconApprovals,
  IconAudit,
  IconBlocked,
  IconDevices,
  IconGroups,
  IconNotifications,
  IconPolicies,
  IconReleases,
  IconRingfence,
  IconTenants,
  IconTokens,
} from "./icons";
import { useTheme } from "./util";

type NavItem = { to: string; label: string; icon: ComponentType<{ className?: string }> };

// Grouped so the sidebar has a shape. Ungrouped, thirteen destinations read
// as one undifferentiated list where everything looks equally important.
// The order follows how the console is actually used: watch the fleet, then
// change what it is allowed to do, then administer the system itself.
const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "Monitor",
    items: [
      { to: "/devices", label: "Devices", icon: IconDevices },
      { to: "/blocks", label: "Blocked programs", icon: IconBlocked },
      { to: "/approvals", label: "Approvals", icon: IconApprovals },
      { to: "/alerts", label: "Alerts", icon: IconAlerts },
      { to: "/activity", label: "Activity", icon: IconActivity },
    ],
  },
  {
    label: "Control",
    items: [
      { to: "/policies", label: "Policies", icon: IconPolicies },
      { to: "/ringfences", label: "Ringfences", icon: IconRingfence },
      { to: "/groups", label: "Groups", icon: IconGroups },
    ],
  },
  {
    label: "Administration",
    items: [
      { to: "/notifications", label: "Notifications", icon: IconNotifications },
      { to: "/tokens", label: "Install tokens", icon: IconTokens },
      { to: "/admins", label: "Admins", icon: IconAdmins },
      { to: "/releases", label: "Agent releases", icon: IconReleases },
      { to: "/audit", label: "Audit log", icon: IconAudit },
    ],
  },
];

// Shown only to a provider (the MSP operator) who manages tenants.
const PROVIDER_GROUP = {
  label: "Provider",
  items: [{ to: "/tenants", label: "Tenants", icon: IconTenants }],
};

export function Layout() {
  const { me, logout } = useAuth();
  const theme = useTheme();
  // Held in state so the label re-renders on toggle. theme.apply only touches
  // the DOM and localStorage, so reading theme.get() during render left the
  // button showing a stale label until some unrelated re-render fixed it.
  //
  // "system" resolves to what the stylesheet actually renders, which is dark
  // for anything not explicitly light. Comparing the stored value directly
  // made the button offer "Dark" while already dark, so the first click was a
  // no-op and reaching light took two presses.
  const [themeName, setThemeName] = useState<"light" | "dark">(
    theme.get() === "light" ? "light" : "dark"
  );
  const next = themeName === "dark" ? "light" : "dark";
  const toggleTheme = () => {
    theme.apply(next);
    setThemeName(next);
  };
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

  const groups = me?.provider ? [...NAV_GROUPS, PROVIDER_GROUP] : NAV_GROUPS;
  const initials = (me?.email ?? "?").slice(0, 2);

  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">
          <BrandMark />
          <span className="brand-name">FreeLocker</span>
        </div>

        {groups.map((g) => (
          <div key={g.label}>
            <div className="nav-group-label">{g.label}</div>
            {g.items.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
              >
                <n.icon />
                {n.label}
                {n.to === "/approvals" && pending > 0 && (
                  <span className="badge fail nav-count">{pending}</span>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      <div className="main">
        <div className="topbar">
          <div className="who">
            Signed in as <b>{me?.email}</b>
          </div>
          <div className="topbar-actions">
            {/* Labelled with the theme it switches TO, which is what the
                click does; labelling it with the current theme reads as a
                status display and invites a pointless click. */}
            <button
              className="ghost iconbtn"
              onClick={toggleTheme}
              title={`Switch to ${next} theme`}
            >
              {next === "dark" ? "Dark" : "Light"}
            </button>
            <div className="account">
              <span className="avatar" aria-hidden="true">
                {initials}
              </span>
              <span className="badge role">{me?.role}</span>
            </div>
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
