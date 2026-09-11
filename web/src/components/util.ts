export function timeAgo(iso: string | null): string {
  if (!iso) return "never";
  const d = new Date(iso).getTime();
  const s = Math.floor((Date.now() - d) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export function fmtUptime(sec: number): string {
  if (!sec) return "—";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

export function useTheme() {
  const key = "fl-theme";
  const get = (): "light" | "dark" | "system" => {
    try {
      return (localStorage.getItem(key) as "light" | "dark") ?? "system";
    } catch {
      return "system";
    }
  };
  const apply = (t: "light" | "dark" | "system") => {
    const root = document.documentElement;
    if (t === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", t);
    try {
      if (t === "system") localStorage.removeItem(key);
      else localStorage.setItem(key, t);
    } catch {
      /* ignore */
    }
  };
  return { get, apply };
}
