const LABELS: Record<string, string> = {
  online: "Online",
  offline: "Offline",
  unexpected_offline: "Offline (unexpected)",
  revoked: "Revoked",
  never_seen: "Never seen",
};

export function StatusDot({ status }: { status: string }) {
  return (
    <span className="status">
      <span className={`dot ${status}`} />
      {LABELS[status] ?? status}
    </span>
  );
}
