import { ReactNode } from "react";

export function Confirm({
  title,
  children,
  confirmLabel,
  danger,
  onConfirm,
  onCancel,
  busy,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  busy?: boolean;
}) {
  return (
    <div className="modal-back" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>{title}</h2>
        <div>{children}</div>
        <div className="btn-row">
          <button className={danger ? "danger" : "primary"} onClick={onConfirm} disabled={busy}>
            {confirmLabel}
          </button>
          <button className="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
