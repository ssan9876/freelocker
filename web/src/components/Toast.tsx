import { createContext, useCallback, useContext, useState, ReactNode } from "react";

type Toast = { id: number; msg: string; kind: "info" | "error" };
type ToastCtx = { notify: (msg: string, kind?: "info" | "error") => void };

const Ctx = createContext<ToastCtx | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const notify = useCallback((msg: string, kind: "info" | "error" = "info") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, msg, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4000);
  }, []);
  return (
    <Ctx.Provider value={{ notify }}>
      {children}
      <div className="toasts">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind === "error" ? "error" : ""}`}>
            {t.msg}
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export function useToast() {
  const c = useContext(Ctx);
  if (!c) throw new Error("useToast outside provider");
  return c;
}
