import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { api, setCsrf, Me } from "./api";

type AuthState = {
  ready: boolean;
  me: Me | null;
  mfaPassed: boolean;
  refresh: () => Promise<void>;
  onLogin: (csrf: string) => void;
  onMfa: () => void;
  logout: () => Promise<void>;
};

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [me, setMe] = useState<Me | null>(null);
  const [mfaPassed, setMfaPassed] = useState(false);

  const refresh = async () => {
    try {
      const m = await api.get<Me>("/api/me");
      setMe(m);
      setMfaPassed(true); // /api/me requires a passed-MFA session
    } catch {
      setMe(null);
    } finally {
      setReady(true);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const onLogin = (csrf: string) => {
    setCsrf(csrf);
    setMfaPassed(false);
  };
  const onMfa = () => {
    setMfaPassed(true);
    refresh();
  };
  const logout = async () => {
    try {
      await api.post("/api/logout");
    } catch {
      /* ignore */
    }
    setMe(null);
    setMfaPassed(false);
    setCsrf("");
  };

  return (
    <Ctx.Provider value={{ ready, me, mfaPassed, refresh, onLogin, onMfa, logout }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth() {
  const c = useContext(Ctx);
  if (!c) throw new Error("useAuth outside provider");
  return c;
}
