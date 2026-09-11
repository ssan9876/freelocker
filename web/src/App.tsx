import { useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api, SetupStatus } from "./api";
import { useAuth } from "./auth";
import { useTheme } from "./components/util";
import { Layout } from "./components/Layout";
import { Setup } from "./pages/Setup";
import { Login } from "./pages/Login";
import { Mfa } from "./pages/Mfa";
import { Devices } from "./pages/Devices";
import { DeviceDetail } from "./pages/DeviceDetail";
import { Policies } from "./pages/Policies";
import { PolicyDetail } from "./pages/PolicyDetail";
import { Blocks } from "./pages/Blocks";
import { Alerts } from "./pages/Alerts";
import { Tokens } from "./pages/Tokens";
import { Groups } from "./pages/Groups";
import { Admins } from "./pages/Admins";
import { Audit } from "./pages/Audit";
import { Releases } from "./pages/Releases";

export function App() {
  const { ready, me, mfaPassed } = useAuth();
  const theme = useTheme();
  const [initialized, setInitialized] = useState<boolean | null>(null);
  const loc = useLocation();

  useEffect(() => {
    theme.apply(theme.get());
  }, []);

  useEffect(() => {
    api
      .get<SetupStatus>("/api/setup/status")
      .then((s) => setInitialized(s.initialized))
      .catch(() => setInitialized(true));
  }, [loc.pathname]);

  if (!ready || initialized === null) return <div className="spin">Loading…</div>;

  if (!initialized) {
    return (
      <Routes>
        <Route path="/setup" element={<Setup onDone={() => setInitialized(true)} />} />
        <Route path="*" element={<Navigate to="/setup" replace />} />
      </Routes>
    );
  }

  if (!me) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/mfa" element={<Mfa />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  if (!mfaPassed) {
    return (
      <Routes>
        <Route path="/mfa" element={<Mfa />} />
        <Route path="*" element={<Navigate to="/mfa" replace />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/devices" element={<Devices />} />
        <Route path="/devices/:id" element={<DeviceDetail />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/policies/:id" element={<PolicyDetail />} />
        <Route path="/blocks" element={<Blocks />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/tokens" element={<Tokens />} />
        <Route path="/groups" element={<Groups />} />
        <Route path="/admins" element={<Admins />} />
        <Route path="/releases" element={<Releases />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="*" element={<Navigate to="/devices" replace />} />
      </Route>
    </Routes>
  );
}
