// Typed client for the FreeLocker console API. Sends cookies and, on
// state-changing requests, the CSRF token returned by /api/login.

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let csrf = "";
export function setCsrf(token: string) {
  csrf = token;
}
export function getCsrf() {
  return csrf;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const init: RequestInit = { method, credentials: "include", headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  if (method !== "GET" && csrf) headers["X-CSRF-Token"] = csrf;

  const resp = await fetch(path, init);
  const text = await resp.text();
  const data = text ? JSON.parse(text) : null;
  if (!resp.ok) {
    throw new ApiError(resp.status, (data && data.error) || `HTTP ${resp.status}`);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
  async upload<T>(path: string, form: FormData): Promise<T> {
    const headers: Record<string, string> = {};
    if (csrf) headers["X-CSRF-Token"] = csrf;
    const resp = await fetch(path, { method: "POST", credentials: "include", headers, body: form });
    const text = await resp.text();
    const data = text ? JSON.parse(text) : null;
    if (!resp.ok) throw new ApiError(resp.status, (data && data.error) || `HTTP ${resp.status}`);
    return data as T;
  },
};

export type Me = { id: string; email: string; role: string; provider: boolean };
export type Tenant = { id: string; name: string; suspended: boolean; created_at: string };
export type SetupStatus = { initialized: boolean };
export type LoginResult = { csrf_token: string; mfa_enrolled: boolean };
export type MfaSetup = { secret: string; otpauth_url: string };

export type Device = {
  id: string;
  hostname: string;
  status: "online" | "offline" | "unexpected_offline" | "revoked" | "never_seen";
  connected: boolean;
  group_id: string | null;
  os_build: string;
  agent_version: string;
  ip_addresses: string[] | null;
  logged_on_user: string;
  uptime_seconds: number;
  last_seen_at: string | null;
  cert_expires_at: string;
  enrolled_at: string;
  // Whether Defender/ASR was active as of this device's last ringfence
  // report. null means the device has never reported one -- distinct from
  // a reported false ("not enforced -- Defender inactive").
  asr_available: boolean | null;
};
export type DeviceDetail = { device: Device; uninstall_code?: string };
export type ControlKey = "usb_storage_blocked" | "network_blocked" | "elevation_blocked";
export type DeviceControlsView = {
  overrides: Record<ControlKey, boolean | null>;
  group: Record<ControlKey, boolean>;
  effective: Record<ControlKey, boolean>;
};
export type Command = {
  id: string;
  type: string;
  state: string;
  result: string;
  issued_at: string;
  expires_at: string;
  completed_at: string | null;
};
export type Group = { id: string; name: string };
export type Token = {
  id: string;
  name: string;
  group_id: string | null;
  expires_at: string | null;
  max_uses: number | null;
  uses: number;
  revoked: boolean;
  created_at: string;
};
export type Admin = {
  id: string;
  email: string;
  role: string;
  disabled: boolean;
  mfa_enrolled: boolean;
  created_at: string;
};
export type Audit = {
  id: number;
  actor: string;
  action: string;
  target_type: string;
  target_id: string;
  detail: Record<string, unknown>;
  ip: string;
  result: string;
  created_at: string;
};
export type Release = { version: string; sha256: string; uploaded_at: string };
export type RolloutSummary = {
  targeted: number;
  already_current: number;
  issued: number;
  updated: number;
  failed: number;
  remaining: number;
};
export type Rollout = {
  id: string;
  version: string;
  group_ids: string[];
  batch_size: number;
  max_failures: number;
  state: "active" | "paused" | "completed" | "cancelled";
  created_by: string;
  created_at: string;
  updated_at: string;
  finished_at: string | null;
  summary: RolloutSummary;
};
export type RolloutDevice = {
  device_id: string;
  hostname: string;
  command_id: string;
  state: "issued" | "updated" | "failed";
  detail: string;
  issued_at: string;
  resolved_at: string | null;
};
export type RolloutDetail = Rollout & { devices: RolloutDevice[] };
export type Policy = { id: string; name: string; mode: "audit" | "enforce"; created_at: string };
export type PolicyRule = {
  id: string;
  kind: "hash" | "publisher" | "path";
  value: string;
  publisher_name: string;
  description: string;
};
export type PolicyDetail = { policy: Policy; rules: PolicyRule[]; version: string };
export type Observation = {
  sha256: string;
  path: string;
  signer: string;
  signer_tbs: string;
  signer_verified: boolean;
  count: number;
  first_seen: string;
  last_seen: string;
};
export type MetricSample = { at: string; cpu_pct: number; mem_pct: number; disk_pct: number };
export type AlertRule = {
  id: string;
  name: string;
  metric: "cpu" | "mem" | "disk";
  op: "gt" | "lt";
  threshold: number;
  duration_seconds: number;
  enabled: boolean;
};
export type Alert = {
  id: number;
  device_id: string;
  metric: string;
  message: string;
  at: string;
  resolved_at: string | null;
};
export type BlockEvent = {
  id: number;
  device_id: string;
  sha256: string;
  path: string;
  signer: string;
  signer_tbs: string;
  signer_verified: boolean;
  blocked: boolean;
  at: string;
};
export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";
export type ApprovalRequest = {
  id: string;
  policy_id: string;
  policy_name: string;
  sha256: string;
  path: string;
  signer: string;
  signer_tbs: string;
  signer_verified: boolean;
  status: ApprovalStatus;
  device_count: number;
  event_count: number;
  first_seen: string;
  last_seen: string;
  decided_at: string | null;
};

export type Ringfence = {
  id: string;
  name: string;
  mode: "audit" | "enforce";
  created_at: string;
  // Groups this ringfence is applied to. The API always sends an array, so
  // no null guard is needed; it is empty when the ringfence is unassigned.
  groups: string[];
};
export type RingfenceProgram = { id: string; path: string; network_blocked: boolean; note: string };
export type RingfenceProtection = { asr_rule: string; action: "audit" | "block" };
export type RingfenceDetail = {
  ringfence: Ringfence;
  programs: RingfenceProgram[];
  protections: RingfenceProtection[];
};
// What is contained on one device. `ringfence` is null when the device's
// group has no assignment — distinct from the request failing, which is why
// the endpoint answers 200 rather than 404 in that case.
export type DeviceRingfence = {
  ringfence: Ringfence | null;
  programs: RingfenceProgram[];
  protections: RingfenceProtection[];
};
export type RingfenceEvent = {
  id: number;
  device_id: string;
  hostname: string;
  kind: "network" | "child_process";
  program: string;
  detail: string;
  enforced: boolean;
  at: string;
};

export type NotificationStatus = { smtp_configured: boolean; event_kinds: string[] };
export type NotificationChannel = {
  id: string;
  kind: "email" | "webhook";
  name: string;
  events: string[];
  enabled: boolean;
  recipients: string[];
  url: string;
  has_secret: boolean;
  created_at: string;
  updated_at: string;
};
export type NotificationDelivery = {
  id: number;
  channel_id: string;
  channel_name: string;
  event_kind: string;
  title: string;
  state: "pending" | "sent" | "failed";
  attempts: number;
  last_error: string;
  created_at: string;
  sent_at: string | null;
  next_attempt_at: string;
};
