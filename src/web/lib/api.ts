export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

/** JSON fetch against our own API. Throws ApiError with the server's message. */
export async function api<T = unknown>(path: string, options: { method?: string; json?: unknown } = {}): Promise<T> {
  const method = options.method ?? (options.json !== undefined ? "POST" : "GET");
  const res = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    headers: options.json !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: options.json !== undefined ? JSON.stringify(options.json) : undefined,
  });
  const body = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
  if (!res.ok) throw new ApiError(res.status, body.error ?? "error", body.message ?? `Request failed (${res.status})`);
  return body as T;
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError || err instanceof Error) return err.message;
  return "Something went wrong";
}

// --- Shapes returned by the API -------------------------------------------

export interface NameConstraints {
  dns: string[];
  ip: string[];
}

export type Status = "valid" | "revoked" | "expired";

export interface Ca {
  id: string;
  kind: "root" | "intermediate";
  parentId: string | null;
  name: string;
  subject: string;
  serial: string;
  keyAlgorithm: string;
  notBefore: number;
  notAfter: number;
  fingerprint: string;
  certificatePem: string;
  nameConstraints: NameConstraints | null;
  crlNumber: number;
  crlNextUpdate: number | null;
  revokedAt: number | null;
  revocationReason: number | null;
  status: Status;
  createdAt: number;
  certificates?: { total: number; active: number };
}

export interface Certificate {
  id: string;
  caId: string;
  serial: string;
  commonName: string;
  sans: NameConstraints;
  profile: "server" | "client";
  keyAlgorithm: string;
  notBefore: number;
  notAfter: number;
  fingerprint: string;
  certificatePem: string;
  tags: string[];
  notes: string;
  revokedAt: number | null;
  revocationReason: number | null;
  status: Status;
  createdAt: number;
}

export interface Config {
  googleEnabled: boolean;
  emailEnabled: boolean;
  turnstileSiteKey: string | null;
  crlBaseUrl: string;
  maxLeafValidityDays: number;
  revocationReasons: Record<string, string>;
}

export interface Me {
  user: null | {
    id: string;
    email: string;
    emailVerified: boolean;
    hasPassword: boolean;
    google: boolean;
    mfaEnabled: boolean;
  };
  stage?: "full" | "mfa" | "setup";
}
