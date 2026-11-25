import type { Context } from "hono";

export interface UserRow {
  id: string;
  email: string;
  email_verified_at: number | null;
  password_hash: string | null;
  google_sub: string | null;
  totp_secret_enc: string | null;
  totp_enabled_at: number | null;
  totp_last_step: number | null;
  created_at: number;
}

export interface SessionInfo {
  id: string;
  user: UserRow;
  mfaAt: number | null;
  createdAt: number;
}

export type AppEnv = {
  Bindings: Env;
  Variables: { session: SessionInfo | null };
};

export type AppContext = Context<AppEnv>;
