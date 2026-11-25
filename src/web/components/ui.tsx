import { useState, type ReactNode } from "react";
import type { Status } from "../lib/api";

export function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <p className="error" role="alert">
      {error}
    </p>
  );
}

export function Notice({ kind = "info", children }: { kind?: "info" | "warn" | "ok"; children: ReactNode }) {
  return <div className={`notice notice-${kind}`}>{children}</div>;
}

export function StatusBadge({ status, notAfter }: { status: Status; notAfter?: number }) {
  const soon = status === "valid" && notAfter !== undefined && notAfter - Date.now() < 30 * 86_400_000;
  const label = soon ? "expiring" : status;
  return <span className={`badge badge-${label}`}>{label}</span>;
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="secondary small"
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? "Copied" : label}
    </button>
  );
}

export function Pem({ text }: { text: string }) {
  return (
    <div className="pem">
      <pre>{text}</pre>
      <CopyButton text={text} />
    </div>
  );
}

export function Code({ children }: { children: string }) {
  return (
    <div className="code">
      <pre>{children}</pre>
      <CopyButton text={children} />
    </div>
  );
}

export function Loading() {
  return <p className="muted">Loading…</p>;
}

/** Runs an async action with busy/error state. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function run<T>(fn: () => Promise<T>): Promise<T | undefined> {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong");
      return undefined;
    } finally {
      setBusy(false);
    }
  }
  return { busy, error, setError, run };
}
