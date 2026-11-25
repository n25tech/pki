import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";

/** Minimal typing for Cloudflare's Turnstile browser API. */
interface TurnstileApi {
  render(
    el: HTMLElement,
    options: {
      sitekey: string;
      action?: string;
      callback?: (token: string) => void;
      "expired-callback"?: () => void;
      "error-callback"?: () => void;
      theme?: "auto" | "light" | "dark";
    },
  ): string;
  reset(id: string): void;
  remove(id: string): void;
}

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

const SCRIPT = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
let loading: Promise<TurnstileApi> | null = null;

function loadTurnstile(): Promise<TurnstileApi> {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  loading ??= new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = SCRIPT;
    script.async = true;
    script.onload = () => (window.turnstile ? resolve(window.turnstile) : reject(new Error("Turnstile failed to load")));
    script.onerror = () => {
      loading = null;
      reject(new Error("Turnstile failed to load"));
    };
    document.head.appendChild(script);
  });
  return loading;
}

export interface TurnstileHandle {
  /** Tokens are single-use: call after a failed submit to get a fresh one. */
  reset(): void;
}

/**
 * Cloudflare Turnstile widget. Renders nothing when `siteKey` is null
 * (Turnstile not configured on the server).
 */
export const Turnstile = forwardRef<
  TurnstileHandle,
  { siteKey: string | null | undefined; action: string; onToken: (token: string | null) => void }
>(function Turnstile({ siteKey, action, onToken }, ref) {
  const el = useRef<HTMLDivElement>(null);
  const widget = useRef<string | null>(null);
  const callback = useRef(onToken);
  callback.current = onToken;

  useImperativeHandle(ref, () => ({
    reset() {
      callback.current(null);
      if (widget.current) window.turnstile?.reset(widget.current);
    },
  }));

  useEffect(() => {
    if (!siteKey || !el.current) return;
    let cancelled = false;
    loadTurnstile()
      .then((api) => {
        if (cancelled || !el.current) return;
        widget.current = api.render(el.current, {
          sitekey: siteKey,
          action,
          theme: "auto",
          callback: (token) => callback.current(token),
          "expired-callback": () => callback.current(null),
          "error-callback": () => callback.current(null),
        });
      })
      .catch(() => callback.current(null));
    return () => {
      cancelled = true;
      if (widget.current) window.turnstile?.remove(widget.current);
      widget.current = null;
    };
  }, [siteKey, action]);

  if (!siteKey) return null;
  return <div ref={el} className="turnstile" />;
});
