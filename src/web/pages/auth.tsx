import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from "react-router";
import { renderSVG } from "uqr";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { download } from "../lib/files";
import { ErrorBox, Field, Notice, useAction } from "../components/ui";
import { Turnstile, type TurnstileHandle } from "../components/turnstile";

const DISCLAIMER = (
  <Notice kind="warn">
    <strong>Not for production.</strong> A convenience tool for labs and internal, non-critical services. For anything
    with a real security requirement, use <a href="https://letsencrypt.org/">Let&rsquo;s Encrypt</a> or a properly
    operated CA.
  </Notice>
);

const OAUTH_ERRORS: Record<string, string> = {
  google_state: "Google sign-in expired or was interrupted. Try again.",
  google_token: "Google sign-in failed. Try again.",
  google_unverified: "Your Google account's email isn't verified.",
  google_mismatch: "This email is linked to a different Google account.",
};

function GoogleButton() {
  const { config } = useAuth();
  if (!config?.googleEnabled) return null;
  return (
    <>
      <a className="button secondary wide" href="/api/auth/google/start">
        Continue with Google
      </a>
      <div className="divider">or</div>
    </>
  );
}

export function Login() {
  const { me, refresh } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [params] = useSearchParams();
  const { busy, error, run } = useAction();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const from = (location.state as { from?: string } | null)?.from ?? "/";

  if (me?.stage === "full") return <Navigate to={from} replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    const res = await run(() => api<{ mfaRequired: boolean }>("/auth/login", { json: { email, password } }));
    if (!res) return;
    await refresh();
    navigate(res.mfaRequired ? "/login/mfa" : "/setup-2fa", { replace: true, state: { from } });
  }

  return (
    <section className="narrow">
      <h1>Sign in</h1>
      <ErrorBox error={OAUTH_ERRORS[params.get("error") ?? ""] ?? null} />
      <GoogleButton />
      <form onSubmit={submit} className="stack">
        <Field label="Email">
          <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>
        <Field label="Password">
          <input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <ErrorBox error={error} />
        <button disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
      <p className="muted">
        <Link to="/forgot-password">Forgot password?</Link> · No account? <Link to="/register">Create one</Link>
      </p>
      {DISCLAIMER}
    </section>
  );
}

export function Register() {
  const { refresh, config } = useAuth();
  const navigate = useNavigate();
  const { busy, error, run } = useAction();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [agreed, setAgreed] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const turnstile = useRef<TurnstileHandle>(null);
  const needsCheck = !!config?.turnstileSiteKey;

  async function submit(e: FormEvent) {
    e.preventDefault();
    const ok = await run(() => api("/auth/register", { json: { email, password, turnstileToken } }));
    if (!ok) {
      turnstile.current?.reset();
      return;
    }
    await refresh();
    navigate("/setup-2fa", { replace: true });
  }

  return (
    <section className="narrow">
      <h1>Create an account</h1>
      {DISCLAIMER}
      <GoogleButton />
      <form onSubmit={submit} className="stack">
        <Field label="Email">
          <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>
        <Field label="Password" hint="At least 12 characters. A passphrase works well.">
          <input type="password" autoComplete="new-password" minLength={12} required value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <label className="check">
          <input type="checkbox" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
          <span>
            I understand this isn&rsquo;t a production PKI and agree to the <Link to="/legal">terms</Link>.
          </span>
        </label>
        <Turnstile ref={turnstile} siteKey={config?.turnstileSiteKey} action="register" onToken={setTurnstileToken} />
        <ErrorBox error={error} />
        <button disabled={busy || !agreed || (needsCheck && !turnstileToken)}>{busy ? "Creating…" : "Create account"}</button>
      </form>
      <p className="muted">
        Already have an account? <Link to="/login">Sign in</Link>
      </p>
    </section>
  );
}

export function MfaChallenge() {
  const { me, refresh } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const { busy, error, run } = useAction();
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const from = (location.state as { from?: string } | null)?.from ?? "/";

  if (me && !me.user) return <Navigate to="/login" replace />;
  if (me?.stage === "full") return <Navigate to={from} replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    const ok = await run(() => api("/auth/mfa", { json: useRecovery ? { recoveryCode: code } : { code } }));
    if (!ok) return;
    await refresh();
    navigate(from, { replace: true });
  }

  return (
    <section className="narrow">
      <h1>Two-factor authentication</h1>
      <form onSubmit={submit} className="stack">
        {useRecovery ? (
          <Field label="Recovery code" hint="Each recovery code works once.">
            <input autoComplete="off" required value={code} onChange={(e) => setCode(e.target.value)} placeholder="xxxx-xxxx-xxxx" />
          </Field>
        ) : (
          <Field label="Code from your authenticator app">
            <input inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} required autoFocus value={code} onChange={(e) => setCode(e.target.value)} />
          </Field>
        )}
        <ErrorBox error={error} />
        <button disabled={busy}>{busy ? "Checking…" : "Continue"}</button>
      </form>
      <p>
        <button
          type="button"
          className="link"
          onClick={() => {
            setUseRecovery(!useRecovery);
            setCode("");
          }}
        >
          {useRecovery ? "Use an authenticator code" : "Use a recovery code instead"}
        </button>
      </p>
    </section>
  );
}

export function SetupTwoFactor() {
  const { me, refresh } = useAuth();
  const navigate = useNavigate();
  const { busy, error, run } = useAction();
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (me?.user && !me.user.mfaEnabled && !setup) {
      void run(() => api<{ secret: string; uri: string }>("/auth/totp/setup", { json: {} }).then(setSetup));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me]);

  const qr = useMemo(() => (setup ? `data:image/svg+xml;utf8,${encodeURIComponent(renderSVG(setup.uri))}` : null), [setup]);

  if (me?.user?.mfaEnabled && !recoveryCodes) return <Navigate to="/" replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    const res = await run(() => api<{ recoveryCodes: string[] }>("/auth/totp/enable", { json: { code } }));
    if (res) setRecoveryCodes(res.recoveryCodes);
  }

  if (recoveryCodes) {
    return (
      <section className="narrow">
        <h1>Save your recovery codes</h1>
        <p>If you lose your authenticator, each of these codes lets you sign in once. They won&rsquo;t be shown again.</p>
        <ul className="codes">
          {recoveryCodes.map((c) => (
            <li key={c}>
              <code>{c}</code>
            </li>
          ))}
        </ul>
        <div className="row">
          <button type="button" className="secondary" onClick={() => download("pki-recovery-codes.txt", recoveryCodes.join("\n") + "\n", "text/plain")}>
            Download
          </button>
        </div>
        <label className="check">
          <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          <span>I&rsquo;ve saved these codes somewhere safe</span>
        </label>
        <button
          disabled={!saved}
          onClick={async () => {
            await refresh();
            navigate("/", { replace: true });
          }}
        >
          Continue
        </button>
      </section>
    );
  }

  return (
    <section className="narrow">
      <h1>Set up two-factor authentication</h1>
      <p>
        Your account can issue certificates that your devices trust, so a second factor is required before you can
        create a CA.
      </p>
      <ol className="steps">
        <li>Scan this QR code with an authenticator app (1Password, Bitwarden, Google Authenticator, Aegis…).</li>
        <li>Enter the 6-digit code it shows.</li>
      </ol>
      {qr && <img className="qr" src={qr} alt="QR code for your authenticator app" width={220} height={220} />}
      {setup && (
        <details>
          <summary>Can&rsquo;t scan? Enter the key manually</summary>
          <code className="secret">{setup.secret.replace(/(.{4})/g, "$1 ").trim()}</code>
        </details>
      )}
      <form onSubmit={submit} className="stack">
        <Field label="6-digit code">
          <input inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} required value={code} onChange={(e) => setCode(e.target.value)} />
        </Field>
        <ErrorBox error={error} />
        <button disabled={busy || !setup}>{busy ? "Checking…" : "Turn on two-factor"}</button>
      </form>
    </section>
  );
}

function tokenFromHash(): string {
  return new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
}

export function VerifyEmail() {
  const { refresh } = useAuth();
  const { error, run } = useAction();
  const [done, setDone] = useState(false);
  useEffect(() => {
    void run(async () => {
      await api("/auth/verify-email", { json: { token: tokenFromHash() } });
      setDone(true);
      await refresh();
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <section className="narrow">
      <h1>Email verification</h1>
      {done ? <Notice kind="ok">Your email address is confirmed.</Notice> : <ErrorBox error={error} />}
      {!done && !error && <p className="muted">Checking…</p>}
      <p>
        <Link to="/">Continue</Link>
      </p>
    </section>
  );
}

export function ForgotPassword() {
  const { config } = useAuth();
  const { busy, error, run } = useAction();
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const turnstile = useRef<TurnstileHandle>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (await run(() => api("/auth/forgot", { json: { email, turnstileToken } }))) setSent(true);
    else turnstile.current?.reset();
  }
  return (
    <section className="narrow">
      <h1>Reset your password</h1>
      {sent ? (
        <Notice kind="ok">If an account exists for {email}, we&rsquo;ve sent a reset link. It expires in an hour.</Notice>
      ) : (
        <form onSubmit={submit} className="stack">
          {config && !config.emailEnabled && <Notice kind="warn">Email sending isn&rsquo;t configured on this server yet.</Notice>}
          <Field label="Email">
            <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </Field>
          <Turnstile ref={turnstile} siteKey={config?.turnstileSiteKey} action="forgot" onToken={setTurnstileToken} />
          <ErrorBox error={error} />
          <button disabled={busy || (!!config?.turnstileSiteKey && !turnstileToken)}>Send reset link</button>
        </form>
      )}
      <p>
        <Link to="/login">Back to sign in</Link>
      </p>
    </section>
  );
}

export function ResetPassword() {
  const navigate = useNavigate();
  const { busy, error, run } = useAction();
  const [password, setPassword] = useState("");
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (await run(() => api("/auth/reset", { json: { token: tokenFromHash(), password } }))) navigate("/login", { replace: true });
  }
  return (
    <section className="narrow">
      <h1>Choose a new password</h1>
      <form onSubmit={submit} className="stack">
        <Field label="New password" hint="At least 12 characters. You'll still need your authenticator code to sign in.">
          <input type="password" autoComplete="new-password" minLength={12} required value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <ErrorBox error={error} />
        <button disabled={busy}>Set password</button>
      </form>
    </section>
  );
}
