import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { download, formatDateTime } from "../lib/files";
import { ErrorBox, Field, Notice, useAction } from "../components/ui";

interface AuditEvent {
  id: number;
  action: string;
  target: string | null;
  ip: string;
  created_at: number;
}

export function Account() {
  const { me, refresh } = useAuth();
  const navigate = useNavigate();
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const verify = useAction();
  const password = useAction();
  const exporter = useAction();
  const remove = useAction();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [passwordDone, setPasswordDone] = useState(false);
  const [verifySent, setVerifySent] = useState(false);
  const [confirmEmail, setConfirmEmail] = useState("");

  useEffect(() => {
    api<{ events: AuditEvent[] }>("/account/audit").then((r) => setEvents(r.events)).catch(() => setEvents([]));
  }, []);

  if (!me?.user) return null;
  const user = me.user;

  async function changePassword(e: FormEvent) {
    e.preventDefault();
    if (await password.run(() => api("/auth/password", { json: { currentPassword, newPassword } }))) {
      setPasswordDone(true);
      setCurrentPassword("");
      setNewPassword("");
    }
  }

  return (
    <section className="narrow">
      <h1>Account</h1>

      <h2>Email</h2>
      <p>
        {user.email} {user.emailVerified ? <span className="badge badge-valid">verified</span> : <span className="badge badge-expiring">unverified</span>}
      </p>
      {!user.emailVerified && (
        <>
          <button className="secondary" disabled={verify.busy || verifySent} onClick={async () => {
            if (await verify.run(() => api("/auth/resend-verification", { json: {} }))) setVerifySent(true);
          }}>
            {verifySent ? "Sent. Check your inbox" : "Resend verification email"}
          </button>
          <ErrorBox error={verify.error} />
        </>
      )}

      <h2>Two-factor authentication</h2>
      {user.mfaEnabled ? <p>On.</p> : <p><Link to="/setup-2fa">Set it up</Link> to start creating CAs.</p>}

      <h2>{user.hasPassword ? "Change password" : "Set a password"}</h2>
      {user.google && <p className="muted small">You can also sign in with Google.</p>}
      <form onSubmit={changePassword} className="stack">
        {user.hasPassword && (
          <Field label="Current password">
            <input type="password" autoComplete="current-password" required value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
          </Field>
        )}
        <Field label="New password" hint="At least 12 characters. Other sessions will be signed out.">
          <input type="password" autoComplete="new-password" minLength={12} required value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
        </Field>
        <ErrorBox error={password.error} />
        {passwordDone && <Notice kind="ok">Password updated.</Notice>}
        <div>
          <button className="secondary" disabled={password.busy}>Save password</button>
        </div>
      </form>

      {me.stage === "full" && (
        <>
          <h2>Export</h2>
          <p className="muted small">
            Downloads your CA certificates, root and intermediate private keys (unencrypted), CRLs and certificate
            inventory as JSON. Keep the file safe: anyone with it can issue certificates for your allowed names.
          </p>
          <button className="secondary" disabled={exporter.busy} onClick={() => exporter.run(async () => {
            const data = await api("/account/export");
            download(`pki-export-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(data, null, 2), "application/json");
          })}>
            Download export
          </button>
          <ErrorBox error={exporter.error} />
        </>
      )}

      <h2>Recent activity</h2>
      {events && events.length > 0 ? (
        <table className="table small">
          <tbody>
            {events.slice(0, 30).map((e) => (
              <tr key={e.id}>
                <td>{formatDateTime(e.created_at)}</td>
                <td>{e.action}</td>
                <td className="muted">{e.ip}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="muted">No activity yet.</p>
      )}

      <h2>Delete account</h2>
      <div className="card stack danger-zone">
        <p>
          Permanently deletes your account, every CA, the stored intermediate keys and the certificate inventory.
          Published CRLs and CA certificates stop being served. This can&rsquo;t be undone.
        </p>
        <Field label={`Type ${user.email} to confirm`}>
          <input value={confirmEmail} onChange={(e) => setConfirmEmail(e.target.value)} />
        </Field>
        <ErrorBox error={remove.error} />
        <div>
          <button className="danger" disabled={remove.busy || confirmEmail.trim().toLowerCase() !== user.email.toLowerCase()} onClick={async () => {
            if (await remove.run(() => api("/account", { method: "DELETE", json: { confirmEmail } }))) {
              await refresh();
              navigate("/register");
            }
          }}>
            Delete my account
          </button>
        </div>
      </div>
    </section>
  );
}
