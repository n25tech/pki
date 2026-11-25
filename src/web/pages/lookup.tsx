import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api, type Ca, type Certificate } from "../lib/api";
import { formatDate } from "../lib/files";
import { ErrorBox, Field, Notice, StatusBadge, useAction } from "../components/ui";

type Result =
  | { result: "ca"; ca: Ca }
  | { result: "unknown"; subject: string; issuer: string; serial: string; fingerprint: string }
  | {
      result: "issued";
      subject: string;
      serial: string;
      fingerprint: string;
      notAfter: number;
      status: "valid" | "revoked" | "expired";
      revokedVia: { id: string; name: string } | null;
      chain: { id: string; name: string; kind: string }[];
      certificate: Certificate | null;
    };

export function Lookup() {
  const [pem, setPem] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const { busy, error, run } = useAction();

  async function submit(e: FormEvent) {
    e.preventDefault();
    setResult(null);
    const res = await run(() => api<Result>("/lookup", { json: { certificatePem: pem } }));
    if (res) setResult(res);
  }

  return (
    <section className="narrow">
      <h1>Look up a certificate</h1>
      <p>Check whether a certificate was issued by one of your CAs, and whether it&rsquo;s still valid.</p>
      <form onSubmit={submit} className="stack">
        <Field label="Certificate (PEM)" hint={<>Get one from a server with: <code>openssl s_client -connect host:443 &lt;/dev/null | openssl x509</code></>}>
          <textarea rows={8} className="mono" required value={pem} onChange={(e) => setPem(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
        </Field>
        <Field label="…or choose a file">
          <input type="file" accept=".pem,.crt,.cer" onChange={async (e) => {
            const file = e.target.files?.[0];
            if (file) setPem(await file.text());
          }} />
        </Field>
        <ErrorBox error={error} />
        <button disabled={busy}>{busy ? "Checking…" : "Look up"}</button>
      </form>

      {result?.result === "ca" && (
        <Notice kind="ok">
          This is your CA certificate <Link to={`/cas/${result.ca.id}`}>{result.ca.name}</Link>.
        </Notice>
      )}
      {result?.result === "unknown" && (
        <Notice kind="warn">
          <strong>Not issued by any of your CAs.</strong>
          <br />
          Subject: {result.subject}
          <br />
          Issuer: {result.issuer}
        </Notice>
      )}
      {result?.result === "issued" && (
        <div className="card stack">
          <div className="row">
            <strong>Issued by your CA</strong> <StatusBadge status={result.status} notAfter={result.notAfter} />
          </div>
          <div>
            Chain:{" "}
            {result.chain.map((ca, i) => (
              <span key={ca.id}>
                {i > 0 && " → "}
                <Link to={`/cas/${ca.id}`}>{ca.name}</Link>
              </span>
            ))}
          </div>
          <div className="muted small">
            {result.subject} · expires {formatDate(result.notAfter)} · serial <code>{result.serial}</code>
          </div>
          {result.revokedVia && <Notice kind="warn">Its CA “{result.revokedVia.name}” has been revoked.</Notice>}
          {result.certificate ? (
            <Link to={`/certificates/${result.certificate.id}`}>Open in inventory</Link>
          ) : (
            <p className="muted small">Signed by your CA but not in the inventory (perhaps issued elsewhere with the same key).</p>
          )}
        </div>
      )}
    </section>
  );
}
