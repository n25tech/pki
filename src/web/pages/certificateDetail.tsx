import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { api, type Certificate } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDate, formatDateTime, lines } from "../lib/files";
import { CertificateDownloads } from "../components/downloads";
import { ErrorBox, Field, Loading, Notice, Pem, StatusBadge, useAction } from "../components/ui";

interface Detail {
  certificate: Certificate;
  chainPem: string[];
  issuer: { id: string; name: string };
  root: { id: string; name: string };
}

export function CertificateDetail() {
  const { id } = useParams();
  const { config } = useAuth();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [tags, setTags] = useState("");
  const [notes, setNotes] = useState("");
  const [reason, setReason] = useState(1);
  const save = useAction();
  const revoke = useAction();

  const load = useCallback(() => {
    api<Detail>(`/certificates/${id}`)
      .then((d) => {
        setDetail(d);
        setTags(d.certificate.tags.join(" "));
        setNotes(d.certificate.notes);
      })
      .catch((e) => setLoadError(e.message));
  }, [id]);
  useEffect(load, [load]);

  if (loadError) return <ErrorBox error={loadError} />;
  if (!detail) return <Loading />;
  const c = detail.certificate;

  return (
    <section>
      <div className="page-head">
        <div>
          <p className="muted small">
            Issued by <Link to={`/cas/${detail.issuer.id}`}>{detail.issuer.name}</Link> · root{" "}
            <Link to={`/cas/${detail.root.id}`}>{detail.root.name}</Link>
          </p>
          <h1>{c.commonName}</h1>
        </div>
        <StatusBadge status={c.status} notAfter={c.notAfter} />
      </div>
      {c.revokedAt && (
        <Notice kind="warn">
          Revoked {formatDateTime(c.revokedAt)} ({config?.revocationReasons[String(c.revocationReason)] ?? "unspecified"}).
        </Notice>
      )}

      <div className="grid2">
        <div>
          <dl className="facts">
            <dt>Names</dt>
            <dd>{[...c.sans.dns, ...c.sans.ip].join(", ")}</dd>
            <dt>Type</dt>
            <dd>{c.profile === "server" ? "TLS server" : "TLS client"}</dd>
            <dt>Key</dt>
            <dd>{c.keyAlgorithm}</dd>
            <dt>Valid</dt>
            <dd>
              {formatDate(c.notBefore)} – {formatDate(c.notAfter)}
            </dd>
            <dt>Serial</dt>
            <dd>
              <code>{c.serial}</code>
            </dd>
            <dt>SHA-256</dt>
            <dd>
              <code className="wrap">{c.fingerprint}</code>
            </dd>
            <dt>Issued</dt>
            <dd>{formatDateTime(c.createdAt)}</dd>
          </dl>
          <h2>Downloads</h2>
          <CertificateDownloads cert={c} chainPem={detail.chainPem} />
          <p className="muted small">The private key isn&rsquo;t stored here. Use the copy you downloaded when it was issued.</p>
        </div>

        <div className="stack">
          <h2>Notes</h2>
          <Field label="Tags">
            <input value={tags} onChange={(e) => setTags(e.target.value)} />
          </Field>
          <Field label="Notes">
            <textarea rows={4} value={notes} onChange={(e) => setNotes(e.target.value)} />
          </Field>
          <ErrorBox error={save.error} />
          <div>
            <button className="secondary" disabled={save.busy} onClick={() => save.run(async () => {
              await api(`/certificates/${c.id}`, { method: "PATCH", json: { tags: lines(tags), notes } });
              load();
            })}>
              Save
            </button>
          </div>

          {!c.revokedAt && (
            <div className="card stack">
              <h3>Revoke</h3>
              <p className="muted small">
                Adds this certificate to the CA&rsquo;s revocation list immediately. Many clients don&rsquo;t check
                revocation lists for private CAs, so also replace the certificate and remove it from the device.
              </p>
              <Field label="Reason">
                <select value={reason} onChange={(e) => setReason(Number(e.target.value))}>
                  {Object.entries(config?.revocationReasons ?? {}).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </Field>
              <ErrorBox error={revoke.error} />
              <div>
                <button className="danger" disabled={revoke.busy} onClick={() => {
                  if (!confirm(`Revoke ${c.commonName}? This can't be undone.`)) return;
                  void revoke.run(async () => {
                    await api(`/certificates/${c.id}/revoke`, { json: { reason } });
                    load();
                  });
                }}>
                  Revoke certificate
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
      <h2>Certificate (PEM)</h2>
      <Pem text={c.certificatePem} />
    </section>
  );
}
