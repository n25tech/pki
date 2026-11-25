import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import * as pki from "../../shared/pki";
import { api, type Ca, type Certificate } from "../lib/api";
import { useAuth } from "../lib/auth";
import { download, formatDate, formatDateTime, slug } from "../lib/files";
import { ErrorBox, Field, Loading, Notice, StatusBadge, useAction } from "../components/ui";

interface Detail {
  ca: Ca;
  parent: Ca | null;
  children: Ca[];
  crlPem: string | null;
}

export function CaDetail() {
  const { id } = useParams();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api<Detail>(`/cas/${id}`)
      .then(setDetail)
      .catch((e) => setError(e.message));
  }, [id]);
  useEffect(load, [load]);

  if (error) return <ErrorBox error={error} />;
  if (!detail) return <Loading />;
  return detail.ca.kind === "root" ? <RootView detail={detail} reload={load} /> : <IntermediateView detail={detail} />;
}

function CaFacts({ ca }: { ca: Ca }) {
  const { config } = useAuth();
  return (
    <dl className="facts">
      <dt>Subject</dt>
      <dd>{ca.subject}</dd>
      <dt>Key</dt>
      <dd>{ca.keyAlgorithm}</dd>
      <dt>Valid</dt>
      <dd>
        {formatDate(ca.notBefore)} – {formatDate(ca.notAfter)}
      </dd>
      <dt>Serial</dt>
      <dd>
        <code>{ca.serial}</code>
      </dd>
      <dt>SHA-256</dt>
      <dd>
        <code className="wrap">{ca.fingerprint}</code>
      </dd>
      {config && (
        <>
          <dt>Public URLs</dt>
          <dd>
            <code>
              {config.crlBaseUrl}/{ca.id}.crt
            </code>
            <br />
            <code>
              {config.crlBaseUrl}/{ca.id}.crl
            </code>
          </dd>
        </>
      )}
      <dt>CRL</dt>
      <dd>
        #{ca.crlNumber}, next update {formatDateTime(ca.crlNextUpdate)}
      </dd>
    </dl>
  );
}

function RootView({ detail, reload }: { detail: Detail; reload: () => void }) {
  const { ca: root, children } = detail;
  const { config } = useAuth();
  const [params] = useSearchParams();
  const action = useAction();
  const [message, setMessage] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<Ca | null>(null);
  const [reason, setReason] = useState(1);

  async function revoke() {
    if (!revoking) return;
    const res = await action.run(() => api(`/cas/${revoking.id}/revoke`, { json: { reason } }));
    if (res) {
      setMessage(`"${revoking.name}" is revoked and listed on the root's CRL.`);
      setRevoking(null);
      reload();
    }
  }

  return (
    <section>
      <div className="page-head">
        <div>
          <p className="muted small">Root CA</p>
          <h1>{root.name}</h1>
        </div>
        <StatusBadge status={root.status} />
      </div>
      {params.get("created") && children.length === 0 && (
        <Notice kind="ok">Root CA saved. Next, create an intermediate below. Certificates are issued from intermediates.</Notice>
      )}

      <div className="grid2">
        <div>
          <h2>Details</h2>
          <CaFacts ca={root} />
        </div>
        <div>
          <h2>Allowed names</h2>
          <p className="muted small">Clients reject any certificate from this root for other names.</p>
          <ul className="tags">
            {[...(root.nameConstraints?.dns ?? []), ...(root.nameConstraints?.ip ?? [])].map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
          <div className="row">
            <button className="secondary" onClick={() => download(`${slug(root.name)}.crt`, root.certificatePem)}>
              Download certificate
            </button>
            <Link className="button secondary" to="/trust">
              How to trust it
            </Link>
          </div>
        </div>
      </div>

      {message && <Notice kind="ok">{message}</Notice>}

      <h2>Intermediate CAs</h2>
      {children.length === 0 ? (
        <p className="muted">None yet.</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Key</th>
              <th>Expires</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {children.map((inter) => (
              <tr key={inter.id}>
                <td>
                  <Link to={`/cas/${inter.id}`}>{inter.name}</Link>
                </td>
                <td>{inter.keyAlgorithm}</td>
                <td>{formatDate(inter.notAfter)}</td>
                <td>
                  <StatusBadge status={inter.status} notAfter={inter.notAfter} />
                </td>
                <td className="right">
                  {!inter.revokedAt && (
                    <button className="danger small" onClick={() => setRevoking(inter)}>
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {revoking && (
        <div className="card stack danger-zone">
          <h3>Revoke &ldquo;{revoking.name}&rdquo;?</h3>
          <p className="muted small">
            It&rsquo;s added to the root&rsquo;s revocation list, can&rsquo;t issue certificates any more, and its stored
            key is destroyed. Certificates it issued stop validating for clients that check revocation. This can&rsquo;t
            be undone.
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
          <ErrorBox error={action.error} />
          <div className="row">
            <button className="danger" disabled={action.busy} onClick={revoke}>
              {action.busy ? "Revoking…" : "Revoke intermediate"}
            </button>
            <button className="link" onClick={() => setRevoking(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      <NewIntermediate root={root} onCreated={reload} />
    </section>
  );
}

function NewIntermediate({ root, onCreated }: { root: Ca; onCreated: () => void }) {
  const { busy, error, run } = useAction();
  const [name, setName] = useState(`${root.name.replace(/\s*Root\s*CA$/i, "")} Issuing CA`.trim());
  const [algorithm, setAlgorithm] = useState<pki.KeyAlgorithm>("ECDSA-P256");
  const [years, setYears] = useState(5);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const ok = await run(async () => {
      // Generate the key pair here (fast in the browser, slow for RSA in a Worker); the root signs it on the server.
      const keys = await pki.generateKeyPair(algorithm);
      const csr = await pki.createCsr(keys, name.trim(), { dns: [], ip: [] });
      return api("/cas/intermediates", {
        json: {
          rootId: root.id,
          name: name.trim(),
          csrPem: csr.toString("pem"),
          privateKeyPem: pki.privateKeyToPem(await pki.exportPrivateKey(keys.privateKey)),
          validityDays: years * 365,
        },
      });
    });
    if (ok) onCreated();
  }

  if (root.revokedAt || root.status !== "valid") return null;
  return (
    <form onSubmit={submit} className="card stack">
      <h3>New intermediate CA</h3>
      <p className="muted small">Signed by this root. Its key is stored encrypted and used to issue certificates.</p>
      <div className="grid3">
        <Field label="Name">
          <input required maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Key type">
          <select value={algorithm} onChange={(e) => setAlgorithm(e.target.value as pki.KeyAlgorithm)}>
            <option value="ECDSA-P256">ECDSA P-256 (recommended)</option>
            <option value="ECDSA-P384">ECDSA P-384</option>
            <option value="RSA-2048">RSA 2048 (for old clients)</option>
          </select>
        </Field>
        <Field label="Valid for (years)" hint="Capped at the root's expiry">
          <input type="number" min={1} max={20} value={years} onChange={(e) => setYears(Number(e.target.value))} />
        </Field>
      </div>
      <ErrorBox error={error} />
      <div>
        <button disabled={busy}>{busy ? "Creating…" : "Create intermediate"}</button>
      </div>
    </form>
  );
}

function IntermediateView({ detail }: { detail: Detail }) {
  const { ca, parent } = detail;
  const [certs, setCerts] = useState<Certificate[] | null>(null);
  useEffect(() => {
    api<{ certificates: Certificate[] }>(`/certificates?caId=${ca.id}`).then((r) => setCerts(r.certificates));
  }, [ca.id]);

  const chain = [ca.certificatePem, parent?.certificatePem ?? ""].join("");
  return (
    <section>
      <div className="page-head">
        <div>
          <p className="muted small">
            Intermediate CA · signed by {parent && <Link to={`/cas/${parent.id}`}>{parent.name}</Link>}
          </p>
          <h1>{ca.name}</h1>
        </div>
        <div className="row">
          <StatusBadge status={ca.status} notAfter={ca.notAfter} />
          {ca.status === "valid" && (
            <Link className="button" to={`/certificates/new?caId=${ca.id}`}>
              Issue certificate
            </Link>
          )}
        </div>
      </div>
      {ca.revokedAt && <Notice kind="warn">Revoked {formatDateTime(ca.revokedAt)}. Its key has been destroyed.</Notice>}
      <CaFacts ca={ca} />
      <div className="row">
        <button className="secondary" onClick={() => download(`${slug(ca.name)}.crt`, ca.certificatePem)}>
          Download certificate
        </button>
        <button className="secondary" onClick={() => download(`${slug(ca.name)}-chain.pem`, chain)}>
          Download CA chain
        </button>
      </div>
      <h2>Issued certificates</h2>
      {!certs ? (
        <Loading />
      ) : certs.length === 0 ? (
        <p className="muted">None yet.</p>
      ) : (
        <ul className="list">
          {certs.map((c) => (
            <li key={c.id}>
              <Link to={`/certificates/${c.id}`}>{c.commonName}</Link> <span className="muted small">expires {formatDate(c.notAfter)}</span>{" "}
              <StatusBadge status={c.status} notAfter={c.notAfter} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
