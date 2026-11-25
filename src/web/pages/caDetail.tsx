import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import * as pki from "../../shared/pki";
import { api, type Ca, type Certificate } from "../lib/api";
import { useAuth } from "../lib/auth";
import { publishRootCrl, unlockRootKey } from "../lib/ca";
import { download, formatDate, formatDateTime, slug } from "../lib/files";
import { rootKeys, useRootKey } from "../lib/rootKeys";
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
  const [params] = useSearchParams();
  const rootKey = useRootKey(root.id);
  const action = useAction();
  const [message, setMessage] = useState<string | null>(null);

  async function refreshCrl() {
    if (!rootKey) return;
    const res = await action.run(() => publishRootCrl(root, children, rootKey));
    if (res) {
      setMessage("Root CRL refreshed.");
      reload();
    }
  }

  async function revoke(inter: Ca) {
    if (!rootKey) return;
    if (!confirm(`Revoke "${inter.name}"? It will stop issuing certificates, its stored key is destroyed, and this can't be undone.`)) return;
    const res = await action.run(() => publishRootCrl(root, children, rootKey, [inter], 1));
    if (res) {
      setMessage(`"${inter.name}" is revoked.`);
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
        <Notice kind="ok">Root CA registered. Next, create an intermediate below. Your root key is still unlocked in this tab.</Notice>
      )}

      <div className="grid2">
        <div>
          <h2>Details</h2>
          <CaFacts ca={root} />
          <h3>Allowed names</h3>
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

        <div>
          <h2>Root key</h2>
          <RootKeyPanel root={root} />
          {rootKey && (
            <button className="secondary" disabled={action.busy} onClick={refreshCrl}>
              Refresh root CRL
            </button>
          )}
        </div>
      </div>

      {message && <Notice kind="ok">{message}</Notice>}
      <ErrorBox error={action.error} />

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
                    <button className="danger small" disabled={!rootKey || action.busy} title={rootKey ? "" : "Unlock the root key first"} onClick={() => revoke(inter)}>
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <NewIntermediate root={root} rootKey={rootKey} onCreated={reload} />
    </section>
  );
}

function RootKeyPanel({ root }: { root: Ca }) {
  const rootKey = useRootKey(root.id);
  const { error, run } = useAction();

  if (rootKey) {
    return (
      <Notice kind="ok">
        Unlocked in this tab (held in memory only).{" "}
        <button className="link" onClick={() => rootKeys.forget(root.id)}>
          Lock
        </button>
      </Notice>
    );
  }
  return (
    <div className="stack">
      <p className="muted small">
        Creating or revoking intermediates and refreshing the root CRL need your root key. It&rsquo;s used in this browser
        tab only and never uploaded.
      </p>
      <Field label="Root key file (.key.pem)">
        <input
          type="file"
          accept=".pem,.key,application/x-pem-file"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void run(async () => rootKeys.set(root.id, await unlockRootKey(root, await file.text())));
            e.target.value = "";
          }}
        />
      </Field>
      <ErrorBox error={error} />
    </div>
  );
}

function NewIntermediate({ root, rootKey, onCreated }: { root: Ca; rootKey: CryptoKey | undefined; onCreated: () => void }) {
  const { config } = useAuth();
  const { busy, error, run } = useAction();
  const [name, setName] = useState(`${root.name.replace(/\s*Root\s*CA$/i, "")} Issuing CA`.trim());
  const [algorithm, setAlgorithm] = useState<pki.KeyAlgorithm>("ECDSA-P256");
  const [years, setYears] = useState(5);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!rootKey || !config) return;
    const ok = await run(async () => {
      const { certificate, keys } = await pki.createIntermediateCa({
        issuer: new pki.x509.X509Certificate(root.certificatePem),
        issuerKey: rootKey,
        subject: { commonName: name.trim() },
        keyAlgorithm: algorithm,
        validityDays: years * 365,
        crlUrl: `${config.crlBaseUrl}/${root.id}.crl`,
        issuerCertUrl: `${config.crlBaseUrl}/${root.id}.crt`,
      });
      return api("/cas/intermediates", {
        json: {
          rootId: root.id,
          name: name.trim(),
          certificatePem: certificate.toString("pem"),
          privateKeyPem: pki.privateKeyToPem(await pki.exportPrivateKey(keys.privateKey)),
        },
      });
    });
    if (ok) onCreated();
  }

  if (root.revokedAt) return null;
  return (
    <form onSubmit={submit} className="card stack">
      <h3>New intermediate CA</h3>
      <p className="muted small">
        Signed by your root in this browser. Its private key is then stored encrypted on the server, so certificates can
        be issued without your root key.
      </p>
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
        <button disabled={busy || !rootKey}>{busy ? "Creating…" : rootKey ? "Create intermediate" : "Unlock the root key to continue"}</button>
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
