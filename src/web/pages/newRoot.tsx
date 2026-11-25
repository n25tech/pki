import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import * as pki from "../../shared/pki";
import { api, type Ca } from "../lib/api";
import { download, lines, slug } from "../lib/files";
import { ErrorBox, Field, Notice, useAction } from "../components/ui";

type Generated = { certificatePem: string; keyPem: string };

export function NewRoot() {
  const navigate = useNavigate();
  const { busy, error, setError, run } = useAction();
  const [name, setName] = useState("Home Lab Root CA");
  const [organization, setOrganization] = useState("");
  const [algorithm, setAlgorithm] = useState<pki.KeyAlgorithm>("ECDSA-P384");
  const [years, setYears] = useState(10);
  const [dns, setDns] = useState(pki.DEFAULT_PERMITTED_DNS.join("\n"));
  const [ips, setIps] = useState(pki.DEFAULT_PERMITTED_IP.join("\n"));
  const [generated, setGenerated] = useState<Generated | null>(null);

  async function generate(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      let nameConstraints: pki.NameConstraintSpec;
      try {
        nameConstraints = pki.validateNameConstraints({ dns: lines(dns), ip: lines(ips) });
      } catch (err) {
        setError((err as Error).message);
        return;
      }
      const { certificate, keys } = await pki.createRootCa({
        subject: { commonName: name.trim(), organization: organization.trim() || undefined },
        keyAlgorithm: algorithm,
        validityDays: years * 365,
        nameConstraints,
      });
      setGenerated({
        certificatePem: certificate.toString("pem"),
        keyPem: pki.privateKeyToPem(await pki.exportPrivateKey(keys.privateKey)),
      });
    });
  }

  async function register() {
    if (!generated) return;
    const res = await run(() =>
      api<{ ca: Ca }>("/cas/roots", {
        json: { name: name.trim(), certificatePem: generated.certificatePem, privateKeyPem: generated.keyPem },
      }),
    );
    if (res) navigate(`/cas/${res.ca.id}?created=1`);
  }

  if (generated) {
    const base = slug(name);
    return (
      <section className="narrow">
        <h1>Review and save</h1>
        <p>
          Your root CA is ready. Saving stores the certificate and its private key (encrypted) so this service can
          sign intermediates and revocation lists for you.
        </p>
        <Notice kind="info">
          Optionally keep your own backup of the root key. Anyone with it can issue certificates for your allowed
          names, so store it somewhere safe (a password manager or encrypted drive).
        </Notice>
        <div className="row">
          <button type="button" className="secondary" onClick={() => download(`${base}.key.pem`, generated.keyPem)}>
            Download key backup
          </button>
          <button type="button" className="secondary" onClick={() => download(`${base}.crt`, generated.certificatePem)}>
            Download certificate
          </button>
        </div>
        <ErrorBox error={error} />
        <div className="row">
          <button disabled={busy} onClick={register}>
            {busy ? "Saving…" : "Save root CA"}
          </button>
          <button type="button" className="link" onClick={() => setGenerated(null)}>
            Start over
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="narrow">
      <h1>New root CA</h1>
      <p>
        The key pair is generated in your browser, then the certificate and key are stored with this service
        (the key encrypted) so it can create intermediates for you.
      </p>
      <form onSubmit={generate} className="stack">
        <Field label="Name" hint="Shown in certificate details, e.g. “Smith Home Lab Root CA”.">
          <input required maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Organization (optional)">
          <input maxLength={64} value={organization} onChange={(e) => setOrganization(e.target.value)} />
        </Field>
        <div className="grid2">
          <Field label="Key type">
            <select value={algorithm} onChange={(e) => setAlgorithm(e.target.value as pki.KeyAlgorithm)}>
              <option value="ECDSA-P384">ECDSA P-384 (recommended)</option>
              <option value="ECDSA-P256">ECDSA P-256</option>
              <option value="RSA-4096">RSA 4096 (slow to generate)</option>
              <option value="RSA-3072">RSA 3072</option>
            </select>
          </Field>
          <Field label="Valid for (years)">
            <input type="number" min={1} max={25} value={years} onChange={(e) => setYears(Number(e.target.value))} />
          </Field>
        </div>
        <fieldset>
          <legend>Allowed names</legend>
          <p className="muted small">
            This root can only ever be used for these names, even if a key leaks. Browsers and other clients enforce
            this, so it can&rsquo;t be used to impersonate public websites. Each DNS entry covers the name and all its
            subdomains.
          </p>
          <div className="grid2">
            <Field label="DNS suffixes (one per line)" hint="e.g. home.arpa, lan, internal, cluster.local, lab.example.com. Public suffixes on their own (com, co.uk, github.io…) aren’t allowed.">
              <textarea rows={5} value={dns} onChange={(e) => setDns(e.target.value)} />
            </Field>
            <Field label="IP ranges (CIDR, one per line)" hint="Leave empty to disallow IP addresses">
              <textarea rows={5} value={ips} onChange={(e) => setIps(e.target.value)} />
            </Field>
          </div>
        </fieldset>
        <ErrorBox error={error} />
        <button disabled={busy}>{busy ? "Generating…" : "Generate root CA"}</button>
      </form>
    </section>
  );
}
