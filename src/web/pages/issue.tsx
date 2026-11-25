import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import * as pki from "../../shared/pki";
import { api, type Ca, type Certificate } from "../lib/api";
import { useAuth } from "../lib/auth";
import { lines } from "../lib/files";
import { CertificateDownloads } from "../components/downloads";
import { ErrorBox, Field, Loading, Notice, useAction } from "../components/ui";

type Issued = { certificate: Certificate; chainPem: string[]; keyPem?: string };

const isIp = (s: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || s.includes(":");

export function IssueCertificate() {
  const { config } = useAuth();
  const [params] = useSearchParams();
  const [cas, setCas] = useState<Ca[] | null>(null);
  const [caId, setCaId] = useState(params.get("caId") ?? "");
  const [names, setNames] = useState("");
  const [commonName, setCommonName] = useState("");
  const [profile, setProfile] = useState<"server" | "client">("server");
  const [validityDays, setValidityDays] = useState(90);
  const [mode, setMode] = useState<"generate" | "csr">("generate");
  const [algorithm, setAlgorithm] = useState<pki.KeyAlgorithm>("ECDSA-P256");
  const [csrPem, setCsrPem] = useState("");
  const [tags, setTags] = useState("");
  const [notes, setNotes] = useState("");
  const [issued, setIssued] = useState<Issued | null>(null);
  const { busy, error, run } = useAction();

  useEffect(() => {
    api<{ cas: Ca[] }>("/cas").then((r) => {
      const usable = r.cas.filter((c) => c.kind === "intermediate" && c.status === "valid");
      setCas(r.cas);
      if (!caId && usable[0]) setCaId(usable[0].id);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Pre-fill names from a pasted CSR.
  useEffect(() => {
    if (mode !== "csr" || !csrPem.includes("BEGIN")) return;
    try {
      const csr = new pki.x509.Pkcs10CertificateRequest(csrPem);
      const sans = pki.csrSubjectAltNames(csr);
      const all = [...sans.dns, ...sans.ip];
      if (all.length && !names) setNames(all.join("\n"));
      const cn = pki.csrCommonName(csr);
      if (cn && !commonName) setCommonName(cn);
    } catch {
      // not a complete CSR yet
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [csrPem, mode]);

  if (!cas) return <Loading />;
  const intermediates = cas.filter((c) => c.kind === "intermediate" && c.status === "valid");
  const root = cas.find((c) => c.id === cas.find((x) => x.id === caId)?.parentId);

  if (intermediates.length === 0) {
    return (
      <section className="narrow">
        <h1>Issue a certificate</h1>
        <Notice kind="info">
          You need an intermediate CA first. <Link to="/">Go to your CAs</Link>.
        </Notice>
      </section>
    );
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    const all = lines(names);
    const sans = { dns: all.filter((n) => !isIp(n)), ip: all.filter(isIp) };
    const cn = commonName.trim() || all[0];
    const res = await run(async () => {
      let keyPem: string | undefined;
      let csr = csrPem;
      if (mode === "generate") {
        const keys = await pki.generateKeyPair(algorithm);
        csr = (await pki.createCsr(keys, cn, sans)).toString("pem");
        keyPem = pki.privateKeyToPem(await pki.exportPrivateKey(keys.privateKey));
      }
      const out = await api<{ certificate: Certificate; chainPem: string[] }>("/certificates", {
        json: {
          caId,
          csrPem: csr,
          commonName: cn,
          sans: all.length ? sans : undefined,
          profile,
          validityDays,
          tags: lines(tags),
          notes,
        },
      });
      return { ...out, keyPem };
    });
    if (res) setIssued(res);
  }

  if (issued) {
    return (
      <section className="narrow">
        <h1>Certificate issued</h1>
        <p>
          <strong>{issued.certificate.commonName}</strong>, valid until {new Date(issued.certificate.notAfter).toLocaleDateString()}.
        </p>
        {issued.keyPem && (
          <Notice kind="warn">
            <strong>Download the private key now.</strong> It was generated in your browser and isn&rsquo;t stored
            anywhere. If you lose it, issue a new certificate.
          </Notice>
        )}
        <CertificateDownloads cert={issued.certificate} chainPem={issued.chainPem} keyPem={issued.keyPem} />
        <div className="row">
          <Link className="button secondary" to={`/certificates/${issued.certificate.id}`}>
            View details
          </Link>
          <button className="link" onClick={() => setIssued(null)}>
            Issue another
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="narrow">
      <h1>Issue a certificate</h1>
      <form onSubmit={submit} className="stack">
        <Field label="Issuing CA">
          <select value={caId} onChange={(e) => setCaId(e.target.value)}>
            {intermediates.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </Field>
        {root?.nameConstraints && (
          <p className="muted small">
            Allowed names for this CA: {[...root.nameConstraints.dns.map((d) => `*.${d}`), ...root.nameConstraints.ip].join(", ")}
          </p>
        )}

        <div className="tabs" role="tablist">
          <button type="button" role="tab" aria-selected={mode === "generate"} className={mode === "generate" ? "tab active" : "tab"} onClick={() => setMode("generate")}>
            Generate key in browser
          </button>
          <button type="button" role="tab" aria-selected={mode === "csr"} className={mode === "csr" ? "tab active" : "tab"} onClick={() => setMode("csr")}>
            I have a CSR
          </button>
        </div>

        {mode === "generate" ? (
          <Field label="Key type" hint="The key is created here and never sent to the server.">
            <select value={algorithm} onChange={(e) => setAlgorithm(e.target.value as pki.KeyAlgorithm)}>
              <option value="ECDSA-P256">ECDSA P-256 (recommended)</option>
              <option value="ECDSA-P384">ECDSA P-384</option>
              <option value="RSA-2048">RSA 2048 (for old devices)</option>
              <option value="RSA-3072">RSA 3072</option>
            </select>
          </Field>
        ) : (
          <Field label="Certificate signing request (PEM)" hint="e.g. openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -subj /CN=nas.lan">
            <textarea rows={8} required className="mono" value={csrPem} onChange={(e) => setCsrPem(e.target.value)} placeholder="-----BEGIN CERTIFICATE REQUEST-----" />
          </Field>
        )}

        <Field label="DNS names and IP addresses (one per line)" hint={mode === "csr" ? "Leave empty to use the names in the CSR." : "Wildcards like *.k8s.lan are allowed."}>
          <textarea rows={4} required={mode === "generate"} value={names} onChange={(e) => setNames(e.target.value)} placeholder={"nas.home.arpa\n192.168.1.10"} />
        </Field>
        <Field label="Common name (optional)" hint="Defaults to the first name. Modern clients only check the names above.">
          <input maxLength={64} value={commonName} onChange={(e) => setCommonName(e.target.value)} />
        </Field>
        <div className="grid2">
          <Field label="Type">
            <select value={profile} onChange={(e) => setProfile(e.target.value as "server" | "client")}>
              <option value="server">TLS server</option>
              <option value="client">TLS client (mTLS)</option>
            </select>
          </Field>
          <Field label="Valid for (days)" hint={`Max ${config?.maxLeafValidityDays ?? 398}. Shorter is safer.`}>
            <input type="number" min={1} max={config?.maxLeafValidityDays ?? 398} value={validityDays} onChange={(e) => setValidityDays(Number(e.target.value))} />
          </Field>
        </div>
        <Field label="Tags (optional)" hint="Space or comma separated, e.g. nas storage">
          <input value={tags} onChange={(e) => setTags(e.target.value)} />
        </Field>
        <Field label="Notes (optional)">
          <textarea rows={2} maxLength={2000} value={notes} onChange={(e) => setNotes(e.target.value)} />
        </Field>
        <ErrorBox error={error} />
        <button disabled={busy}>{busy ? "Issuing…" : "Issue certificate"}</button>
      </form>
    </section>
  );
}
