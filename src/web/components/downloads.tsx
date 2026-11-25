import { download, kubernetesSecret, slug } from "../lib/files";
import type { Certificate } from "../lib/api";
import { Code } from "./ui";

/** Download buttons for an issued certificate. `keyPem` is only available right after issuing in the browser. */
export function CertificateDownloads({ cert, chainPem, keyPem }: { cert: Certificate; chainPem: string[]; keyPem?: string }) {
  const base = slug(cert.commonName.replace(/^\*\./, "wildcard."));
  // Full chain for servers: leaf + intermediate (the root is installed on clients, not sent).
  const fullchain = cert.certificatePem + (chainPem[0] ?? "");
  const rootPem = chainPem[chainPem.length - 1] ?? "";
  return (
    <div className="stack">
      <div className="row wrap">
        <button className="secondary" onClick={() => download(`${base}.crt`, cert.certificatePem)}>
          Certificate
        </button>
        <button className="secondary" onClick={() => download(`${base}.fullchain.pem`, fullchain)}>
          Full chain
        </button>
        <button className="secondary" onClick={() => download(`${base}.root.crt`, rootPem)}>
          Root certificate
        </button>
        {keyPem && (
          <>
            <button onClick={() => download(`${base}.key.pem`, keyPem)}>Private key</button>
            <button className="secondary" onClick={() => download(`${base}-tls-secret.yaml`, kubernetesSecret(cert.commonName, fullchain, keyPem), "application/yaml")}>
              Kubernetes secret
            </button>
          </>
        )}
      </div>
      <details>
        <summary>Need a .pfx / .p12 (Windows, Java)?</summary>
        <p className="muted small">Combine the key and full chain with OpenSSL:</p>
        <Code>{`openssl pkcs12 -export -out ${base}.pfx -inkey ${base}.key.pem -in ${base}.fullchain.pem`}</Code>
      </details>
    </div>
  );
}
