import { useState, type JSX } from "react";
import { Code } from "../components/ui";

const GUIDES: { id: string; label: string; body: JSX.Element }[] = [
  {
    id: "windows",
    label: "Windows",
    body: (
      <>
        <p>In an administrator PowerShell or Command Prompt:</p>
        <Code>certutil -addstore -f Root root.crt</Code>
        <p className="muted small">
          Or double-click the .crt → Install Certificate → Local Machine → “Place all certificates in the following
          store” → Trusted Root Certification Authorities. Chrome and Edge use this store.
        </p>
      </>
    ),
  },
  {
    id: "macos",
    label: "macOS",
    body: (
      <>
        <Code>sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root.crt</Code>
        <p className="muted small">Or open the file in Keychain Access, add it to System, and set “When using this certificate” to Always Trust. Safari and Chrome use the keychain.</p>
      </>
    ),
  },
  {
    id: "debian",
    label: "Debian / Ubuntu",
    body: <Code>{`sudo cp root.crt /usr/local/share/ca-certificates/lab-root.crt\nsudo update-ca-certificates`}</Code>,
  },
  {
    id: "fedora",
    label: "Fedora / RHEL",
    body: <Code>{`sudo cp root.crt /etc/pki/ca-trust/source/anchors/lab-root.crt\nsudo update-ca-trust`}</Code>,
  },
  {
    id: "arch",
    label: "Arch",
    body: <Code>sudo trust anchor --store root.crt</Code>,
  },
  {
    id: "firefox",
    label: "Firefox",
    body: (
      <p>
        Firefox has its own store: Settings → Privacy &amp; Security → Certificates → View Certificates → Authorities →
        Import, then tick “Trust this CA to identify websites”. On Windows and macOS you can instead set{" "}
        <code>security.enterprise_roots.enabled</code> to <code>true</code> in <code>about:config</code> to use the
        system store.
      </p>
    ),
  },
  {
    id: "ios",
    label: "iPhone / iPad",
    body: (
      <ol>
        <li>Open the root .crt on the device (AirDrop, email or Safari) and allow the profile download.</li>
        <li>Settings → General → VPN &amp; Device Management → install the profile.</li>
        <li>Settings → General → About → Certificate Trust Settings → turn on full trust for the root.</li>
      </ol>
    ),
  },
  {
    id: "android",
    label: "Android",
    body: (
      <p>
        Settings → Security &amp; privacy → More security settings → Encryption &amp; credentials → Install a certificate
        → CA certificate. (Menu names vary by maker.) Chrome trusts user-installed CAs; many other apps don&rsquo;t
        unless they opt in.
      </p>
    ),
  },
  {
    id: "java",
    label: "Java",
    body: (
      <>
        <Code>keytool -importcert -cacerts -alias lab-root -file root.crt</Code>
        <p className="muted small">The default store password is <code>changeit</code>.</p>
      </>
    ),
  },
  {
    id: "docker",
    label: "Docker & containers",
    body: (
      <>
        <p>In a Debian/Ubuntu-based image:</p>
        <Code>{`COPY root.crt /usr/local/share/ca-certificates/lab-root.crt\nRUN update-ca-certificates`}</Code>
        <p>For the Docker daemon to trust a private registry:</p>
        <Code>{`sudo mkdir -p /etc/docker/certs.d/registry.lan\nsudo cp root.crt /etc/docker/certs.d/registry.lan/ca.crt`}</Code>
      </>
    ),
  },
  {
    id: "runtimes",
    label: "Node, Python, curl",
    body: (
      <>
        <Code>{`export NODE_EXTRA_CA_CERTS=/path/to/root.crt      # Node.js\nexport REQUESTS_CA_BUNDLE=/path/to/root.crt       # Python requests\ncurl --cacert /path/to/root.crt https://nas.lan`}</Code>
        <p className="muted small">Python&rsquo;s requests replaces the default bundle with this file; point it at a combined bundle if you also need public sites.</p>
      </>
    ),
  },
];

export function TrustGuide() {
  const [open, setOpen] = useState("windows");
  return (
    <section>
      <h1>Trust your root CA</h1>
      <p>
        Devices only accept your certificates after your <strong>root</strong> certificate is installed as trusted.
        Download it from the root CA&rsquo;s page (it&rsquo;s the public certificate, never the key), then follow the
        steps for each device. Only install roots you created.
      </p>
      <div className="guide">
        <nav className="guide-nav">
          {GUIDES.map((g) => (
            <button key={g.id} className={g.id === open ? "tab active" : "tab"} onClick={() => setOpen(g.id)}>
              {g.label}
            </button>
          ))}
        </nav>
        <div className="guide-body">{GUIDES.find((g) => g.id === open)!.body}</div>
      </div>
    </section>
  );
}
