import { useEffect, useState } from "react";

type Health = "checking" | "ok" | "down";

export function App() {
  const [health, setHealth] = useState<Health>("checking");

  useEffect(() => {
    fetch("/api/health")
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((body: { ok?: boolean }) => setHealth(body.ok ? "ok" : "down"))
      .catch(() => setHealth("down"));
  }, []);

  return (
    <main className="page">
      <header>
        <h1>Private PKI</h1>
        <p className="lede">
          Create your own certificate authority, issue certificates for your homelab or internal services,
          keep track of what you issued, and revoke individual certificates.
        </p>
      </header>

      <section className="disclaimer" role="note">
        <h2>Not for production</h2>
        <p>
          This is a convenience tool for labs and internal, non-critical use. It is not a hardened or
          production PKI. For anything with a real security requirement, use{" "}
          <a href="https://letsencrypt.org/">Let&rsquo;s Encrypt</a> or a properly operated CA.
        </p>
      </section>

      <p className={`status status-${health}`}>
        API: {health === "checking" ? "checking…" : health === "ok" ? "online" : "unreachable"}
      </p>
    </main>
  );
}
