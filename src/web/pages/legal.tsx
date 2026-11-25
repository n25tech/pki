export function Legal() {
  return (
    <section className="narrow prose">
      <h1>Disclaimer, terms &amp; privacy</h1>

      <h2 id="disclaimer">Disclaimer</h2>
      <p>
        <strong>This is not a production PKI.</strong> It&rsquo;s a convenience tool for homelabs and internal,
        non-critical services. It hasn&rsquo;t been independently audited, it isn&rsquo;t operated to the standards of a
        public certificate authority, and it stores your CA private keys (encrypted) on a shared hosted service. For anything
        with a real security, compliance or availability requirement, use{" "}
        <a href="https://letsencrypt.org/">Let&rsquo;s Encrypt</a> or a properly operated CA.
      </p>
      <p>
        Root CAs created here are restricted by name constraints to the private names you choose, which limits what a
        leaked key could be used for. You are responsible for which roots you install on your devices.
      </p>

      <h2 id="terms">Terms of use</h2>
      <ul>
        <li>The service is provided “as is”, without warranty of any kind, and may change or stop at any time.</li>
        <li>You&rsquo;re responsible for keeping your recovery codes, any key backups and exported data safe.</li>
        <li>Don&rsquo;t use the service to impersonate others, intercept traffic you aren&rsquo;t authorized to, or break the law.</li>
        <li>We may suspend accounts that abuse the service.</li>
        <li>To the extent permitted by law, we aren&rsquo;t liable for any loss arising from your use of the service.</li>
      </ul>

      <h2 id="privacy">Privacy</h2>
      <ul>
        <li>We store your email address, a password hash, your two-factor secret (encrypted), your CA certificates and their private keys (encrypted), the certificates you issue, and an activity log with IP addresses.</li>
        <li>Private keys generated in your browser for end-entity certificates are never sent to us.</li>
        <li>CA certificates and CRLs are public by design: they&rsquo;re served at their distribution URLs.</li>
        <li>Data is hosted on Cloudflare. We don&rsquo;t sell data or use third-party analytics or advertising.</li>
        <li>You can export your data or delete your account at any time from the account page. Deletion is immediate.</li>
      </ul>
      <p className="muted small">The source code is public at <a href="https://github.com/n25tech/pki">github.com/n25tech/pki</a>.</p>
    </section>
  );
}
