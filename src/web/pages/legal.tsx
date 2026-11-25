const CONTACT = "privacy@n25tech.com";
const UPDATED = "25 November 2026";

export function Legal() {
  return (
    <section className="narrow prose">
      <h1>Disclaimer, terms &amp; privacy</h1>
      <p className="muted small">Last updated {UPDATED}.</p>

      <h2 id="disclaimer">Disclaimer</h2>
      <p>
        <strong>This is not a production PKI.</strong> It&rsquo;s a convenience tool for homelabs and internal,
        non-critical services. It hasn&rsquo;t been independently audited, it isn&rsquo;t operated to the standards of a
        public certificate authority, and it stores your CA private keys (encrypted) on a shared hosted service. For
        anything with a real security, compliance or availability requirement, use{" "}
        <a href="https://letsencrypt.org/">Let&rsquo;s Encrypt</a> or a properly operated CA.
      </p>
      <p>
        Every root CA created here is restricted by name constraints to the private names you choose, which limits what
        a leaked key could be used for. You decide which roots you install on your devices, and you&rsquo;re
        responsible for that choice.
      </p>

      <h2 id="terms">Terms of use</h2>
      <p>
        This service (&ldquo;the service&rdquo;) is operated by n25tech (&ldquo;we&rdquo;, &ldquo;us&rdquo;) at
        pki.n25tech.com. By creating an account you agree to these terms.
      </p>
      <ul>
        <li>
          <strong>No warranty.</strong> The service is provided &ldquo;as is&rdquo; and &ldquo;as available&rdquo;,
          without warranty of any kind. It may change, be interrupted or be discontinued at any time.
        </li>
        <li>
          <strong>Limitation of liability.</strong> To the fullest extent permitted by law, we aren&rsquo;t liable for
          any loss or damage arising from your use of the service, including loss of data, outages, or the misuse of
          keys or certificates.
        </li>
        <li>
          <strong>Your responsibilities.</strong> Keep your password, authenticator, recovery codes, key backups and
          exported data safe. If you lose your password and second factor together, we may not be able to restore
          access.
        </li>
        <li>
          <strong>Acceptable use.</strong> Don&rsquo;t use the service to impersonate others, intercept traffic you
          aren&rsquo;t authorized to intercept, distribute malware, or break any law. Don&rsquo;t try to get around the
          name constraints, rate limits or security controls, or create accounts automatically.
        </li>
        <li>
          <strong>Suspension.</strong> We may suspend or delete accounts that break these terms or put other users or
          the service at risk.
        </li>
        <li>
          <strong>Age.</strong> You must be at least 16 to use the service.
        </li>
        <li>
          <strong>Changes.</strong> We may update these terms. When we do, we&rsquo;ll change the date above, and we may
          notify account holders by email about significant changes.
        </li>
      </ul>

      <h2 id="privacy">Privacy</h2>
      <h3>What we store</h3>
      <ul>
        <li>Your email address, and whether it&rsquo;s verified.</li>
        <li>A password hash (never the password itself), or your Google account ID if you sign in with Google.</li>
        <li>Your two-factor secret (encrypted) and hashes of your recovery codes.</li>
        <li>Your CA certificates and their private keys, encrypted with a key that is only available to the service.</li>
        <li>The certificates you issue, with the tags and notes you add.</li>
        <li>
          An activity log of security-relevant events (sign-ins, certificate issuance, revocation…) with the IP address
          they came from.
        </li>
        <li>Active sessions, with the IP address and browser they were created from.</li>
      </ul>
      <p>
        Private keys you generate in your browser for end-entity certificates are never sent to us. CA certificates and
        certificate revocation lists are public by design: they&rsquo;re served at their distribution URLs so devices
        can check them.
      </p>

      <h3>Why</h3>
      <p>
        We use this data only to run the service: to sign you in, keep your account secure, issue and revoke
        certificates, and send emails you need (address verification and password resets). We don&rsquo;t sell data,
        and we don&rsquo;t use analytics, advertising or tracking.
      </p>

      <h3>Cookies</h3>
      <p>
        We use one essential cookie to keep you signed in, plus a short-lived cookie during Google sign-in. No tracking
        cookies.
      </p>

      <h3>Service providers</h3>
      <ul>
        <li>
          <strong>Cloudflare</strong> hosts the service and its database, and provides Turnstile, the check on the
          sign-up and password-reset forms that tells people from bots.
        </li>
        <li>
          <strong>Resend</strong> delivers our emails, so it processes your email address and the email content.
        </li>
        <li>
          <strong>Google</strong> handles sign-in if you choose &ldquo;Continue with Google&rdquo;.
        </li>
      </ul>
      <p>These providers may process data in countries other than your own.</p>

      <h3>How long we keep it</h3>
      <p>
        We keep your data until you delete your account. Deleting your account (from the account page) immediately
        deletes your CAs, their keys, your certificates and your activity log. Copies in database backups expire within
        30 days.
      </p>

      <h3>Your choices</h3>
      <p>
        You can export all your data, including CA keys, or delete your account at any time from the account page. For
        any other privacy request or question, email <a href={`mailto:${CONTACT}`}>{CONTACT}</a>.
      </p>

      <h2 id="source">Source code</h2>
      <p>
        The service is open source under the{" "}
        <a href="https://www.gnu.org/licenses/agpl-3.0.html">GNU Affero General Public License v3.0</a>. The code is at{" "}
        <a href="https://github.com/n25tech/pki">github.com/n25tech/pki</a>. Please report security issues privately
        through{" "}
        <a href="https://github.com/n25tech/pki/security/advisories/new">GitHub&rsquo;s vulnerability reporting</a>.
      </p>
    </section>
  );
}
