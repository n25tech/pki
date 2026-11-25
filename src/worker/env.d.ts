// Secrets aren't in wrangler.jsonc, so `wrangler types` can't see them.
interface PkiSecrets {
  MASTER_KEY: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  RESEND_API_KEY?: string;
}
declare namespace Cloudflare {
  interface Env extends PkiSecrets {}
}
interface Env extends PkiSecrets {}
