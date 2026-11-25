import { Hono } from "hono";

/** pki-acme host. The ACME server (RFC 8555) is planned for Phase 3. */
export const acme = new Hono<{ Bindings: Env }>();

acme.all("*", (c) =>
  c.json(
    {
      type: "urn:ietf:params:acme:error:serverInternal",
      detail: "ACME is not available yet",
    },
    503,
    { "Content-Type": "application/problem+json" },
  ),
);
