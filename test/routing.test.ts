import { describe, expect, it } from "vitest";
import { exports } from "cloudflare:workers";

const fetchWorker = (url: string, init?: RequestInit) => exports.default.fetch(new Request(url, init));

describe("hostname routing", () => {
  it("serves the API on the app host with security headers", async () => {
    const res = await fetchWorker("https://pki.n25tech.com/api/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(res.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
    expect(res.headers.get("Strict-Transport-Security")).toBe("max-age=31536000");
  });

  it("returns JSON 404 for unknown API routes", async () => {
    const res = await fetchWorker("https://pki.n25tech.com/api/nope");
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ error: "not_found" });
  });

  it("redirects plain HTTP to HTTPS on the app host", async () => {
    const res = await fetchWorker("http://pki.n25tech.com/certs?x=1", { redirect: "manual" });
    expect(res.status).toBe(301);
    expect(res.headers.get("Location")).toBe("https://pki.n25tech.com/certs?x=1");
  });

  it("serves the CRL host over plain HTTP without redirecting or HSTS", async () => {
    const res = await fetchWorker("http://pki-crl.n25tech.com/", { redirect: "manual" });
    expect(res.status).toBe(200);
    expect(res.headers.get("Strict-Transport-Security")).toBeNull();
  });

  it("does not expose the API or app on the CRL host", async () => {
    expect((await fetchWorker("https://pki-crl.n25tech.com/api/health")).status).toBe(404);
    expect((await fetchWorker("http://pki-crl.n25tech.com/unknown-ca.crl")).status).toBe(404);
    expect((await fetchWorker("http://pki-crl.n25tech.com/../etc.crl")).status).toBe(404);
  });

  it("rejects non-GET methods on the CRL host", async () => {
    expect((await fetchWorker("http://pki-crl.n25tech.com/x.crl", { method: "POST" })).status).toBe(405);
  });

  it("answers ACME requests with a problem document", async () => {
    const res = await fetchWorker("https://pki-acme.n25tech.com/directory");
    expect(res.status).toBe(503);
    expect(res.headers.get("Content-Type")).toContain("application/problem+json");
  });

  it("refuses unknown hostnames", async () => {
    expect((await fetchWorker("https://evil.example.com/api/health")).status).toBe(404);
  });

  it("serves everything on dev hosts, with CRL and ACME under prefixes", async () => {
    expect((await fetchWorker("http://localhost/api/health")).status).toBe(200);
    expect((await fetchWorker("http://localhost/_crl/")).status).toBe(200);
    expect((await fetchWorker("http://localhost/_acme/directory")).status).toBe(503);
  });
});
