import { Hono } from "hono";

export const api = new Hono<{ Bindings: Env }>().basePath("/api");

api.get("/health", (c) => c.json({ ok: true }));

api.notFound((c) => c.json({ error: "not_found" }, 404));

api.onError((err, c) => {
  console.error(err);
  return c.json({ error: "internal_error" }, 500);
});
