import type { AppContext } from "../lib/context";
import { fail } from "../lib/util";

const MAX_BODY_BYTES = 256 * 1024;

/** Reads a JSON object body (max 256 KiB). Missing or invalid bodies become {}. */
export async function readJson<T>(c: AppContext): Promise<Partial<T>> {
  const length = Number(c.req.header("Content-Length") ?? 0);
  if (length > MAX_BODY_BYTES) fail(413, "too_large", "Request body is too large");
  const text = await c.req.text();
  if (text.length > MAX_BODY_BYTES) fail(413, "too_large", "Request body is too large");
  if (!text) return {};
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    fail(400, "invalid_json", "Request body must be JSON");
  }
}
