import { Hono } from "hono";
import { ScanRequestSchema } from "./schemas.js";
import { authorize } from "./auth.js";
import {
  HashMismatchError,
  IdempotencyConflictError,
  MemoryGateService,
  NotFoundError,
} from "./scan.js";

export function createApp(service = new MemoryGateService()) {
  const app = new Hono();

  app.post("/v1/memory/scan", async (c) => {
    const auth = authorize(c.req.raw.headers);
    if (!auth.ok) {
      return c.json({ error: "unauthorized" }, 401);
    }

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid_json" }, 400);
    }

    const parsed = ScanRequestSchema.safeParse(body);
    if (!parsed.success) {
      return c.json(
        { error: "invalid_request", details: parsed.error.flatten() },
        400,
      );
    }

    try {
      const result = service.scan(
        parsed.data,
        c.req.header("Idempotency-Key") ?? undefined,
      );
      return c.json(result);
    } catch (err) {
      if (err instanceof HashMismatchError) {
        return c.json(
          { error: "content_hash_mismatch", expected: err.expected },
          400,
        );
      }
      if (err instanceof IdempotencyConflictError) {
        return c.json({ error: "idempotency_key_conflict" }, 409);
      }
      throw err;
    }
  });

  app.get("/v1/memory/scans/:scan_id", (c) => {
    const auth = authorize(c.req.raw.headers);
    if (!auth.ok) {
      return c.json({ error: "unauthorized" }, 401);
    }

    try {
      const result = service.get(c.req.param("scan_id"));
      return c.json(result);
    } catch (err) {
      if (err instanceof NotFoundError) {
        return c.json({ error: "scan_not_found" }, 404);
      }
      throw err;
    }
  });

  return Object.assign(app, { service });
}

export type MemoryGateApp = ReturnType<typeof createApp>;
