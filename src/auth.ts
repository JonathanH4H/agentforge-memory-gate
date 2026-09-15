export type AuthResult =
  | { ok: true; method: "bearer" | "x402" }
  | { ok: false; error: "unauthorized" };

/**
 * MVP auth:
 * - Authorization: Bearer <non-empty prepaid stub>
 * - or x402 stub header X-PAYMENT / PAYMENT-SIGNATURE (any non-empty value)
 *
 * No on-chain settlement. Missing/empty credentials are free (no scan emit).
 */
export function authorize(headers: Headers): AuthResult {
  const bearer = headers.get("authorization");
  if (bearer) {
    const match = /^Bearer\s+(\S+)/i.exec(bearer.trim());
    if (match?.[1]) return { ok: true, method: "bearer" };
  }

  const x402 = headers.get("x-payment") ?? headers.get("payment-signature");
  if (x402 && x402.trim().length > 0) {
    return { ok: true, method: "x402" };
  }

  return { ok: false, error: "unauthorized" };
}
