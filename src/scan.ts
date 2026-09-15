import type { ScanRequest, ScanResult } from "./schemas.js";
import { FPR_NOTE, GAP_DISCLOSURE, ScanResultSchema } from "./schemas.js";
import { contentHash, hashesMatch, normalizeContentHash } from "./hash.js";
import { detect, redactText } from "./detector.js";
import { applyPolicy } from "./policy.js";
import { createMeter, newId } from "./meter.js";
import { InMemoryStore, requestFingerprint } from "./store.js";

export class HashMismatchError extends Error {
  readonly expected: string;
  constructor(expected: string) {
    super("content_hash_mismatch");
    this.name = "HashMismatchError";
    this.expected = expected;
  }
}

export class IdempotencyConflictError extends Error {
  constructor() {
    super("idempotency_key_conflict");
    this.name = "IdempotencyConflictError";
  }
}

export class NotFoundError extends Error {
  constructor() {
    super("scan_not_found");
    this.name = "NotFoundError";
  }
}

export class MemoryGateService {
  constructor(readonly store = new InMemoryStore()) {}

  scan(req: ScanRequest, idempotencyKey?: string): ScanResult {
    const expected = contentHash(req.text);
    if (!hashesMatch(req.content_hash, req.text)) {
      throw new HashMismatchError(expected);
    }

    const fingerprint = requestFingerprint({
      content_hash: normalizeContentHash(req.content_hash) ?? expected,
      nonce: req.nonce,
      agent_id: req.agent_id,
      policy: req.policy,
      text: req.text,
    });

    if (idempotencyKey) {
      const prior = this.store.getIdempotency(idempotencyKey);
      if (prior) {
        if (prior.fingerprint !== fingerprint) {
          throw new IdempotencyConflictError();
        }
        const existing = this.store.get(prior.scanId);
        if (existing) return existing;
      }
    }

    const detection = detect(req.text);
    const action = applyPolicy(detection.recommended, req.policy);
    const redacted_text =
      action === "redact" ? redactText(req.text, detection.redactSpans) : null;

    const result: ScanResult = ScanResultSchema.parse({
      scan_id: newId("scn"),
      content_hash: expected,
      action,
      score: detection.score,
      detectors: detection.detectors,
      redacted_text,
      gap_disclosure: GAP_DISCLOSURE,
      fpr_note: FPR_NOTE,
      meter: createMeter(action),
    });

    this.store.put(result, idempotencyKey, fingerprint);
    this.store.bill(result.meter.meter_ref);
    return result;
  }

  get(scanId: string): ScanResult {
    const result = this.store.get(scanId);
    if (!result) throw new NotFoundError();
    return result;
  }

  get billCount(): number {
    return this.store.billCount;
  }
}
