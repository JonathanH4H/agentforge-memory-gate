import type { ScanResult } from "./schemas.js";

export type IdempotencyRecord = {
  scanId: string;
  fingerprint: string;
};

export class InMemoryStore {
  readonly scans = new Map<string, ScanResult>();
  readonly idempotency = new Map<string, IdempotencyRecord>();
  readonly billed = new Set<string>();
  billCount = 0;

  put(result: ScanResult, idempotencyKey: string | undefined, fingerprint: string): void {
    this.scans.set(result.scan_id, result);
    if (idempotencyKey) {
      this.idempotency.set(idempotencyKey, {
        scanId: result.scan_id,
        fingerprint,
      });
    }
  }

  get(scanId: string): ScanResult | undefined {
    return this.scans.get(scanId);
  }

  getIdempotency(key: string): IdempotencyRecord | undefined {
    return this.idempotency.get(key);
  }

  /** Bill once per meter_ref. Idempotent replay and GET must not call this again. */
  bill(meterRef: string): void {
    if (this.billed.has(meterRef)) return;
    this.billed.add(meterRef);
    this.billCount += 1;
  }
}

export function requestFingerprint(input: {
  content_hash: string;
  nonce: string;
  agent_id: string;
  policy: { mode: string; max_action: string };
  text: string;
}): string {
  return JSON.stringify({
    content_hash: input.content_hash.toLowerCase(),
    nonce: input.nonce,
    agent_id: input.agent_id,
    policy: input.policy,
    text: input.text,
  });
}
