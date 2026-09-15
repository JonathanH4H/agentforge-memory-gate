import { createHash } from "node:crypto";
import { ACTIONS, type Action, type ScanRequest } from "../src/schemas.js";

export function sha256Content(text: string): string {
  return `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
}

export function scanRequest(
  text: string,
  overrides: Partial<ScanRequest> = {},
): ScanRequest {
  const mergedText = overrides.text ?? text;
  const {
    content_hash: contentHashOverride,
    text: _ignoredText,
    ...rest
  } = overrides;
  return {
    text: mergedText,
    source_class: "user",
    content_hash: contentHashOverride ?? sha256Content(mergedText),
    policy: { mode: "enforce", max_action: "block" },
    nonce: "nonce-1",
    agent_id: "agt_test",
    ...rest,
  };
}

export const AUTH = { Authorization: "Bearer prepaid-test-key" };

export function severityAtLeast(action: Action, min: Action): boolean {
  return ACTIONS.indexOf(action) >= ACTIONS.indexOf(min);
}
