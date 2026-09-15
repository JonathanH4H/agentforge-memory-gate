import { createHash } from "node:crypto";

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export function contentHash(text: string): string {
  return `sha256:${sha256Hex(text)}`;
}

export function normalizeContentHash(value: string): string | null {
  const match = /^sha256:([a-fA-F0-9]{64})$/.exec(value);
  if (!match) return null;
  return `sha256:${match[1].toLowerCase()}`;
}

export function hashesMatch(clientHash: string, text: string): boolean {
  const normalized = normalizeContentHash(clientHash);
  if (!normalized) return false;
  return normalized === contentHash(text);
}
