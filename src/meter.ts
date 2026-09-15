import { randomBytes } from "node:crypto";
import type { Action, Meter } from "./schemas.js";

export function newId(prefix: "scn" | "mtr"): string {
  return `${prefix}_${randomBytes(12).toString("hex")}`;
}

export function createMeter(outcome: Action): Meter {
  return {
    meter_ref: newId("mtr"),
    sku: "memory_scan",
    billable: true,
    usdc: null,
    price_pending: true,
    outcome,
    unit: "memory_scan",
  };
}
