import type { Action } from "./schemas.js";

const ORDER: readonly Action[] = ["allow", "redact", "quarantine", "block"];

export function actionRank(action: Action): number {
  return ORDER.indexOf(action);
}

export function clampAction(recommended: Action, maxAction: Action): Action {
  return actionRank(recommended) <= actionRank(maxAction) ? recommended : maxAction;
}

export type PolicyInput = {
  mode: "enforce" | "silent" | "declared";
  max_action: Action;
};

/**
 * - enforce / declared: return detector recommendation clamped to max_action
 * - silent: still scan, but never raise action above allow (monitor-only)
 *
 * declared and enforce are equivalent at this scan API (no memory write occurs here).
 */
export function applyPolicy(recommended: Action, policy: PolicyInput): Action {
  if (policy.mode === "silent") return "allow";
  return clampAction(recommended, policy.max_action);
}
