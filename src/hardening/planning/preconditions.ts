/**
 * Precondition engine.
 *
 * Evaluates the preconditions each control declares. A critical precondition
 * that is unsatisfied (or unknown while the control needs action) turns the
 * control into `blocked` rather than merely "risky" — the engine decides this,
 * not the LLM.
 */

import type { ControlDefinition } from "../controls/types";
import type { OperationalContext, Precondition, ServerInventory } from "../models";

export function assessPreconditions(
  control: ControlDefinition,
  inventory: ServerInventory,
  context: OperationalContext,
): Precondition[] {
  if (!control.preconditions) return [];
  let specs: ReturnType<NonNullable<ControlDefinition["preconditions"]>>;
  try {
    specs = control.preconditions(inventory, context);
  } catch {
    return [];
  }
  const results: Precondition[] = [];
  for (const spec of specs) {
    let check: ReturnType<typeof spec.check>;
    try {
      check = spec.check(inventory, context);
    } catch (err) {
      check = {
        status: "unknown",
        evidence: [],
        missingContext: [],
        reason: `precondition evaluation failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    results.push({
      id: spec.id,
      description: spec.description,
      critical: spec.critical,
      status: check.status,
      evidence: check.evidence,
      missingContext: check.missingContext,
      reason: check.reason,
    });
  }
  return results;
}

export function criticalPreconditionsUnsatisfied(preconditions: Precondition[]): Precondition[] {
  return preconditions.filter((p) => p.critical && p.status === "unsatisfied");
}

export function criticalPreconditionsUnknown(preconditions: Precondition[]): Precondition[] {
  return preconditions.filter((p) => p.critical && p.status === "unknown");
}
