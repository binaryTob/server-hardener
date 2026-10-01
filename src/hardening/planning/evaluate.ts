/**
 * Control evaluation: composes applicability, state assessment, risk and
 * preconditions into a deterministic `EvaluatedControl`, then classifies it
 * into an operator-facing tier (safe / review / risky / skip).
 *
 * Decision precedence (engine-owned, never the LLM's):
 *   not-applicable / unsupported / unknown / requires-context (applicability)
 *   -> error (assessment failure)
 *   -> blocked (a critical precondition is unsatisfied)
 *   -> compliant
 *   -> requires-context (decision-critical information is missing)
 *   -> blocked (a critical precondition remains unknown)
 *   -> the control's own assessment (non-compliant / requires-review / unknown)
 */

import type { ControlDefinition, ControlStateAssessment } from "../controls/types";
import type {
  ControlEvaluationStatus,
  EvaluatedControl,
  EvidenceRef,
  OperationalContext,
  RiskLevel,
  ServerInventory,
  Tier,
} from "../models";
import { decideApplicability } from "./applicability";
import {
  assessPreconditions,
  criticalPreconditionsUnknown,
  criticalPreconditionsUnsatisfied,
} from "./preconditions";
import { assessRisk } from "./risk";

const ACTIONABLE: ReadonlySet<ControlEvaluationStatus> = new Set([
  "non-compliant",
  "requires-review",
  "requires-context",
  "blocked",
]);

const HIGH: ReadonlySet<RiskLevel> = new Set(["high", "critical"]);

/**
 * Operator-facing grouping. No numeric scoring:
 * - safe:   low operational impact, no lockout, low availability risk;
 * - risky:  can cut access (higher lockout) or disrupt availability;
 * - review: everything else that needs a human decision;
 * - skip:   nothing to do (compliant / not applicable / unsupported).
 */
export function classifyTier(control: {
  status: ControlEvaluationStatus;
  risk: { availabilityRisk: RiskLevel; lockoutRisk: RiskLevel };
}): Tier {
  if (!ACTIONABLE.has(control.status)) return "skip";
  if (HIGH.has(control.risk.lockoutRisk) || HIGH.has(control.risk.availabilityRisk)) return "risky";
  const low =
    !HIGH.has(control.risk.availabilityRisk) &&
    !HIGH.has(control.risk.lockoutRisk) &&
    (control.risk.availabilityRisk === "none" || control.risk.availabilityRisk === "low") &&
    (control.risk.lockoutRisk === "none" || control.risk.lockoutRisk === "low");
  if (control.status === "non-compliant" && low) return "safe";
  return "review";
}

function safeAssess(
  control: ControlDefinition,
  inventory: ServerInventory,
  context: OperationalContext,
): ControlStateAssessment {
  try {
    return control.assess(inventory, context);
  } catch (err) {
    return {
      status: "error",
      currentState: null,
      evidence: [],
      missingContext: [],
      rationale: `assessment failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

function dedupeStrings(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function dedupeEvidence(values: EvidenceRef[]): EvidenceRef[] {
  const seen = new Set<string>();
  const result: EvidenceRef[] = [];
  for (const value of values) {
    const key = `${value.inventoryPath}|${value.observed ?? ""}|${value.note ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(value);
  }
  return result;
}

export function evaluateControl(
  control: ControlDefinition,
  inventory: ServerInventory,
  context: OperationalContext,
): EvaluatedControl {
  const applicability = decideApplicability(control, inventory, context);
  const actionable = applicability.status === "applicable" || applicability.status === "requires-context";

  const state: ControlStateAssessment = actionable
    ? safeAssess(control, inventory, context)
    : {
        status: "unknown",
        currentState: null,
        evidence: [],
        missingContext: [],
        rationale: applicability.rationale,
      };

  const preconditions = actionable ? assessPreconditions(control, inventory, context) : [];
  const risk = assessRisk(control, state, inventory, context);

  const unsatisfied = criticalPreconditionsUnsatisfied(preconditions);
  const unknownCritical = criticalPreconditionsUnknown(preconditions);
  const missingContext = dedupeStrings([
    ...applicability.missingContext,
    ...state.missingContext,
    ...preconditions.flatMap((p) => p.missingContext),
  ]);

  const blockers: string[] = [];
  let status: ControlEvaluationStatus;

  if (applicability.status === "not-applicable") status = "not-applicable";
  else if (applicability.status === "unsupported") status = "unsupported";
  else if (applicability.status === "unknown") status = "unknown";
  else if (applicability.status === "requires-context") status = "requires-context";
  else if (state.status === "error") status = "error";
  else if (unsatisfied.length > 0) {
    status = "blocked";
    for (const precondition of unsatisfied) {
      blockers.push(
        `unsatisfied precondition ${precondition.id}: ${precondition.description}${precondition.reason ? ` (${precondition.reason})` : ""}`,
      );
    }
  } else if (state.status === "compliant") status = "compliant";
  else if (missingContext.length > 0) status = "requires-context";
  else if (unknownCritical.length > 0) {
    status = "blocked";
    for (const precondition of unknownCritical) {
      blockers.push(
        `unresolved precondition ${precondition.id}: ${precondition.description}${precondition.reason ? ` (${precondition.reason})` : ""}`,
      );
    }
  } else status = state.status;

  return {
    controlId: control.id,
    title: control.title,
    category: control.category,
    status,
    tier: classifyTier({ status, risk }),
    currentState: state.currentState,
    desiredState: control.desiredState,
    applicability,
    risk,
    preconditions,
    blockers,
    missingContext,
    evidence: dedupeEvidence([
      ...applicability.evidence,
      ...state.evidence,
      ...preconditions.flatMap((p) => p.evidence),
    ]),
    requiresApproval: control.requiresApproval,
    reversible: control.reversible,
    tags: control.tags,
  };
}

/** Evaluate the whole catalog and group by tier. */
export function evaluateCatalog(
  catalog: ControlDefinition[],
  inventory: ServerInventory,
  context: OperationalContext,
): { controls: EvaluatedControl[]; byTier: Record<Tier, EvaluatedControl[]> } {
  const controls = catalog.map((definition) => evaluateControl(definition, inventory, context));
  const byTier: Record<Tier, EvaluatedControl[]> = { safe: [], review: [], risky: [], skip: [] };
  for (const control of controls) byTier[control.tier].push(control);
  return { controls, byTier };
}
