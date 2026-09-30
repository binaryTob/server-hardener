/**
 * Control evaluation: composes applicability, state assessment, risk and
 * preconditions into a single deterministic `PlannedControl`.
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
  EvidenceRef,
  OperationalContext,
  PlannedControl,
  ServerInventory,
} from "../models";
import { decideApplicability } from "./applicability";
import { phaseIndex } from "./phases";
import {
  assessPreconditions,
  criticalPreconditionsUnknown,
  criticalPreconditionsUnsatisfied,
} from "./preconditions";
import { assessRisk } from "./risk";

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
): PlannedControl {
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
    phase: control.phase,
    phaseIndex: phaseIndex(control.phase),
    order: control.order,
    status,
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
