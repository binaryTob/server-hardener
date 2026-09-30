/**
 * Plan generator.
 *
 * Deterministic: the same inventory, context and catalog always produce the
 * same evaluations, statuses by control and the same ordering. Only ids and
 * timestamps vary (and can be injected for tests).
 *
 * This module never persists and never applies anything.
 */
import { randomUUID } from "node:crypto";
import {
  CATALOG_VERSION,
  CONTROL_CATALOG,
  type ControlDefinition,
  validateCatalog,
} from "../controls/catalog";
import type {
  ControlEvaluationStatus,
  HardeningPlan,
  OperationalContext,
  PlanBlocker,
  PlanCounts,
  PlannedControl,
  ServerInventory,
} from "../models";
import { contextCompleteness, touchContext, withDetectedRoles } from "./context";
import { evaluateControl } from "./evaluate";
import { PHASE_ORDER } from "./phases";
import { buildQuestions, missingContextByPath } from "./questions";

export const ALL_EVALUATION_STATUSES: ControlEvaluationStatus[] = [
  "compliant",
  "non-compliant",
  "not-applicable",
  "unknown",
  "requires-context",
  "requires-review",
  "blocked",
  "unsupported",
  "error",
];

export interface GeneratePlanOptions {
  inventory: ServerInventory;
  context: OperationalContext;
  now: () => string;
  /** Inject for deterministic tests. */
  planId?: string;
  profile?: string;
  catalog?: ControlDefinition[];
}

export function generatePlan(options: GeneratePlanOptions): HardeningPlan {
  const catalog = options.catalog ?? CONTROL_CATALOG;
  const context = touchContext(
    withDetectedRoles(options.context, options.inventory),
    options.context.updatedAt,
  );

  const controls = catalog.map((definition) => evaluateControl(definition, options.inventory, context));
  orderControls(controls);

  const counts = countByStatus(controls);
  const questions = buildQuestions(missingContextByPath(controls));
  const blockers = collectBlockers(controls);
  const warnings = collectWarnings(options.inventory, context, catalog, controls);

  return {
    schemaVersion: 1,
    planId: options.planId ?? `plan-${randomUUID()}`,
    serverId: options.inventory.serverId,
    inventoryId: options.inventory.inventoryId,
    contextUpdatedAt: context.updatedAt ?? null,
    generatedAt: options.now(),
    profile: options.profile ?? "baseline",
    catalogVersion: CATALOG_VERSION,
    controls,
    counts,
    unresolvedQuestions: questions,
    blockers,
    warnings,
    status: "draft",
  };
}

/** Operational order: phase, then declared order, then id (stable). */
export function orderControls(controls: PlannedControl[]): void {
  controls.sort(
    (a, b) => a.phaseIndex - b.phaseIndex || a.order - b.order || a.controlId.localeCompare(b.controlId),
  );
  controls.forEach((control, index) => {
    control.order = index + 1;
  });
}

export function countByStatus(controls: PlannedControl[]): PlanCounts {
  const counts = {} as PlanCounts;
  for (const status of ALL_EVALUATION_STATUSES) counts[status] = 0;
  for (const control of controls) counts[control.status] += 1;
  return counts;
}

export function collectBlockers(controls: PlannedControl[]): PlanBlocker[] {
  const blockers: PlanBlocker[] = [];
  for (const control of controls) {
    if (control.status !== "blocked") continue;
    blockers.push({
      controlId: control.controlId,
      reason: control.blockers[0] ?? "blocked by an unresolved precondition",
      preconditionIds: control.preconditions
        .filter((p) => p.critical && p.status !== "satisfied")
        .map((p) => p.id),
    });
  }
  return blockers;
}

function collectWarnings(
  inventory: ServerInventory,
  context: OperationalContext,
  catalog: ControlDefinition[],
  controls: PlannedControl[],
): string[] {
  const warnings: string[] = [];

  const completeness = contextCompleteness(context);
  if (!completeness.complete) {
    warnings.push(`operational context is incomplete: ${completeness.missing.join(", ")}`);
  }

  const degradedSections = (Object.entries(inventory) as [string, { status?: string }][])
    .filter(([, value]) => value && typeof value === "object" && "status" in value)
    .filter(([, value]) => value.status !== "success")
    .map(([name, value]) => `${name}=${value.status}`);
  if (degradedSections.length > 0) {
    warnings.push(`inventory has non-success sections: ${degradedSections.join(", ")}`);
  }

  const catalogIssues = validateCatalog(catalog);
  for (const issue of catalogIssues) {
    warnings.push(`catalog issue: ${issue.controlId} ${issue.problem}`);
  }

  const unknownOrContext = controls.filter(
    (c) => c.status === "unknown" || c.status === "requires-context",
  ).length;
  if (unknownOrContext > 0) {
    warnings.push(
      `${unknownOrContext} control(s) could not be fully evaluated with the available evidence/context`,
    );
  }

  if (PHASE_ORDER.length === 0) warnings.push("no plan phases configured");
  return warnings;
}
