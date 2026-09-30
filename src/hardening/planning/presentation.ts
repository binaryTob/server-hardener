/**
 * Plan presentation. Pure formatting over an already-computed plan: this
 * module formats the engine's decision, it never makes one.
 */
import type {
  ControlEvaluationStatus,
  HardeningPlan,
  OperationalContext,
  PlanBlocker,
  PlanCounts,
  PlannedControl,
  PlanningQuestion,
} from "../models";

const ACTIONABLE_STATUSES = new Set<ControlEvaluationStatus>([
  "non-compliant",
  "requires-review",
  "requires-context",
  "blocked",
  "unknown",
]);

const HIGH_IMPACT = new Set(["high", "critical"]);

export interface PlanSummary {
  planId: string;
  serverId: string;
  generatedAt: string;
  profile: string;
  total: number;
  counts: PlanCounts;
  highSecurityImpact: PlannedControl[];
  potentialLockout: PlannedControl[];
  blocked: PlanBlocker[];
  questions: PlanningQuestion[];
  warnings: string[];
}

export function summarizePlan(plan: HardeningPlan): PlanSummary {
  const actionable = plan.controls.filter((c) => ACTIONABLE_STATUSES.has(c.status));
  return {
    planId: plan.planId,
    serverId: plan.serverId,
    generatedAt: plan.generatedAt,
    profile: plan.profile,
    total: plan.controls.length,
    counts: plan.counts,
    highSecurityImpact: actionable.filter((c) => HIGH_IMPACT.has(c.risk.securityImpact)),
    potentialLockout: actionable.filter((c) => HIGH_IMPACT.has(c.risk.lockoutRisk)),
    blocked: plan.blockers,
    questions: plan.unresolvedQuestions,
    warnings: plan.warnings,
  };
}

export function findControl(plan: HardeningPlan, controlId: string): PlannedControl | null {
  return plan.controls.find((c) => c.controlId === controlId) ?? null;
}

export function formatPlanSummary(plan: HardeningPlan, serverLabel?: string): string {
  const summary = summarizePlan(plan);
  const lines: string[] = [];
  lines.push(`Server: ${serverLabel ?? plan.serverId}`);
  lines.push(`Plan:   ${plan.planId} (${plan.profile}, ${plan.status}, catalog ${plan.catalogVersion})`);
  lines.push(`Generated: ${plan.generatedAt}`);
  lines.push("");
  lines.push(`Controls evaluated: ${summary.total}`);
  lines.push("");
  const order: ControlEvaluationStatus[] = [
    "compliant",
    "non-compliant",
    "requires-context",
    "requires-review",
    "blocked",
    "unknown",
    "not-applicable",
    "unsupported",
    "error",
  ];
  for (const status of order) {
    const count = summary.counts[status] ?? 0;
    if (count === 0) continue;
    lines.push(`  ${status.padEnd(20)} ${count}`);
  }

  if (summary.highSecurityImpact.length > 0) {
    lines.push("");
    lines.push("High security impact:");
    for (const control of summary.highSecurityImpact.slice(0, 12)) {
      lines.push(`- ${control.controlId} ${control.title} [${control.status}]`);
    }
  }

  if (summary.potentialLockout.length > 0) {
    lines.push("");
    lines.push("Potential lockout:");
    for (const control of summary.potentialLockout.slice(0, 12)) {
      lines.push(`- ${control.controlId} ${control.title} [lockout=${control.risk.lockoutRisk}]`);
    }
  }

  if (summary.blocked.length > 0) {
    lines.push("");
    lines.push("Blocked:");
    for (const blocker of summary.blocked) {
      lines.push(`${blocker.controlId}`);
      lines.push(`Reason: ${blocker.reason}`);
      if (blocker.preconditionIds.length > 0) {
        lines.push(`Preconditions: ${blocker.preconditionIds.join(", ")}`);
      }
    }
  }

  if (summary.questions.length > 0) {
    lines.push("");
    lines.push("Questions required before continuing:");
    summary.questions.forEach((question, index) => {
      lines.push(`${index + 1}. ${question.prompt}`);
      lines.push(`   (${question.reason}; affects ${question.affectedControls.join(", ")})`);
    });
  }

  if (summary.warnings.length > 0) {
    lines.push("");
    lines.push("Warnings:");
    for (const warning of summary.warnings) lines.push(`- ${warning}`);
  }

  lines.push("");
  lines.push("Status: draft — review only. No changes are applied by Phase 2.");
  return lines.join("\n");
}

export function formatContextSummary(context: OperationalContext): string {
  const confirmed = context.roles.filter((r) => r.confidence === "confirmed").map((r) => r.role);
  const derived = context.roles.filter((r) => r.confidence === "derived").map((r) => r.role);
  const lines: string[] = [];
  lines.push(`serverId: ${context.serverId}`);
  lines.push(`updatedAt: ${context.updatedAt}`);
  lines.push(`environment: ${context.environment}`);
  lines.push(`criticality: ${context.criticality}`);
  lines.push(`internetExposure: ${context.internetExposure}`);
  lines.push(`roles confirmed: ${confirmed.join(", ") || "(none)"}`);
  lines.push(`roles derived:   ${derived.join(", ") || "(none)"}`);
  lines.push(`management.methods: ${context.management.methods.join(", ") || "(none declared)"}`);
  lines.push(`management.secondaryPathConfirmed: ${String(context.management.secondaryPathConfirmed)}`);
  lines.push(`management.consoleAccess: ${String(context.management.consoleAccess)}`);
  lines.push(`networks.administrative: ${context.networks.administrative.join(", ") || "(none declared)"}`);
  lines.push(`networks.service: ${context.networks.service.join(", ") || "(none declared)"}`);
  lines.push(`reboot.allowed: ${String(context.reboot.allowed)}`);
  lines.push(`reboot.maintenanceWindowAvailable: ${String(context.reboot.maintenanceWindowAvailable)}`);
  lines.push(`highAvailability: ${String(context.highAvailability)}`);
  lines.push(`operatorNotes: ${context.operatorNotes ?? "(none)"}`);
  return lines.join("\n");
}

export function formatControlExplanation(control: PlannedControl): string {
  const lines: string[] = [];
  lines.push(`${control.controlId} — ${control.title}`);
  lines.push(`Category: ${control.category} · Phase: ${control.phase} (order ${control.order})`);
  lines.push(`Status: ${control.status}`);
  lines.push(`Current: ${control.currentState ?? "(unknown / not observable)"}`);
  lines.push(`Desired: ${control.desiredState}`);
  lines.push("");
  lines.push(`Applicability: ${control.applicability.status} — ${control.applicability.rationale}`);
  if (control.applicability.evidence.length > 0) {
    lines.push("  evidence:");
    for (const item of control.applicability.evidence) {
      lines.push(
        `    - ${item.inventoryPath} = ${item.observed ?? "(null)"}${item.note ? ` (${item.note})` : ""}`,
      );
    }
  }
  lines.push(
    `Risk: impact=${control.risk.securityImpact} availability=${control.risk.availabilityRisk} lockout=${control.risk.lockoutRisk} complexity=${control.risk.operationalComplexity}`,
  );
  lines.push(`  ${control.risk.rationale}`);

  if (control.preconditions.length > 0) {
    lines.push("");
    lines.push("Preconditions:");
    for (const precondition of control.preconditions) {
      const marker = precondition.critical ? "[critical]" : "[optional]";
      lines.push(
        `  - ${marker} ${precondition.id}: ${precondition.status}${precondition.reason ? ` — ${precondition.reason}` : ""}`,
      );
    }
  }

  if (control.blockers.length > 0) {
    lines.push("");
    lines.push("Blockers:");
    for (const blocker of control.blockers) lines.push(`  - ${blocker}`);
  }

  if (control.missingContext.length > 0) {
    lines.push("");
    lines.push("Missing context:");
    for (const path of control.missingContext) lines.push(`  - ${path}`);
  }

  if (control.evidence.length > 0) {
    lines.push("");
    lines.push("Evidence:");
    for (const item of control.evidence) {
      lines.push(
        `  - ${item.inventoryPath} = ${item.observed ?? "(null)"}${item.note ? ` (${item.note})` : ""}`,
      );
    }
  }

  return lines.join("\n");
}
