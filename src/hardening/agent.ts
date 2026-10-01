/**
 * High-level local agent API.
 *
 * Ties discovery + controls + remediation together for the local host and
 * produces the human-readable text the OpenCode tools return. Tools stay thin;
 * all orchestration and formatting lives here so it is testable without
 * OpenCode.
 */
import { CATALOG_VERSION, CONTROL_CATALOG } from "./controls/catalog";
import type { CommandRunner } from "./exec";
import type { FileReader } from "./fsio";
import { formatSummary, runDiscovery, summarizeInventory } from "./inventory";
import type { EvaluatedControl, OperationalContext, PlanningQuestion, ServerInventory, Tier } from "./models";
import { contextCompleteness, emptyContext, withDetectedRoles } from "./planning/context";
import { evaluateCatalog } from "./planning/evaluate";
import { buildQuestions, missingContextByPath } from "./planning/questions";
import { getRemediation } from "./remediation/registry";
import {
  applyControl,
  type ExecutionOutcome,
  previewControl,
  rollbackControl,
  verifyControl,
} from "./remediation/run";
import type { SystemPaths } from "./remediation/types";
import { defaultStoreRoot, readContext, readLastRun } from "./store";

export interface AgentDeps {
  storeRoot?: string;
  runner?: CommandRunner;
  files?: FileReader;
  paths?: SystemPaths;
  hasRoot?: boolean;
  now?: () => string;
}

export const HARDEN_DOMAINS = {
  sysctl: ["KRN"],
  ssh: ["SSH"],
  firewall: ["FW"],
  service: ["SVC"],
  logging: ["LOG", "AUD"],
  filesystem: ["FS"],
} as const;

export type HardenDomain = keyof typeof HARDEN_DOMAINS;

export interface Assessment {
  inventory: ServerInventory;
  context: OperationalContext;
  controls: EvaluatedControl[];
  byTier: Record<Tier, EvaluatedControl[]>;
  questions: PlanningQuestion[];
  contextMissing: string[];
  catalogVersion: string;
}

function now(deps: AgentDeps): string {
  return (deps.now ?? (() => new Date().toISOString()))();
}

/** Discover the local host and evaluate the whole catalog against it. */
export async function assess(deps: AgentDeps = {}): Promise<Assessment> {
  const storeRoot = deps.storeRoot ?? defaultStoreRoot();
  const inventory = await runDiscovery({
    ...(deps.runner ? { runner: deps.runner } : {}),
    ...(deps.files ? { files: deps.files } : {}),
    ...(deps.now ? { now: deps.now } : {}),
  });
  const stored = await readContext(storeRoot);
  const context = withDetectedRoles(stored ?? emptyContext(now(deps)), inventory);
  const { controls, byTier } = evaluateCatalog(CONTROL_CATALOG, inventory, context);
  const questions = buildQuestions(missingContextByPath(controls));
  return {
    inventory,
    context,
    controls,
    byTier,
    questions,
    contextMissing: contextCompleteness(context).missing,
    catalogVersion: CATALOG_VERSION,
  };
}

// --- Text rendering --------------------------------------------------------

function detectedCapabilities(inventory: ServerInventory): string[] {
  const found = new Set<string>();
  const controls = inventory.securityControls.data;
  if (controls?.sshServer.available) found.add("OpenSSH");
  for (const runtime of inventory.containers.data?.runtimes ?? []) found.add(runtime.name);
  for (const capability of controls?.endpointProtection ?? []) found.add(capability.name);
  for (const implementation of controls?.firewall.detectedImplementations ?? []) found.add(implementation);
  for (const name of inventory.services.data?.services ?? []) {
    if (
      name.active === true &&
      ["nginx", "apache2", "httpd", "docker", "postgresql", "mysql", "mariadb"].some((s) =>
        name.name.includes(s),
      )
    ) {
      found.add(name.name);
    }
  }
  return [...found];
}

export function formatAssessment(assessment: Assessment): string {
  const lines: string[] = [];
  const identity = assessment.inventory.identity.data;
  lines.push(`Host: ${identity?.hostname ?? "(unknown)"}`);
  lines.push(`OS:   ${assessment.inventory.operatingSystem.data?.distribution ?? "(unknown)"}`);
  const detected = detectedCapabilities(assessment.inventory);
  if (detected.length > 0) lines.push(`Detected: ${detected.join(", ")}`);
  lines.push("");

  const actionable = (tier: Tier) => assessment.byTier[tier];
  const total = actionable("safe").length + actionable("review").length + actionable("risky").length;
  if (total === 0) {
    lines.push("No hardening opportunities found with the current evidence/context.");
  }

  const renderTier = (label: string, tier: Tier) => {
    const controls = actionable(tier);
    if (controls.length === 0) return;
    lines.push(`${label} (${controls.length})`);
    for (const control of controls) {
      const current = control.currentState ? ` — now: ${control.currentState}` : "";
      lines.push(`- ${control.controlId} ${control.title}${current}`);
    }
    lines.push("");
  };
  renderTier("SAFE", "safe");
  renderTier("REVIEW", "review");
  renderTier("RISKY", "risky");

  const skipped = assessment.byTier.skip.length;
  if (skipped > 0) lines.push(`(${skipped} controls already compliant / not applicable)`);

  if (assessment.contextMissing.length > 0) {
    lines.push("");
    lines.push(`Operational context incomplete: ${assessment.contextMissing.join(", ")}`);
  }
  if (assessment.questions.length > 0) {
    lines.push("");
    lines.push("Questions before risky changes:");
    for (const question of assessment.questions) {
      lines.push(`- ${question.prompt} (affects ${question.affectedControls.join(", ")})`);
    }
  }
  lines.push("");
  lines.push(`catalog ${assessment.catalogVersion} · no changes applied by assessment`);
  return lines.join("\n");
}

export function formatControlDetail(control: EvaluatedControl): string {
  const lines: string[] = [];
  lines.push(`${control.controlId} — ${control.title}`);
  lines.push(`category: ${control.category} · tier: ${control.tier} · status: ${control.status}`);
  lines.push(`current: ${control.currentState ?? "(unknown / not observable)"}`);
  lines.push(`desired: ${control.desiredState}`);
  lines.push(
    `risk: security=${control.risk.securityImpact} availability=${control.risk.availabilityRisk} lockout=${control.risk.lockoutRisk}`,
  );
  if (control.evidence.length > 0) {
    lines.push("evidence:");
    for (const item of control.evidence) {
      lines.push(
        `  - ${item.inventoryPath} = ${item.observed ?? "(null)"}${item.note ? ` (${item.note})` : ""}`,
      );
    }
  }
  if (control.preconditions.length > 0) {
    lines.push("preconditions:");
    for (const precondition of control.preconditions) {
      lines.push(
        `  - ${precondition.critical ? "[critical]" : "[optional]"} ${precondition.id}: ${precondition.status}`,
      );
    }
  }
  if (control.blockers.length > 0) {
    lines.push("blocked:");
    for (const blocker of control.blockers) lines.push(`  - ${blocker}`);
  }
  if (control.missingContext.length > 0) {
    lines.push(`missing context: ${control.missingContext.join(", ")}`);
  }
  return lines.join("\n");
}

export function formatPreview(preview: NonNullable<ExecutionOutcome["preview"]>): string {
  const lines: string[] = [];
  lines.push(`${preview.controlId} — ${preview.title}`);
  lines.push(`Current: ${preview.currentState ?? "(unknown)"}`);
  lines.push(`Desired: ${preview.desiredState}`);
  lines.push(`Impact:  availability=${preview.risk.availabilityRisk} lockout=${preview.risk.lockoutRisk}`);
  if (preview.manual) {
    lines.push("");
    lines.push(`MANUAL REMEDIATION REQUIRED: ${preview.manualReason}`);
    return lines.join("\n");
  }
  lines.push("");
  lines.push("Steps:");
  for (const step of preview.steps) lines.push(`  - ${step}`);
  if (preview.files.length > 0) {
    lines.push("Files (backed up first):");
    for (const file of preview.files) lines.push(`  - ${file.path}`);
  }
  if (preview.commands.length > 0) {
    lines.push("Commands:");
    for (const command of preview.commands) lines.push(`  - ${command}`);
  }
  if (preview.warnings.length > 0) {
    lines.push("");
    lines.push("WARNINGS:");
    for (const warning of preview.warnings) lines.push(`  ! ${warning}`);
  }
  lines.push("");
  lines.push(
    "To apply: call the matching harden_* tool with action 'apply' and confirm: true after operator approval.",
  );
  return lines.join("\n");
}

export function formatOutcome(outcome: ExecutionOutcome): string {
  const lines: string[] = [];
  lines.push(`${outcome.action}: ${outcome.controlId}`);
  lines.push(`result: ${outcome.message}`);
  if (outcome.verification) {
    lines.push(
      `verification: ${outcome.verification.passed === true ? "PASSED" : outcome.verification.passed === false ? "FAILED" : "INCONCLUSIVE"}`,
    );
    lines.push(`  check:    ${outcome.verification.check}`);
    lines.push(`  expected: ${outcome.verification.expected}`);
    lines.push(`  observed: ${outcome.verification.observed ?? "(none)"}`);
  }
  if (outcome.backupIds.length > 0) lines.push(`backups: ${outcome.backupIds.join(", ")}`);
  return lines.join("\n");
}

// --- Domain operations -----------------------------------------------------

function domainControls(assessment: Assessment, domain: HardenDomain): EvaluatedControl[] {
  const prefixes = HARDEN_DOMAINS[domain];
  return assessment.controls.filter((control) => prefixes.some((p) => control.controlId.startsWith(`${p}-`)));
}

/** True when a control id belongs to a hardening domain (pure, for tools/tests). */
export function controlBelongsToDomain(domain: HardenDomain, controlId: string): boolean {
  return HARDEN_DOMAINS[domain].some((prefix) => controlId.startsWith(`${prefix}-`));
}

export function formatDomainInspect(assessment: Assessment, domain: HardenDomain): string {
  const controls = domainControls(assessment, domain);
  const lines: string[] = [`${domain} controls (local host)`];
  for (const control of controls) {
    lines.push(`- ${control.controlId} [${control.tier}/${control.status}] ${control.title}`);
    lines.push(`    current: ${control.currentState ?? "(unknown)"}`);
    lines.push(`    desired: ${control.desiredState}`);
  }
  return lines.join("\n");
}

function findDomainControl(
  assessment: Assessment,
  domain: HardenDomain,
  controlId: string,
): EvaluatedControl {
  if (!controlBelongsToDomain(domain, controlId)) {
    throw new Error(`control ${controlId} does not belong to ${domain}`);
  }
  const control = assessment.controls.find((c) => c.controlId === controlId);
  if (!control) throw new Error(`unknown control ${controlId}`);
  return control;
}

export async function domainAction(
  domain: HardenDomain,
  action: "inspect" | "preview" | "apply" | "verify" | "rollback",
  controlId: string | undefined,
  deps: AgentDeps & { target?: string } = {},
): Promise<string> {
  const assessment = await assess(deps);
  if (action === "inspect") return formatDomainInspect(assessment, domain);
  if (!controlId) throw new Error(`action ${action} requires a controlId`);
  const control = findDomainControl(assessment, domain, controlId);
  const request = {
    storeRoot: deps.storeRoot ?? defaultStoreRoot(),
    inventory: assessment.inventory,
    context: assessment.context,
    control,
    ...(deps.runner ? { runner: deps.runner } : {}),
    ...(deps.paths ? { paths: deps.paths } : {}),
    ...(deps.hasRoot !== undefined ? { hasRoot: deps.hasRoot } : {}),
    ...(deps.now ? { now: deps.now } : {}),
    ...(deps.target !== undefined ? { target: deps.target } : {}),
  };
  switch (action) {
    case "preview": {
      const outcome = await previewControl(request);
      return outcome.preview ? formatPreview(outcome.preview) : outcome.message;
    }
    case "apply":
      return formatOutcome(await applyControl(request));
    case "verify":
      return formatOutcome(await verifyControl(request));
    case "rollback":
      return formatOutcome(await rollbackControl(request));
  }
}

export function formatSystemInspection(inventory: ServerInventory): string {
  return formatSummary(summarizeInventory(inventory));
}

export async function lastRunSummary(storeRoot: string): Promise<string> {
  const run = await readLastRun(storeRoot);
  if (!run) return "No runs recorded yet (.server-hardener/last-run.json is absent).";
  const lines = [`last run: ${run.updatedAt} · host: ${run.hostname ?? "(unknown)"}`];
  if (run.entries.length === 0) lines.push("no changes recorded");
  for (const entry of run.entries) {
    lines.push(`- ${entry.at} ${entry.action} ${entry.controlId} [${entry.result}] ${entry.message}`);
  }
  return lines.join("\n");
}

export function remediationImplemented(controlId: string): boolean {
  return !getRemediation(controlId).manual;
}
