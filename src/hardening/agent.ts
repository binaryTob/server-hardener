/**
 * High-level agent API.
 *
 * The agent runs on the OPERATOR workstation and operates on ONE target host
 * per session via SSH (or LocalHost only when `localhost` is named explicitly).
 * This module resolves the target, runs discovery/evaluation against it, drives
 * remediation and renders text for the OpenCode tools.
 */
import { CATALOG_VERSION, CONTROL_CATALOG } from "./controls/catalog";
import { NoTargetError } from "./errors";
import { formatSummary, runDiscovery, summarizeInventory } from "./inventory";
import type { EvaluatedControl, OperationalContext, PlanningQuestion, Tier } from "./models";
import { contextCompleteness, emptyContext, withDetectedRoles } from "./planning/context";
import { evaluateCatalog } from "./planning/evaluate";
import { buildQuestions, missingContextByPath } from "./planning/questions";
import {
  applyControl,
  type ExecuteRequest,
  type ExecutionOutcome,
  previewControl,
  rollbackControl,
  verifyControl,
} from "./remediation/run";
import {
  defaultStoreRoot,
  readContext,
  readLastRun,
  readSession,
  type SessionInfo,
  saveContext,
  writeSession,
} from "./store";
import { createHost, type Host, type HostFactoryOptions, probeHost } from "./transport/host";
import { parseTarget, type TargetSpec } from "./transport/target";

export interface AgentDeps {
  storeRoot?: string;
  hostOptions?: HostFactoryOptions;
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

export interface HostMeta {
  label: string;
  target: string;
  root: boolean;
  sudo: boolean;
  isLocalhost: boolean;
  hostname: string | null;
}

export interface Assessment {
  meta: HostMeta;
  context: OperationalContext;
  controls: EvaluatedControl[];
  byTier: Record<Tier, EvaluatedControl[]>;
  questions: PlanningQuestion[];
  contextMissing: string[];
  catalogVersion: string;
  inventorySummary: string;
}

function now(deps: AgentDeps): string {
  return (deps.now ?? (() => new Date().toISOString()))();
}

// --- Target resolution -----------------------------------------------------

function resolveTargetString(explicit: string | undefined, session: SessionInfo | null): string {
  if (explicit !== undefined) return explicit;
  if (session) return session.target;
  throw new NoTargetError(
    'No target selected. Choose a server first, e.g. target { action: "connect", target: "admin@server.example" }.',
  );
}

export async function resolveHost(
  storeRoot: string,
  explicitTarget: string | undefined,
  deps: AgentDeps,
): Promise<{ host: Host; spec: TargetSpec; session: SessionInfo | null }> {
  const session = await readSession(storeRoot);
  const targetString = resolveTargetString(explicitTarget, session);
  const spec = parseTarget(targetString);
  const host = createHost(spec, deps.hostOptions ?? {});
  return { host, spec, session };
}

export interface ConnectResult {
  host: Host;
  spec: TargetSpec;
  info: SessionInfo;
  connectionMessage: string;
}

/** Validate + connect to a target and remember it for the session. */
export async function connectTarget(
  storeRoot: string,
  targetString: string,
  deps: AgentDeps,
): Promise<ConnectResult> {
  const spec = parseTarget(targetString);
  const host = createHost(spec, deps.hostOptions ?? {});
  const connection = await host.verifyConnection();
  if (connection.status !== "ok") {
    throw new NoTargetError(describeConnection(connection));
  }
  const probe = await probeHost(host);
  const info: SessionInfo = {
    target: targetString.trim(),
    connectedAt: now(deps),
    hostname: host.label,
    root: probe.root,
    sudo: probe.sudo,
    isLocalhost: spec.isLocalhost,
  };
  await writeSession(storeRoot, info);
  if (spec.port !== null) {
    const stored = await readContext(storeRoot);
    if (stored === null || (stored.management.sshPort ?? null) === null) {
      const base = stored ?? emptyContext(now(deps));
      await saveContext(storeRoot, {
        ...base,
        management: { ...base.management, sshPort: spec.port },
        updatedAt: now(deps),
      });
    }
  }
  return { host, spec, info, connectionMessage: "SSH connection OK." };
}

export function describeTargetInfo(targetString: string, info: SessionInfo): string {
  const lines = [
    `Active target: ${targetString}`,
    `  destination: ${info.hostname ?? "(unknown)"}`,
    `  local: ${info.isLocalhost}`,
    `  root: ${info.root} · passwordless sudo: ${info.sudo}`,
    `  connectedAt: ${info.connectedAt}`,
  ];
  if (!info.root && !info.sudo) {
    lines.push("  note: privileged changes need root or passwordless sudo on the target.");
  }
  return lines.join("\n");
}

function describeConnection(outcome: { failureKind?: string; stderr: string; status: string }): string {
  switch (outcome.failureKind) {
    case "host-key":
      return "SSH host key verification failed. Add the host to known_hosts (or verify its fingerprint) and retry.";
    case "auth":
      return "SSH authentication failed. Check your ssh config, agent and keys.";
    case "connection":
      return "SSH connection failed (unreachable / refused / timed out).";
    case "timeout":
      return "SSH connection timed out.";
    default:
      return `SSH connection failed: ${outcome.stderr.trim() || outcome.status}`;
  }
}

// --- Assessment ------------------------------------------------------------

async function assessHost(
  host: Host,
  spec: TargetSpec,
  storeRoot: string,
  deps: AgentDeps,
): Promise<Assessment> {
  const inventory = await runDiscovery({ runner: host, files: host, platform: host.platformHint });
  const stored = await readContext(storeRoot);
  let context = withDetectedRoles(stored ?? emptyContext(now(deps)), inventory);
  if ((context.management.sshPort ?? null) === null && spec.port !== null) {
    context = { ...context, management: { ...context.management, sshPort: spec.port } };
  }
  const { controls, byTier } = evaluateCatalog(CONTROL_CATALOG, inventory, context);
  const questions = buildQuestions(missingContextByPath(controls));
  const probe = await probeHost(host);
  return {
    meta: {
      label: host.label,
      target: spec.raw,
      root: probe.root,
      sudo: probe.sudo,
      isLocalhost: spec.isLocalhost,
      hostname: inventory.identity.data?.hostname ?? null,
    },
    context,
    controls,
    byTier,
    questions,
    contextMissing: contextCompleteness(context).missing,
    catalogVersion: CATALOG_VERSION,
    inventorySummary: formatSummary(summarizeInventory(inventory)),
  };
}

export async function assess(deps: AgentDeps & { target?: string } = {}): Promise<Assessment> {
  const storeRoot = deps.storeRoot ?? defaultStoreRoot();
  const { host, spec } = await resolveHost(storeRoot, deps.target, deps);
  return assessHost(host, spec, storeRoot, deps);
}

// --- Text rendering --------------------------------------------------------

export function formatAssessment(assessment: Assessment): string {
  const lines: string[] = [];
  lines.push(`Target: ${assessment.meta.label}`);
  lines.push(`Host:   ${assessment.meta.hostname ?? "(unknown)"}`);
  lines.push("");
  lines.push(assessment.inventorySummary);
  lines.push("");

  const renderTier = (label: string, tier: Tier) => {
    const controls = assessment.byTier[tier];
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

  if (assessment.contextMissing.length > 0) {
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
  for (const precondition of control.preconditions) {
    lines.push(
      `  precondition ${precondition.critical ? "[critical] " : ""}${precondition.id}: ${precondition.status}`,
    );
  }
  for (const blocker of control.blockers) lines.push(`  blocked: ${blocker}`);
  if (control.missingContext.length > 0) lines.push(`missing context: ${control.missingContext.join(", ")}`);
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
    lines.push("Files (backed up first, on the target):");
    for (const file of preview.files) lines.push(`  - ${file.path}`);
  }
  if (preview.commands.length > 0) {
    lines.push("Commands (on the target):");
    for (const command of preview.commands) lines.push(`  - ${command}`);
  }
  if (preview.warnings.length > 0) {
    lines.push("");
    lines.push("WARNINGS:");
    for (const warning of preview.warnings) lines.push(`  ! ${warning}`);
  }
  lines.push("");
  lines.push(
    `To apply: call the matching harden_* tool with action 'apply' and confirm: true after operator approval.`,
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
  if (outcome.backupIds.length > 0) lines.push(`backups (on target): ${outcome.backupIds.join(", ")}`);
  return lines.join("\n");
}

// --- Domain operations -----------------------------------------------------

export function controlBelongsToDomain(domain: HardenDomain, controlId: string): boolean {
  return HARDEN_DOMAINS[domain].some((prefix) => controlId.startsWith(`${prefix}-`));
}

function domainControls(assessment: Assessment, domain: HardenDomain): EvaluatedControl[] {
  return assessment.controls.filter((control) => controlBelongsToDomain(domain, control.controlId));
}

export function formatDomainInspect(assessment: Assessment, domain: HardenDomain): string {
  const lines: string[] = [`${domain} controls on ${assessment.meta.label}`];
  for (const control of domainControls(assessment, domain)) {
    lines.push(`- ${control.controlId} [${control.tier}/${control.status}] ${control.title}`);
    lines.push(`    current: ${control.currentState ?? "(unknown)"}`);
    lines.push(`    desired: ${control.desiredState}`);
  }
  return lines.join("\n");
}

export async function domainAction(
  domain: HardenDomain,
  action: "inspect" | "preview" | "apply" | "verify" | "rollback",
  controlId: string | undefined,
  deps: AgentDeps & { target?: string; targetUnit?: string } = {},
): Promise<string> {
  const storeRoot = deps.storeRoot ?? defaultStoreRoot();
  const { host, spec } = await resolveHost(storeRoot, deps.target, deps);
  const assessment = await assessHost(host, spec, storeRoot, deps);

  if (action === "inspect") return formatDomainInspect(assessment, domain);
  if (!controlId) throw new NoTargetError(`action ${action} requires a controlId`);
  if (!controlBelongsToDomain(domain, controlId)) {
    throw new NoTargetError(`control ${controlId} does not belong to ${domain}`);
  }
  const control = assessment.controls.find((c) => c.controlId === controlId);
  if (!control) throw new NoTargetError(`unknown control ${controlId}`);

  const request: ExecuteRequest = {
    storeRoot,
    host,
    inventory: await runDiscovery({ runner: host, files: host, platform: host.platformHint }),
    context: assessment.context,
    control,
    targetHost: host.label,
    hasRoot: assessment.meta.root,
    sudo: assessment.meta.sudo,
    ...(deps.now ? { now: deps.now } : {}),
    ...(deps.targetUnit !== undefined ? { target: deps.targetUnit } : {}),
  };

  switch (action) {
    case "preview": {
      const outcome = await previewControl(request);
      return outcome.preview ? formatPreview(outcome.preview) : outcome.message;
    }
    case "verify":
      return formatOutcome(await verifyControl(request));
    case "rollback":
      return formatOutcome(await rollbackControl(request));
    case "apply": {
      const outcome = await applyControl(request);
      let text = formatOutcome(outcome);
      if (outcome.changed && (domain === "ssh" || domain === "firewall")) {
        text += await reconnectCheck(host, request);
      }
      return text;
    }
  }
}

/** After an access-affecting change, prove a NEW connection from here works. */
async function reconnectCheck(host: Host, request: ExecuteRequest): Promise<string> {
  const attempts = 3;
  let connection = await host.verifyConnection();
  for (let i = 1; i < attempts && connection.status !== "ok"; i++) {
    // Servers may temporarily rate-limit fresh connections; retry before
    // concluding the change locked us out.
    await new Promise((resolve) => setTimeout(resolve, 2000));
    connection = await host.verifyConnection();
  }
  if (connection.status === "ok") {
    return "\nreconnect check: OK — a new SSH session from the workstation succeeded.";
  }

  const kind = connection.failureKind ?? connection.status;
  if (kind === "auth" || kind === "host-key") {
    const rollback = await rollbackControl(request);
    return `\nreconnect check: FAILED (${kind}). Automatic rollback attempted: ${rollback.message}`;
  }

  // connection/timeout: may be transient rate limiting. Confirm the authorized
  // administrative port is still listening before deciding.
  const port = request.context.management.sshPort ?? null;
  const ss = await host.exec("ss", ["-tln"]);
  const listening = port !== null && new RegExp(`:${port}\\s`).test(ss.stdout);
  if (listening) {
    return `\nreconnect check: not confirmed (${kind}); the authorized port ${port} is still listening, so the change was kept. Retry SSH if the session drops.`;
  }
  const rollback = await rollbackControl(request);
  return `\nreconnect check: FAILED (${kind}) and port ${port ?? "?"} is not listening. Automatic rollback attempted: ${rollback.message}`;
}

// --- Misc ------------------------------------------------------------------

export function formatSystemInspection(summary: string): string {
  return summary;
}

export async function lastRunSummary(storeRoot: string): Promise<string> {
  const run = await readLastRun(storeRoot);
  if (!run) return "No runs recorded yet (.server-hardener/last-run.json is absent).";
  const lines = [`last run: ${run.updatedAt} · host: ${run.hostname ?? "(unknown)"}`];
  if (run.entries.length === 0) lines.push("no changes recorded");
  for (const entry of run.entries) {
    lines.push(
      `- ${entry.at} ${entry.host} ${entry.action} ${entry.controlId} [${entry.result}] ${entry.message}`,
    );
  }
  return lines.join("\n");
}
