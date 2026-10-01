/**
 * Remediation orchestrator over a target Host.
 *
 * Enforces the safety gates in one place:
 * - the target connection is verified before any change;
 * - only controls the assessment marked `non-compliant` or `requires-review`;
 * - manual-only controls never apply;
 * - root/sudo is required where the change needs it (no password handling);
 * - backups are taken ON THE TARGET and every change is verified and recorded
 *   in `.server-hardener/last-run.json`.
 */
import type { CommandOutcome, CommandRunner } from "../exec";
import type {
  EvaluatedControl,
  LastRunEntry,
  OperationalContext,
  ServerInventory,
  VerificationResult,
} from "../models";
import { appendLastRun, newRunId, readLastRun } from "../store";
import type { Host } from "../transport/host";
import { getRemediation } from "./registry";
import {
  type AppliedChange,
  defaultSystemPaths,
  type RemediationApplyResult,
  type RemediationContext,
  type RemediationPreview,
  type SystemPaths,
} from "./types";

const APPLICABLE_STATUSES = new Set(["non-compliant", "requires-review"]);
const BACKUP_BASE = "/var/backups/server-hardener";

export interface ExecuteRequest {
  storeRoot: string;
  host: Host;
  inventory: ServerInventory;
  context: OperationalContext;
  control: EvaluatedControl;
  targetHost: string;
  target?: string;
  paths?: SystemPaths;
  hasRoot?: boolean;
  sudo?: boolean;
  now?: () => string;
}

export interface ExecutionOutcome {
  action: "preview" | "apply" | "verify" | "rollback";
  controlId: string;
  applied: boolean;
  changed: boolean;
  message: string;
  verification: VerificationResult | null;
  backupIds: string[];
  preview: RemediationPreview | null;
}

async function ensureBackupDir(
  host: Host,
  runId: string,
  hasRoot: boolean,
  sudo: boolean,
): Promise<string | null> {
  if (hasRoot || sudo) {
    const dir = `${BACKUP_BASE}/${runId}`;
    const outcome = await host.exec("mkdir", ["-p", "--", dir], { sudo: !hasRoot });
    if (outcome.status === "ok") return dir;
  }
  const home = await host.homeDir();
  if (home) {
    const dir = `${home}/.server-hardener-backups/${runId}`;
    const outcome = await host.exec("mkdir", ["-p", "--", dir]);
    if (outcome.status === "ok") return dir;
  }
  return null;
}

async function buildContext(request: ExecuteRequest, runId: string): Promise<RemediationContext> {
  const hasRoot = request.hasRoot ?? false;
  const sudo = request.sudo ?? false;
  const backupDir = await ensureBackupDir(request.host, runId, hasRoot, sudo);
  const privileged: CommandRunner = { run: (command, args) => request.host.runPrivileged(command, args) };
  const context: RemediationContext = {
    host: request.host,
    runner: privileged,
    inventory: request.inventory,
    context: request.context,
    control: request.control,
    paths: request.paths ?? defaultSystemPaths(),
    runId,
    backupDir,
    hasRoot,
    sudo,
    now: request.now ?? (() => new Date().toISOString()),
  };
  if (request.target !== undefined) context.target = request.target;
  return context;
}

function connectionMessage(outcome: CommandOutcome): string {
  switch (outcome.failureKind) {
    case "host-key":
      return "SSH host key verification failed. Add the host to known_hosts (or verify the fingerprint) before continuing.";
    case "auth":
      return "SSH authentication failed. Check your ssh config, agent and keys.";
    case "connection":
      return "SSH connection failed (host unreachable/refused/timed out).";
    case "timeout":
      return "SSH connection timed out.";
    default:
      return `SSH connection failed: ${outcome.stderr.trim() || outcome.status}`;
  }
}

export async function previewControl(request: ExecuteRequest): Promise<ExecutionOutcome> {
  const ctx = await buildContext(request, "preview");
  const preview = await getRemediation(ctx.control.controlId).preview(ctx);
  return {
    action: "preview",
    controlId: ctx.control.controlId,
    applied: false,
    changed: false,
    message: preview.manual ? `manual remediation required: ${preview.manualReason}` : "preview ready",
    verification: null,
    backupIds: [],
    preview,
  };
}

export async function applyControl(request: ExecuteRequest): Promise<ExecutionOutcome> {
  const remediation = getRemediation(request.control.controlId);
  if (remediation.manual) {
    return refused(request, `manual remediation required: ${remediation.manualReason}`);
  }
  if (!APPLICABLE_STATUSES.has(request.control.status)) {
    return refused(
      request,
      `refusing to apply ${request.control.controlId}: status is "${request.control.status}" (only non-compliant or requires-review can be applied)`,
    );
  }
  if (remediation.requiresRoot && !(request.hasRoot || request.sudo)) {
    return refused(
      request,
      "this change needs administrative privileges on the target. Connect as root or ensure passwordless sudo (sudo -n) is available; no password is handled.",
    );
  }

  const connection = await request.host.verifyConnection();
  if (connection.status !== "ok") {
    return refused(request, connectionMessage(connection));
  }

  const ctx = await buildContext(request, newRunId());
  const result = await remediation.apply(ctx);
  await record(request, "apply", result, ctx);
  return {
    action: "apply",
    controlId: ctx.control.controlId,
    applied: result.changed && result.verification.passed === true,
    changed: result.changed,
    message: result.message,
    verification: result.verification,
    backupIds: result.backupIds,
    preview: null,
  };
}

export async function verifyControl(request: ExecuteRequest): Promise<ExecutionOutcome> {
  const ctx = await buildContext(request, "verify");
  const verification = await getRemediation(ctx.control.controlId).verify(ctx);
  return {
    action: "verify",
    controlId: ctx.control.controlId,
    applied: false,
    changed: false,
    message: verification.passed === true ? "verification passed" : "verification did not pass",
    verification,
    backupIds: [],
    preview: null,
  };
}

export async function rollbackControl(request: ExecuteRequest): Promise<ExecutionOutcome> {
  const remediation = getRemediation(request.control.controlId);
  const previous = await lastAppliedChange(request.storeRoot, request.targetHost, request.control.controlId);
  if (!previous)
    return refused(
      request,
      `no applied change found for ${request.control.controlId} on ${request.targetHost}`,
    );
  if (remediation.manual) return refused(request, `manual rollback required: ${remediation.manualReason}`);
  if (remediation.requiresRoot && !(request.hasRoot || request.sudo)) {
    return refused(request, "rollback needs administrative privileges on the target.");
  }

  const ctx = await buildContext(request, previous.runId);
  let result: RemediationApplyResult;
  try {
    result = await remediation.rollback(ctx, previous.change);
  } catch (err) {
    return refused(request, `rollback failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  await record(request, "rollback", result, ctx);
  return {
    action: "rollback",
    controlId: ctx.control.controlId,
    applied: result.changed,
    changed: result.changed,
    message: result.message,
    verification: result.verification,
    backupIds: result.backupIds,
    preview: null,
  };
}

async function lastAppliedChange(
  storeRoot: string,
  targetHost: string,
  controlId: string,
): Promise<{ change: AppliedChange; runId: string } | null> {
  const run = await readLastRun(storeRoot);
  if (!run) return null;
  const entry = [...run.entries]
    .reverse()
    .find((e) => e.controlId === controlId && e.host === targetHost && e.action === "apply");
  if (!entry || entry.result === "manual") return null;
  return {
    change: {
      controlId: entry.controlId,
      target: entry.target,
      before: entry.before,
      after: entry.after,
      backupIds: entry.backupIds,
    },
    runId: entry.backupDir ? (entry.backupDir.split("/").at(-1) ?? "restore") : "restore",
  };
}

async function record(
  request: ExecuteRequest,
  action: "apply" | "rollback",
  result: RemediationApplyResult,
  ctx: RemediationContext,
): Promise<void> {
  const entry: LastRunEntry = {
    at: ctx.now(),
    host: request.targetHost,
    controlId: ctx.control.controlId,
    action,
    target: result.target,
    result: entryResult(action, result),
    changed: result.changed,
    message: result.message,
    before: result.before,
    after: result.after,
    backupDir: ctx.backupDir,
    verification: result.verification
      ? {
          check: result.verification.check,
          expected: result.verification.expected,
          observed: result.verification.observed,
          passed: result.verification.passed,
        }
      : null,
    backupIds: result.backupIds,
  };
  await appendLastRun(request.storeRoot, entry, {
    hostname: request.inventory.identity.data?.hostname ?? null,
    evaluated: 1,
  });
}

function entryResult(action: "apply" | "rollback", result: RemediationApplyResult): LastRunEntry["result"] {
  if (action === "rollback") return result.changed ? "rolled-back" : "failed";
  if (result.changed && result.verification.passed === true) return "applied";
  if (!result.changed && result.verification.passed === true) return "skipped";
  return "failed";
}

function refused(request: ExecuteRequest, message: string): ExecutionOutcome {
  return {
    action: "apply",
    controlId: request.control.controlId,
    applied: false,
    changed: false,
    message,
    verification: null,
    backupIds: [],
    preview: null,
  };
}
