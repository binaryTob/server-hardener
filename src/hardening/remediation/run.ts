/**
 * Remediation orchestrator: preview / apply / verify / rollback.
 *
 * Enforces the safety gates in one place:
 * - only controls the plan marked `non-compliant` or `requires-review` apply;
 * - manual-only controls never apply;
 * - root is required for changes that need it (no sudo escalation is performed);
 * - every change is verified (not just exit-code checked) and recorded under
 *   state/<server-id>/{changes,verification,rollbacks}/ with its backups.
 */

import { PlanningError } from "../errors";
import { type CommandRunner, ExecCommandRunner } from "../exec";
import type { HardeningPlan, OperationalContext, ServerInventory, VerificationResult } from "../models";
import {
  loadRollback,
  newChangeId,
  newRollbackId,
  readLatestChange,
  saveChange,
  saveRollback,
  saveVerification,
} from "../state";
import { getRemediation } from "./registry";
import {
  defaultSystemPaths,
  type RemediationApplyResult,
  type RemediationContext,
  type RemediationPreview,
  type SystemPaths,
} from "./types";

const APPLICABLE_STATUSES = new Set(["non-compliant", "requires-review"]);

export interface ExecuteRequest {
  stateRoot: string;
  serverId: string;
  inventory: ServerInventory;
  context: OperationalContext;
  plan: HardeningPlan;
  controlId: string;
  target?: string;
  runner?: CommandRunner;
  paths?: SystemPaths;
  hasRoot?: boolean;
  now?: () => string;
}

export interface ExecutionOutcome {
  action: "preview" | "apply" | "verify" | "rollback";
  controlId: string;
  applied: boolean;
  changed: boolean;
  message: string;
  verification: VerificationResult | null;
  changeId: string | null;
  rollbackId: string | null;
  backupIds: string[];
  preview: RemediationPreview | null;
}

function isRoot(): boolean {
  return typeof process.getuid === "function" && process.getuid() === 0;
}

function buildContext(request: ExecuteRequest): RemediationContext {
  const control = request.plan.controls.find((c) => c.controlId === request.controlId);
  if (!control) {
    throw new PlanningError(`control ${request.controlId} is not part of plan ${request.plan.planId}`);
  }
  const context: RemediationContext = {
    serverId: request.serverId,
    inventory: request.inventory,
    context: request.context,
    plan: request.plan,
    control,
    stateRoot: request.stateRoot,
    runner: request.runner ?? new ExecCommandRunner({ timeoutMs: 120_000, maxOutputBytes: 4 * 1024 * 1024 }),
    paths: request.paths ?? defaultSystemPaths(),
    hasRoot: request.hasRoot ?? isRoot(),
    now: request.now ?? (() => new Date().toISOString()),
  };
  if (request.target !== undefined) context.target = request.target;
  return context;
}

export async function previewControl(request: ExecuteRequest): Promise<ExecutionOutcome> {
  const ctx = buildContext(request);
  const remediation = getRemediation(ctx.control.controlId);
  const preview = await remediation.preview(ctx);
  return {
    action: "preview",
    controlId: ctx.control.controlId,
    applied: false,
    changed: false,
    message: preview.manual ? `manual remediation required: ${preview.manualReason}` : "preview ready",
    verification: null,
    changeId: null,
    rollbackId: null,
    backupIds: [],
    preview,
  };
}

export async function applyControl(request: ExecuteRequest): Promise<ExecutionOutcome> {
  const ctx = buildContext(request);
  const remediation = getRemediation(ctx.control.controlId);

  if (remediation.manual) {
    return refused(ctx, `manual remediation required: ${remediation.manualReason}`);
  }
  if (!APPLICABLE_STATUSES.has(ctx.control.status)) {
    return refused(
      ctx,
      `refusing to apply ${ctx.control.controlId}: plan status is "${ctx.control.status}" (only non-compliant or requires-review may be applied)`,
    );
  }
  if (remediation.requiresRoot && !ctx.hasRoot) {
    return refused(
      ctx,
      "insufficient permissions: applying changes requires root. Run OpenCode as root; no sudo escalation is performed.",
    );
  }

  const result = await remediation.apply(ctx);
  const verificationId = result.verification.verificationId;
  await saveVerification(request.stateRoot, result.verification);

  const reversible = result.reversible && result.strategy !== null;
  const rollbackId = reversible && result.changed ? newRollbackId() : null;
  const changeId = newChangeId();
  const timestamp = ctx.now();

  if (rollbackId) {
    await saveRollback(request.stateRoot, {
      schemaVersion: 1,
      rollbackId,
      changeId,
      serverId: request.serverId,
      timestamp,
      available: true,
      strategy: result.strategy,
      artifacts: result.backupIds,
      verificationId,
    });
  }

  await saveChange(request.stateRoot, {
    schemaVersion: 1,
    changeId,
    controlId: ctx.control.controlId,
    serverId: request.serverId,
    timestamp,
    target: result.target,
    before: result.before,
    after: result.after,
    result: changeResult(result),
    verificationId,
    rollbackId,
  });

  return {
    action: "apply",
    controlId: ctx.control.controlId,
    applied: result.changed && result.verification.passed === true,
    changed: result.changed,
    message: result.message,
    verification: result.verification,
    changeId,
    rollbackId,
    backupIds: result.backupIds,
    preview: null,
  };
}

export async function verifyControl(request: ExecuteRequest): Promise<ExecutionOutcome> {
  const ctx = buildContext(request);
  const remediation = getRemediation(ctx.control.controlId);
  const verification = await remediation.verify(ctx);
  await saveVerification(request.stateRoot, verification);
  return {
    action: "verify",
    controlId: ctx.control.controlId,
    applied: false,
    changed: false,
    message: verification.passed === true ? "verification passed" : "verification did not pass",
    verification,
    changeId: null,
    rollbackId: null,
    backupIds: [],
    preview: null,
  };
}

export async function rollbackControl(request: ExecuteRequest): Promise<ExecutionOutcome> {
  const ctx = buildContext(request);
  const remediation = getRemediation(ctx.control.controlId);
  const change = await readLatestChange(request.stateRoot, request.serverId, ctx.control.controlId);
  if (!change) {
    return refused(ctx, `no applied change found for ${ctx.control.controlId}`);
  }
  if (remediation.manual) {
    return refused(ctx, `manual rollback required: ${remediation.manualReason}`);
  }
  if (remediation.requiresRoot && !ctx.hasRoot) {
    return refused(ctx, "insufficient permissions: rollback requires root");
  }
  if (!change.rollbackId) {
    return refused(ctx, "manual rollback required: no automatic rollback was recorded");
  }
  const rollback = await loadRollback(request.stateRoot, request.serverId, change.rollbackId);
  if (!rollback.available) {
    return refused(ctx, "manual rollback required: the recorded rollback is not available");
  }

  const result = await remediation.rollback(ctx, change, rollback);
  await saveVerification(request.stateRoot, result.verification);
  const changeId = newChangeId();
  await saveChange(request.stateRoot, {
    schemaVersion: 1,
    changeId,
    controlId: ctx.control.controlId,
    serverId: request.serverId,
    timestamp: ctx.now(),
    target: result.target,
    before: change.after,
    after: change.before,
    result: "rolled-back",
    verificationId: result.verification.verificationId,
    rollbackId: change.rollbackId,
  });

  return {
    action: "rollback",
    controlId: ctx.control.controlId,
    applied: result.changed,
    changed: result.changed,
    message: result.message,
    verification: result.verification,
    changeId,
    rollbackId: change.rollbackId,
    backupIds: result.backupIds,
    preview: null,
  };
}

function changeResult(result: RemediationApplyResult): "applied" | "failed" | "skipped" {
  if (result.changed && result.verification.passed === true) return "applied";
  if (!result.changed && result.verification.passed === true) return "skipped";
  return "failed";
}

function refused(ctx: RemediationContext, message: string): ExecutionOutcome {
  return {
    action: "apply",
    controlId: ctx.control.controlId,
    applied: false,
    changed: false,
    message,
    verification: null,
    changeId: null,
    rollbackId: null,
    backupIds: [],
    preview: null,
  };
}
