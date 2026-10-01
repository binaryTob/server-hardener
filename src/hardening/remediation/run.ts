/**
 * Remediation orchestrator: preview / apply / verify / rollback for the local
 * host. Enforces the safety gates in one place:
 * - only controls the assessment marked `non-compliant` or `requires-review`;
 * - manual-only controls never apply;
 * - root is required where the change needs it (no sudo escalation);
 * - every apply/rollback is verified and recorded in `.server-hardener/last-run.json`.
 */

import { AssessmentError } from "../errors";
import { type CommandRunner, ExecCommandRunner } from "../exec";
import type {
  EvaluatedControl,
  LastRunEntry,
  OperationalContext,
  ServerInventory,
  VerificationResult,
} from "../models";
import { appendLastRun, readLastRun } from "../store";
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

export interface ExecuteRequest {
  storeRoot: string;
  inventory: ServerInventory;
  context: OperationalContext;
  control: EvaluatedControl;
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
  backupIds: string[];
  preview: RemediationPreview | null;
}

function isRoot(): boolean {
  return typeof process.getuid === "function" && process.getuid() === 0;
}

function buildContext(request: ExecuteRequest): RemediationContext {
  const context: RemediationContext = {
    inventory: request.inventory,
    context: request.context,
    control: request.control,
    storeRoot: request.storeRoot,
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
  const ctx = buildContext(request);
  const remediation = getRemediation(ctx.control.controlId);

  if (remediation.manual) {
    return refused(ctx, `manual remediation required: ${remediation.manualReason}`);
  }
  if (!APPLICABLE_STATUSES.has(ctx.control.status)) {
    return refused(
      ctx,
      `refusing to apply ${ctx.control.controlId}: status is "${ctx.control.status}" (only non-compliant or requires-review can be applied)`,
    );
  }
  if (remediation.requiresRoot && !ctx.hasRoot) {
    return refused(
      ctx,
      "this change needs administrative privileges. Run OpenCode with the appropriate privileges (no sudo escalation is performed).",
    );
  }

  const result = await remediation.apply(ctx);
  await record(ctx, "apply", result);

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
  const ctx = buildContext(request);
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
  const ctx = buildContext(request);
  const remediation = getRemediation(ctx.control.controlId);
  const previous = await lastAppliedChange(ctx.storeRoot, ctx.control.controlId);
  if (!previous) {
    return refused(ctx, `no applied change found for ${ctx.control.controlId}`);
  }
  if (remediation.manual) {
    return refused(ctx, `manual rollback required: ${remediation.manualReason}`);
  }
  if (remediation.requiresRoot && !ctx.hasRoot) {
    return refused(ctx, "rollback needs administrative privileges.");
  }

  let result: RemediationApplyResult;
  try {
    result = await remediation.rollback(ctx, previous.change);
  } catch (err) {
    return refused(ctx, `rollback failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  await record(ctx, "rollback", result);
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
  controlId: string,
): Promise<{ change: AppliedChange } | null> {
  const run = await readLastRun(storeRoot);
  if (!run) return null;
  const entry = [...run.entries].reverse().find((e) => e.controlId === controlId && e.action === "apply");
  if (!entry || entry.result === "manual") return null;
  return {
    change: {
      controlId: entry.controlId,
      target: entry.target,
      before: entry.before,
      after: entry.after,
      backupIds: entry.backupIds,
    },
  };
}

async function record(
  ctx: RemediationContext,
  action: "apply" | "rollback",
  result: RemediationApplyResult,
): Promise<void> {
  const entry: LastRunEntry = {
    at: ctx.now(),
    controlId: ctx.control.controlId,
    action,
    target: result.target,
    result: entryResult(action, result),
    changed: result.changed,
    message: result.message,
    before: result.before,
    after: result.after,
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
  await appendLastRun(ctx.storeRoot, entry, {
    hostname: ctx.inventory.identity.data?.hostname ?? null,
    evaluated: 1,
  });
}

function entryResult(action: "apply" | "rollback", result: RemediationApplyResult): LastRunEntry["result"] {
  if (action === "rollback") return result.changed ? "rolled-back" : "failed";
  if (result.changed && result.verification.passed === true) return "applied";
  if (!result.changed && result.verification.passed === true) return "skipped";
  return "failed";
}

function refused(ctx: RemediationContext, message: string): ExecutionOutcome {
  void ctx;
  return {
    action: "apply",
    controlId: ctx.control.controlId,
    applied: false,
    changed: false,
    message,
    verification: null,
    backupIds: [],
    preview: null,
  };
}

/** Ensure a control id is part of the catalog (guards tool inputs). */
export function assertKnownControl(control: EvaluatedControl | undefined): EvaluatedControl {
  if (!control) throw new AssessmentError("unknown control");
  return control;
}
