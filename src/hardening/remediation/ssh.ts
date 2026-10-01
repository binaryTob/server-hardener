/**
 * SSH remediation.
 *
 * Always: back up sshd_config, edit a single effective directive, validate with
 * `sshd -t`, reload (never restart) and verify the service stays active. If
 * `sshd -t` fails the backup is restored immediately.
 *
 * Controls that can lock an administrator out refuse to run unless their
 * preconditions hold (alternative admin + privilege escalation) or the operator
 * confirmed a secondary management path.
 */
import { alternativeAdminUserPrecondition, privilegeEscalationPrecondition } from "../controls/helpers";
import type { PreconditionCheck, PreconditionSpec } from "../controls/types";
import type { VerificationResult } from "../models";
import { newVerificationId } from "../store";
import { readDirective, upsertDirective } from "./config";
import { createBackup, readConfig, restoreBackup, writeConfig } from "./fsops";
import type {
  AppliedChange,
  Remediation,
  RemediationApplyResult,
  RemediationContext,
  RemediationPreview,
} from "./types";

interface SshSpec {
  key: string;
  value: string;
  lockout: boolean;
  requirePreconditions?: PreconditionSpec[];
  requireSecondaryPath?: boolean;
}

const SSH_CONTROLS: Record<string, SshSpec> = {
  "SSH-001": {
    key: "PermitRootLogin",
    value: "no",
    lockout: true,
    requirePreconditions: [alternativeAdminUserPrecondition(), privilegeEscalationPrecondition()],
  },
  "SSH-002": {
    key: "PasswordAuthentication",
    value: "no",
    lockout: true,
    requireSecondaryPath: true,
  },
  "SSH-003": { key: "PermitEmptyPasswords", value: "no", lockout: false },
  "SSH-004": { key: "X11Forwarding", value: "no", lockout: false },
  "SSH-005": { key: "MaxAuthTries", value: "4", lockout: false },
};

function spec(ctx: RemediationContext): SshSpec {
  const found = SSH_CONTROLS[ctx.control.controlId];
  if (!found) throw new Error(`no SSH spec for ${ctx.control.controlId}`);
  return found;
}

function serviceUnit(ctx: RemediationContext): string {
  return ctx.inventory.securityControls.data?.sshServer.unit ?? "ssh.service";
}

async function effectiveDirective(ctx: RemediationContext, key: string): Promise<string | null> {
  const outcome = await ctx.runner.run("sshd", ["-T"]);
  if (outcome.status === "ok") {
    const match = new RegExp(`^\\s*${key}\\s+(\\S+)`, "im").exec(outcome.stdout);
    if (match) return match[1] ?? null;
  }
  const text = await readConfig(ctx, ctx.paths.sshdConfig);
  return text ? readDirective(text, key) : null;
}

/** A reason the control must not be applied automatically, or null. */
function unsafeReason(ctx: RemediationContext): string | null {
  const current = spec(ctx);
  if (current.requireSecondaryPath && ctx.context.management.secondaryPathConfirmed !== true) {
    return "refusing to disable password authentication: no secondary management path has been confirmed (set management.secondaryPathConfirmed)";
  }
  for (const precondition of current.requirePreconditions ?? []) {
    const check: PreconditionCheck = precondition.check(ctx.inventory, ctx.context);
    if (check.status !== "satisfied") {
      return `refusing to apply: precondition "${precondition.id}" is ${check.status}${check.reason ? ` (${check.reason})` : ""}`;
    }
  }
  return null;
}

async function preview(ctx: RemediationContext): Promise<RemediationPreview> {
  const current = spec(ctx);
  const fileText = await readConfig(ctx, ctx.paths.sshdConfig);
  const observed = await effectiveDirective(ctx, current.key);
  const warnings: string[] = [];
  if (current.lockout) {
    warnings.push(
      "LOCKOUT RISK: this change can remove the ability to log in if the alternative access path is not verified.",
    );
  }
  if (fileText === null) {
    return {
      controlId: ctx.control.controlId,
      title: ctx.control.title,
      manual: true,
      manualReason: `${ctx.paths.sshdConfig} is not readable`,
      currentState: null,
      desiredState: `${current.key} ${current.value}`,
      steps: [],
      files: [],
      commands: [],
      warnings,
      risk: ctx.control.risk,
      requiresRoot: true,
    };
  }
  if (/^\s*Include\s+/m.test(fileText)) {
    warnings.push(
      "sshd_config contains Include directives; an included file may override this directive — verify with sshd -T after applying.",
    );
  }
  const unsafe = unsafeReason(ctx);
  if (unsafe) warnings.push(unsafe);

  return {
    controlId: ctx.control.controlId,
    title: ctx.control.title,
    manual: unsafe !== null,
    manualReason: unsafe,
    currentState: `${current.key} ${observed ?? "(not observable)"}`,
    desiredState: `${current.key} ${current.value}`,
    steps: [
      `back up ${ctx.paths.sshdConfig}`,
      `set "${current.key} ${current.value}"`,
      "validate with sshd -t",
      `reload ${serviceUnit(ctx)} and confirm it stays active`,
    ],
    files: [{ path: ctx.paths.sshdConfig, willBackup: true }],
    commands: ["sshd -t", `systemctl reload ${serviceUnit(ctx)}`],
    warnings,
    risk: ctx.control.risk,
    requiresRoot: true,
  };
}

async function verify(ctx: RemediationContext): Promise<VerificationResult> {
  const current = spec(ctx);
  const syntax = await ctx.runner.run("sshd", ["-t"]);
  const effective = await effectiveDirective(ctx, current.key);
  const active = await ctx.runner.run("systemctl", ["is-active", serviceUnit(ctx)]);
  const evidence = [
    `sshd -t: ${syntax.status}`,
    `${current.key}: ${effective ?? "?"} (expected ${current.value})`,
    `service: ${active.stdout.trim() || active.status}`,
  ];
  const passed =
    syntax.status === "ok" &&
    active.stdout.trim() === "active" &&
    effective?.toLowerCase() === current.value.toLowerCase();
  return {
    verificationId: newVerificationId(),
    timestamp: ctx.now(),
    target: ctx.paths.sshdConfig,
    check: "sshd syntax valid, service active and effective directive as desired",
    expected: `${current.key} ${current.value}; sshd active`,
    observed: evidence.join("; "),
    passed,
    evidence,
    error: passed ? null : "verification failed",
  };
}

async function apply(ctx: RemediationContext): Promise<RemediationApplyResult> {
  const current = spec(ctx);
  const unsafe = unsafeReason(ctx);
  if (unsafe) {
    return refused(ctx, unsafe);
  }
  const original = await readConfig(ctx, ctx.paths.sshdConfig);
  if (original === null) {
    return refused(ctx, `${ctx.paths.sshdConfig} is not readable`);
  }
  const backup = await createBackup(ctx, ctx.paths.sshdConfig);
  const { content, previous, changed } = upsertDirective(original, current.key, current.value);
  await writeConfig(ctx, ctx.paths.sshdConfig, content);

  const syntax = await ctx.runner.run("sshd", ["-t"]);
  if (syntax.status !== "ok") {
    await writeConfig(ctx, ctx.paths.sshdConfig, original);
    const verification = await verify(ctx);
    return {
      changed: false,
      target: ctx.paths.sshdConfig,
      before: JSON.stringify({ key: current.key, previous }),
      after: null,
      backupIds: [backup.backupId],
      verification: { ...verification, passed: false, error: "sshd -t failed; configuration restored" },
      strategy: "restore-sshd-config-and-reload",
      reversible: true,
      message: `sshd -t failed (${syntax.stderr.trim() || "syntax error"}); backup restored, no change kept`,
    };
  }

  const reload = await reloadSsh(ctx);
  const verification = await verify(ctx);
  return {
    changed,
    target: ctx.paths.sshdConfig,
    before: JSON.stringify({ key: current.key, previous, backupId: backup.backupId }),
    after: JSON.stringify({ key: current.key, value: current.value }),
    backupIds: [backup.backupId],
    verification,
    strategy: "restore-sshd-config-and-reload",
    reversible: true,
    message: reload.ok
      ? `SSH ${current.key} set to ${current.value} and ${serviceUnit(ctx)} reloaded`
      : `SSH configuration changed and validated, but reload reported: ${reload.detail}`,
  };
}

async function reloadSsh(ctx: RemediationContext): Promise<{ ok: boolean; detail: string }> {
  for (const unit of [serviceUnit(ctx), "sshd.service"]) {
    const outcome = await ctx.runner.run("systemctl", ["reload", unit]);
    if (outcome.status === "ok") return { ok: true, detail: unit };
  }
  return { ok: false, detail: "systemctl reload failed for ssh/sshd" };
}

async function rollback(ctx: RemediationContext, change: AppliedChange): Promise<RemediationApplyResult> {
  const before = JSON.parse(change.before ?? "{}") as { backupId?: string };
  if (!before.backupId) return refused(ctx, "no SSH backup recorded; manual rollback required");
  await restoreBackup(ctx, before.backupId);
  const syntax = await ctx.runner.run("sshd", ["-t"]);
  if (syntax.status === "ok") await reloadSsh(ctx);
  const verification = await verify(ctx);
  return {
    changed: true,
    target: ctx.paths.sshdConfig,
    before: change.after,
    after: change.before,
    backupIds: [],
    verification,
    strategy: "restore-sshd-config-and-reload",
    reversible: true,
    message: "sshd_config restored from backup",
  };
}

function refused(ctx: RemediationContext, reason: string): RemediationApplyResult {
  return {
    changed: false,
    target: ctx.control.controlId,
    before: null,
    after: null,
    backupIds: [],
    verification: {
      verificationId: newVerificationId(),
      timestamp: ctx.now(),
      target: ctx.control.controlId,
      check: "apply refused",
      expected: ctx.control.desiredState,
      observed: null,
      passed: false,
      evidence: [reason],
      error: reason,
    },
    strategy: null,
    reversible: true,
    message: reason,
  };
}

export const sshRemediations: Record<string, Remediation> = Object.fromEntries(
  Object.keys(SSH_CONTROLS).map((id) => [
    id,
    {
      controlId: id,
      requiresRoot: true,
      manual: false,
      manualReason: null,
      preview,
      apply,
      verify,
      rollback,
    } satisfies Remediation,
  ]),
);
