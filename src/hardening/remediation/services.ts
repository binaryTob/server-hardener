/**
 * Service remediation (SVC-001): disable/stop known-insecure services only.
 *
 * Unrecognised services are never touched. Rollback re-enables/re-starts a unit
 * based on the state recorded before the change.
 */
import type { ChangeRecord, VerificationResult } from "../models";
import { newVerificationId } from "../state";
import type { Remediation, RemediationApplyResult, RemediationContext, RemediationPreview } from "./types";

export const SERVICE_UNIT_PATTERN = /^[a-zA-Z0-9_.@:-]+\.(service|socket|timer)$/;

const INSECURE_FRAGMENTS = [
  "telnet",
  "rlogin",
  "rsh",
  "rexec",
  "tftp",
  "vsftpd",
  "pure-ftpd",
  "proftpd",
  "ftpd",
  "finger",
  "vnc",
];

interface UnitState {
  unit: string;
  enabled: boolean | null;
  active: boolean | null;
}

function targetUnits(ctx: RemediationContext): string[] {
  if (ctx.target) {
    if (!SERVICE_UNIT_PATTERN.test(ctx.target)) throw new Error(`invalid service unit ${ctx.target}`);
    return [ctx.target];
  }
  return (ctx.inventory.services.data?.services ?? [])
    .filter((s) => s.enabled === true || s.active === true)
    .filter((s) => INSECURE_FRAGMENTS.some((fragment) => s.name.toLowerCase().includes(fragment)))
    .map((s) => s.name);
}

function relatedListeners(ctx: RemediationContext, unit: string): string[] {
  const base = unit.replace(/\.(service|socket|timer)$/, "").toLowerCase();
  return (ctx.inventory.sockets.data?.sockets ?? [])
    .filter((s) => (s.processName ?? "").toLowerCase().includes(base.slice(0, 6)))
    .map((s) => `${s.port ?? "?"}/${s.protocol} (${s.scope})`);
}

async function stateOf(ctx: RemediationContext, unit: string): Promise<UnitState> {
  const enabled = await ctx.runner.run("systemctl", ["is-enabled", unit]);
  const active = await ctx.runner.run("systemctl", ["is-active", unit]);
  return {
    unit,
    enabled: enabled.status === "ok" ? enabled.stdout.trim() !== "disabled" : null,
    active: active.status === "ok" ? active.stdout.trim() === "active" : null,
  };
}

async function preview(ctx: RemediationContext): Promise<RemediationPreview> {
  const units = targetUnits(ctx);
  const details: string[] = [];
  for (const unit of units) {
    const state = await stateOf(ctx, unit);
    const listeners = relatedListeners(ctx, unit);
    details.push(
      `${unit} (enabled=${String(state.enabled)}, active=${String(state.active)})` +
        (listeners.length > 0 ? ` listeners: ${listeners.join(", ")}` : ""),
    );
  }
  return {
    controlId: ctx.control.controlId,
    title: ctx.control.title,
    manual: units.length === 0,
    manualReason: units.length === 0 ? "no insecure service identified in the inventory" : null,
    currentState: details.join("; ") || "none",
    desiredState: "insecure services disabled and stopped",
    steps: units.map((unit) => `systemctl disable --now ${unit}`),
    files: [],
    commands: units.map((unit) => `systemctl disable --now ${unit}`),
    warnings: ["disabling a service affects availability; confirm it is not required before applying"],
    risk: ctx.control.risk,
    requiresRoot: true,
  };
}

async function apply(ctx: RemediationContext): Promise<RemediationApplyResult> {
  const units = targetUnits(ctx);
  if (units.length === 0) {
    return {
      changed: false,
      target: ctx.control.controlId,
      before: null,
      after: null,
      backupIds: [],
      verification: await verify(ctx),
      strategy: "restore-service-state",
      reversible: true,
      message: "no insecure service to disable",
    };
  }
  const before: UnitState[] = [];
  for (const unit of units) {
    before.push(await stateOf(ctx, unit));
    await ctx.runner.run("systemctl", ["disable", "--now", unit]);
  }
  const verification = await verify(ctx);
  return {
    changed: true,
    target: units.join(", "),
    before: JSON.stringify({ units: before }),
    after: JSON.stringify({ units: units.map((unit) => ({ unit, enabled: false, active: false })) }),
    backupIds: [],
    verification,
    strategy: "restore-service-state",
    reversible: true,
    message: `disabled and stopped: ${units.join(", ")}`,
  };
}

async function verify(ctx: RemediationContext): Promise<VerificationResult> {
  const units = targetUnits(ctx);
  const evidence: string[] = [];
  let passed = units.length > 0;
  for (const unit of units) {
    const state = await stateOf(ctx, unit);
    const ok = state.enabled === false && state.active === false;
    if (!ok) passed = false;
    evidence.push(`${unit}: enabled=${String(state.enabled)} active=${String(state.active)}`);
  }
  return {
    schemaVersion: 1,
    verificationId: newVerificationId(),
    serverId: ctx.serverId,
    timestamp: ctx.now(),
    target: units.join(", ") || ctx.control.controlId,
    check: "target services disabled and inactive",
    expected: "enabled=false, active=false",
    observed: evidence.join("; ") || "no target services",
    passed,
    evidence,
    error: passed ? null : "one or more services are still enabled or active",
  };
}

async function rollback(ctx: RemediationContext, change: ChangeRecord): Promise<RemediationApplyResult> {
  const before = JSON.parse(change.before ?? "{}") as { units?: UnitState[] };
  const units = before.units ?? [];
  for (const unit of units) {
    if (unit.enabled) await ctx.runner.run("systemctl", ["enable", unit.unit]);
    if (unit.active) await ctx.runner.run("systemctl", ["start", unit.unit]);
  }
  return {
    changed: units.length > 0,
    target: units.map((u) => u.unit).join(", "),
    before: change.after,
    after: change.before,
    backupIds: [],
    verification: await verify(ctx),
    strategy: "restore-service-state",
    reversible: true,
    message: units.length > 0 ? "service state restored" : "nothing to restore",
  };
}

export const serviceRemediations: Record<string, Remediation> = {
  "SVC-001": {
    controlId: "SVC-001",
    requiresRoot: true,
    manual: false,
    manualReason: null,
    preview,
    apply,
    verify,
    rollback,
  },
};
