/**
 * Logging/audit remediation: enable auditd / start logging service, and
 * optionally install auditd. Package installation happens only when the
 * operator explicitly confirmed (the tool enforces confirmation); it is not
 * reversible automatically.
 */
import type { VerificationResult } from "../models";
import { newVerificationId } from "../store";
import type { Remediation, RemediationApplyResult, RemediationContext, RemediationPreview } from "./types";

function packageManager(ctx: RemediationContext): "apt" | "dnf" | null {
  const managers = ctx.inventory.packages.data?.managersDetected ?? [];
  if (managers.includes("dpkg")) return "apt";
  if (managers.includes("rpm")) return "dnf";
  return null;
}

async function unitActive(ctx: RemediationContext, unit: string): Promise<boolean | null> {
  const outcome = await ctx.runner.run("systemctl", ["is-active", unit]);
  if (outcome.status !== "ok") return null;
  return outcome.stdout.trim() === "active";
}

async function unitEnabled(ctx: RemediationContext, unit: string): Promise<boolean | null> {
  const outcome = await ctx.runner.run("systemctl", ["is-enabled", unit]);
  if (outcome.status !== "ok") return null;
  return outcome.stdout.trim() === "enabled";
}

function verification(
  ctx: RemediationContext,
  unit: string,
  active: boolean | null,
  enabled: boolean | null,
  check: string,
): VerificationResult {
  const passed = active === true && enabled !== false;
  return {
    verificationId: newVerificationId(),
    timestamp: ctx.now(),
    target: unit,
    check,
    expected: `${unit} active`,
    observed: `active=${String(active)} enabled=${String(enabled)}`,
    passed,
    evidence: [
      `systemctl is-active ${unit}: ${String(active)}`,
      `systemctl is-enabled ${unit}: ${String(enabled)}`,
    ],
    error: passed ? null : `${unit} is not active`,
  };
}

// --- AUD-001: install auditd -------------------------------------------------

const auditInstall: Remediation = {
  controlId: "AUD-001",
  requiresRoot: true,
  manual: false,
  manualReason: null,
  preview: async (ctx) => {
    const manager = packageManager(ctx);
    if (manager === null) {
      return manualPreview(ctx, "no supported package manager detected");
    }
    const command = manager === "apt" ? "apt-get install -y auditd" : "dnf install -y auditd";
    return {
      controlId: ctx.control.controlId,
      title: ctx.control.title,
      manual: false,
      manualReason: null,
      currentState: "auditd not installed",
      desiredState: "auditd installed and active",
      steps: [`install auditd with the existing package manager (${manager})`, "enable and start auditd"],
      files: [],
      commands: [command, "systemctl enable --now auditd"],
      warnings: [
        "package installation requires repository access and explicitly confirmed operator intent",
        "automatic rollback is not available for package installation (manual rollback required)",
      ],
      risk: ctx.control.risk,
      requiresRoot: true,
    };
  },
  apply: async (ctx) => {
    const manager = packageManager(ctx);
    if (manager === null) return refused(ctx, "no supported package manager detected");
    const outcome =
      manager === "apt"
        ? await ctx.runner.run("apt-get", ["install", "-y", "auditd"])
        : await ctx.runner.run("dnf", ["install", "-y", "auditd"]);
    if (outcome.status !== "ok") {
      return refused(ctx, `package installation failed: ${outcome.stderr.trim() || outcome.status}`);
    }
    await ctx.runner.run("systemctl", ["enable", "--now", "auditd"]);
    const active = await unitActive(ctx, "auditd");
    const enabled = await unitEnabled(ctx, "auditd");
    return {
      changed: true,
      target: "auditd",
      before: JSON.stringify({ installed: false }),
      after: JSON.stringify({ installed: true, active }),
      backupIds: [],
      verification: verification(ctx, "auditd", active, enabled, "auditd installed and active"),
      strategy: null,
      reversible: false,
      message: `auditd installed (${manager}); manual rollback required to uninstall`,
    };
  },
  verify: async (ctx) =>
    verification(
      ctx,
      "auditd",
      await unitActive(ctx, "auditd"),
      await unitEnabled(ctx, "auditd"),
      "auditd active",
    ),
  rollback: async (ctx) =>
    refused(ctx, "package installation is not automatically reversible (manual rollback required)"),
};

// --- AUD-002: enable auditd --------------------------------------------------

const auditEnable = makeEnableRemediation("AUD-002", "auditd", "auditd enabled and active");
// --- LOG-001: ensure a logging service is active -----------------------------

const loggingEnable: Remediation = {
  controlId: "LOG-001",
  requiresRoot: true,
  manual: false,
  manualReason: null,
  preview: async (ctx) => {
    const unit = loggingUnit(ctx);
    if (unit === null) return manualPreview(ctx, "no logging service unit is available to enable");
    return {
      controlId: ctx.control.controlId,
      title: ctx.control.title,
      manual: false,
      manualReason: null,
      currentState: "no active system logging service",
      desiredState: "a system logging service active",
      steps: [`systemctl enable --now ${unit}`],
      files: [],
      commands: [`systemctl enable --now ${unit}`],
      warnings: [],
      risk: ctx.control.risk,
      requiresRoot: true,
    };
  },
  apply: async (ctx) => {
    const unit = loggingUnit(ctx);
    if (unit === null) return refused(ctx, "no logging service unit available");
    const beforeEnabled = await unitEnabled(ctx, unit);
    const beforeActive = await unitActive(ctx, unit);
    await ctx.runner.run("systemctl", ["enable", "--now", unit]);
    const active = await unitActive(ctx, unit);
    const enabled = await unitEnabled(ctx, unit);
    return {
      changed: true,
      target: unit,
      before: JSON.stringify({ unit, enabled: beforeEnabled, active: beforeActive }),
      after: JSON.stringify({ unit, enabled, active }),
      backupIds: [],
      verification: verification(ctx, unit, active, enabled, "logging service active"),
      strategy: "restore-service-state",
      reversible: true,
      message: `${unit} enabled and started`,
    };
  },
  verify: async (ctx) => {
    const unit = loggingUnit(ctx);
    if (unit === null) return verification(ctx, "logging", null, null, "logging service active");
    return verification(
      ctx,
      unit,
      await unitActive(ctx, unit),
      await unitEnabled(ctx, unit),
      "logging service active",
    );
  },
  rollback: async (ctx, change) => {
    const before = JSON.parse(change.before ?? "{}") as {
      unit?: string;
      enabled?: boolean | null;
      active?: boolean | null;
    };
    const unit = before.unit;
    if (!unit) return refused(ctx, "no logging unit recorded");
    if (before.enabled === false) await ctx.runner.run("systemctl", ["disable", unit]);
    if (before.active === false) await ctx.runner.run("systemctl", ["stop", unit]);
    return {
      changed: true,
      target: unit,
      before: change.after,
      after: change.before,
      backupIds: [],
      verification: await loggingEnable.verify(ctx),
      strategy: "restore-service-state",
      reversible: true,
      message: `${unit} state restored`,
    };
  },
};

function loggingUnit(ctx: RemediationContext): string | null {
  const controls = ctx.inventory.securityControls.data;
  if (controls?.rsyslog.available) return "rsyslog.service";
  if (controls?.journald.available) return "systemd-journald.service";
  return null;
}

// --- helpers -----------------------------------------------------------------

function makeEnableRemediation(controlId: string, unit: string, check: string): Remediation {
  return {
    controlId,
    requiresRoot: true,
    manual: false,
    manualReason: null,
    preview: async (ctx) => ({
      controlId,
      title: ctx.control.title,
      manual: false,
      manualReason: null,
      currentState: `${unit}: active=${String(await unitActive(ctx, unit))}`,
      desiredState: `${unit} enabled and active`,
      steps: [`systemctl enable --now ${unit}`],
      files: [],
      commands: [`systemctl enable --now ${unit}`],
      warnings: [],
      risk: ctx.control.risk,
      requiresRoot: true,
    }),
    apply: async (ctx) => {
      const beforeEnabled = await unitEnabled(ctx, unit);
      const beforeActive = await unitActive(ctx, unit);
      await ctx.runner.run("systemctl", ["enable", "--now", unit]);
      const active = await unitActive(ctx, unit);
      const enabled = await unitEnabled(ctx, unit);
      const changed =
        (active === true && beforeActive !== true) || (enabled === true && beforeEnabled !== true);
      return {
        changed,
        target: unit,
        before: JSON.stringify({ unit, enabled: beforeEnabled, active: beforeActive }),
        after: JSON.stringify({ unit, enabled, active }),
        backupIds: [],
        verification: verification(ctx, unit, active, enabled, check),
        strategy: "restore-service-state",
        reversible: true,
        message: changed
          ? `${unit} enabled and started`
          : `${unit}: no change applied (unit may not exist or was already enabled/active)`,
      };
    },
    verify: async (ctx) =>
      verification(ctx, unit, await unitActive(ctx, unit), await unitEnabled(ctx, unit), check),
    rollback: async (ctx, change) => {
      const before = JSON.parse(change.before ?? "{}") as {
        enabled?: boolean | null;
        active?: boolean | null;
      };
      if (before.enabled === false) await ctx.runner.run("systemctl", ["disable", unit]);
      if (before.active === false) await ctx.runner.run("systemctl", ["stop", unit]);
      return {
        changed: true,
        target: unit,
        before: change.after,
        after: change.before,
        backupIds: [],
        verification: verification(
          ctx,
          unit,
          await unitActive(ctx, unit),
          await unitEnabled(ctx, unit),
          check,
        ),
        strategy: "restore-service-state",
        reversible: true,
        message: `${unit} state restored`,
      };
    },
  };
}

function manualPreview(ctx: RemediationContext, reason: string): RemediationPreview {
  return {
    controlId: ctx.control.controlId,
    title: ctx.control.title,
    manual: true,
    manualReason: reason,
    currentState: ctx.control.currentState,
    desiredState: ctx.control.desiredState,
    steps: [`manual remediation required: ${reason}`],
    files: [],
    commands: [],
    warnings: [],
    risk: ctx.control.risk,
    requiresRoot: false,
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
    reversible: false,
    message: reason,
  };
}

export const loggingRemediations: Record<string, Remediation> = {
  "AUD-001": auditInstall,
  "AUD-002": auditEnable,
  "LOG-001": loggingEnable,
};
