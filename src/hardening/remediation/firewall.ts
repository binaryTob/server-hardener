/**
 * Firewall remediation (FW-001).
 *
 * Enabling a host firewall can cut off the current administrative session, so
 * this remediation (a) determines the administrative port from observed SSH
 * listeners, (b) never closes existing access, and (c) supports only the
 * implementation already present. It never replaces one firewall with another.
 * nftables rule generation is deliberately NOT automated.
 */
import { managementPorts } from "../controls/helpers";
import type { VerificationResult } from "../models";
import { newVerificationId } from "../store";
import type {
  AppliedChange,
  Remediation,
  RemediationApplyResult,
  RemediationContext,
  RemediationPreview,
} from "./types";

type FirewallKind = "ufw" | "firewalld" | "nftables" | null;

function implementation(ctx: RemediationContext): FirewallKind {
  const detected = ctx.inventory.securityControls.data?.firewall.detectedImplementations ?? [];
  if (detected.includes("ufw")) return "ufw";
  if (detected.includes("firewalld")) return "firewalld";
  if (detected.includes("nftables")) return "nftables";
  return null;
}

function administrativePorts(ctx: RemediationContext): number[] {
  // Use the operator-declared / observed SSH ports; never assume 22.
  return managementPorts(ctx.inventory, ctx.context);
}

async function ufwActive(ctx: RemediationContext): Promise<boolean | null> {
  const outcome = await ctx.runner.run("ufw", ["status"]);
  if (outcome.status !== "ok") return null;
  return /Status:\s*active/i.test(outcome.stdout);
}

async function firewalldActive(ctx: RemediationContext): Promise<boolean | null> {
  const outcome = await ctx.runner.run("firewall-cmd", ["--state"]);
  if (outcome.status !== "ok") return null;
  return outcome.stdout.trim() === "running";
}

async function preview(ctx: RemediationContext): Promise<RemediationPreview> {
  const kind = implementation(ctx);
  if (kind === "firewalld") {
    return manual(
      ctx,
      "firewalld requires a reviewed zone/interface and administrative-port policy; automatic activation is disabled",
    );
  }
  if (kind === "nftables") {
    return manual(
      ctx,
      "nftables ruleset generation is not automated in Phase 3; apply a reviewed ruleset manually",
    );
  }
  if (kind === null) {
    return manual(ctx, "no firewall implementation detected; refusing to install or replace one");
  }
  const ports = administrativePorts(ctx);
  const warnings: string[] = [];
  if (ports.length === 0) {
    return manual(ctx, "no administrative SSH port is known; refusing to enable a firewall");
  }
  const commands = [...ports.map((p) => `ufw allow ${p}/tcp`), "ufw --force enable"];
  return {
    controlId: ctx.control.controlId,
    title: ctx.control.title,
    manual: false,
    manualReason: null,
    currentState: `implementation: ${kind}`,
    desiredState: "host firewall active without closing administrative access",
    steps: ["ensure administrative port(s) are allowed, then enable"],
    files: [],
    commands,
    warnings,
    risk: ctx.control.risk,
    requiresRoot: true,
  };
}

function manual(ctx: RemediationContext, reason: string): RemediationPreview {
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

async function verify(ctx: RemediationContext): Promise<VerificationResult> {
  const kind = implementation(ctx);
  let passed: boolean | null = null;
  let observed: string | null = null;
  if (kind === "ufw") {
    passed = await ufwActive(ctx);
    observed = `ufw active: ${String(passed)}`;
  } else if (kind === "firewalld") {
    passed = await firewalldActive(ctx);
    observed = `firewalld running: ${String(passed)}`;
  }
  return {
    verificationId: newVerificationId(),
    timestamp: ctx.now(),
    target: kind ?? "firewall",
    check: "host firewall active",
    expected: "active",
    observed,
    passed,
    evidence: observed ? [observed] : ["no firewall implementation detected"],
    error: passed === null ? "firewall state could not be determined" : null,
  };
}

async function apply(ctx: RemediationContext): Promise<RemediationApplyResult> {
  const kind = implementation(ctx);
  if (kind !== "ufw") {
    return {
      changed: false,
      target: "firewall",
      before: null,
      after: null,
      backupIds: [],
      verification: await verify(ctx),
      strategy: null,
      reversible: false,
      message: "manual remediation required for this firewall implementation",
    };
  }
  const wasActive = await ufwActive(ctx);
  const ports = administrativePorts(ctx);
  if (wasActive === null || ports.length === 0 || wasActive) {
    return {
      changed: false,
      target: kind,
      before: null,
      after: null,
      backupIds: [],
      verification: await verify(ctx),
      strategy: null,
      reversible: false,
      message: wasActive
        ? "ufw already active; no rules changed"
        : "refusing firewall activation: current state or administrative port is unknown",
    };
  }
  for (const port of ports) {
    const allowed = await ctx.runner.run("ufw", ["allow", `${port}/tcp`]);
    if (allowed.status !== "ok") {
      return {
        changed: false,
        target: kind,
        before: null,
        after: null,
        backupIds: [],
        verification: await verify(ctx),
        strategy: null,
        reversible: false,
        message:
          "administrative allow rule failed; firewall was not enabled; review any previously added allow rules",
      };
    }
  }
  await ctx.runner.run("ufw", ["--force", "enable"]);
  const verification = await verify(ctx);
  return {
    changed: true,
    target: kind,
    before: JSON.stringify({ implementation: kind, active: wasActive }),
    after: JSON.stringify({ implementation: kind, active: true }),
    backupIds: [],
    verification,
    strategy: "disable-firewall-if-not-previously-active",
    reversible: true,
    message: `${kind} activation attempted after administrative allow rules; fresh SSH reconnection still required`,
  };
}

async function rollback(ctx: RemediationContext, change: AppliedChange): Promise<RemediationApplyResult> {
  const before = JSON.parse(change.before ?? "{}") as { implementation?: string; active?: boolean | null };
  if (before.active !== false) {
    return {
      changed: false,
      target: before.implementation ?? "firewall",
      before: change.after,
      after: change.before,
      backupIds: [],
      verification: await verify(ctx),
      strategy: null,
      reversible: false,
      message: "firewall was already active before the change; manual review required to roll back",
    };
  }
  if (before.implementation === "ufw") {
    await ctx.runner.run("ufw", ["disable"]);
  } else if (before.implementation === "firewalld") {
    await ctx.runner.run("systemctl", ["disable", "--now", "firewalld"]);
  }
  return {
    changed: true,
    target: before.implementation ?? "firewall",
    before: change.after,
    after: change.before,
    backupIds: [],
    verification: await verify(ctx),
    strategy: "disable-firewall-if-not-previously-active",
    reversible: true,
    message: "firewall returned to its previous state",
  };
}

export const firewallRemediations: Record<string, Remediation> = {
  "FW-001": {
    controlId: "FW-001",
    requiresRoot: true,
    manual: false,
    manualReason: null,
    preview,
    apply,
    verify,
    rollback,
  },
};
