/**
 * Firewall remediation (FW-001).
 *
 * Enabling a host firewall can cut off the current administrative session, so
 * this remediation (a) determines the administrative port from observed SSH
 * listeners, (b) never closes existing access, and (c) supports only the
 * implementation already present. It never replaces one firewall with another.
 * nftables rule generation is deliberately NOT automated.
 */
import type { ChangeRecord, VerificationResult } from "../models";
import { newVerificationId } from "../state";
import type { Remediation, RemediationApplyResult, RemediationContext, RemediationPreview } from "./types";

type FirewallKind = "ufw" | "firewalld" | "nftables" | null;

function implementation(ctx: RemediationContext): FirewallKind {
  const detected = ctx.inventory.securityControls.data?.firewall.detectedImplementations ?? [];
  if (detected.includes("ufw")) return "ufw";
  if (detected.includes("firewalld")) return "firewalld";
  if (detected.includes("nftables")) return "nftables";
  return null;
}

function administrativePorts(ctx: RemediationContext): number[] {
  const ports = new Set<number>();
  for (const socket of ctx.inventory.sockets.data?.sockets ?? []) {
    if (socket.port !== null && socket.port === 22) ports.add(22);
  }
  return [...ports];
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
  if (kind === "ufw" && ports.length === 0) {
    warnings.push(
      "no SSH listener was observed; ensure the administrative port is allowed before enabling the firewall to avoid lockout",
    );
  }
  const commands =
    kind === "ufw"
      ? [...ports.map((p) => `ufw allow ${p}/tcp`), "ufw --force enable"]
      : [
          "firewall-cmd --permanent --add-service=ssh",
          "firewall-cmd --reload",
          "systemctl enable --now firewalld",
        ];
  return {
    controlId: ctx.control.controlId,
    title: ctx.control.title,
    manual: false,
    manualReason: null,
    currentState: `implementation: ${kind}`,
    desiredState: "host firewall active without closing administrative access",
    steps: [
      kind === "ufw"
        ? "ensure administrative port(s) are allowed, then enable"
        : "allow ssh service in the default zone, reload, ensure firewalld is running",
    ],
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
    schemaVersion: 1,
    verificationId: newVerificationId(),
    serverId: ctx.serverId,
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
  if (kind === "nftables" || kind === null) {
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
  const wasActive = kind === "ufw" ? await ufwActive(ctx) : await firewalldActive(ctx);
  if (kind === "ufw") {
    for (const port of administrativePorts(ctx)) {
      await ctx.runner.run("ufw", ["allow", `${port}/tcp`]);
    }
    await ctx.runner.run("ufw", ["--force", "enable"]);
  } else {
    await ctx.runner.run("firewall-cmd", ["--permanent", "--add-service=ssh"]);
    await ctx.runner.run("firewall-cmd", ["--reload"]);
    await ctx.runner.run("systemctl", ["enable", "--now", "firewalld"]);
  }
  const verification = await verify(ctx);
  return {
    changed: wasActive !== true,
    target: kind,
    before: JSON.stringify({ implementation: kind, active: wasActive }),
    after: JSON.stringify({ implementation: kind, active: true }),
    backupIds: [],
    verification,
    strategy: "disable-firewall-if-not-previously-active",
    reversible: true,
    message: `${kind} enabled; administrative access preserved`,
  };
}

async function rollback(ctx: RemediationContext, change: ChangeRecord): Promise<RemediationApplyResult> {
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
