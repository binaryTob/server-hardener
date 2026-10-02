/**
 * SSH controls.
 *
 * None of these redefine SSH security: they encode widely accepted guidance
 * (public OpenSSH documentation, NIST SP 800-123, CIS Controls v8 mappings)
 * as evidence-based checks.
 *
 * IMPORTANT: Phase 1 discovery does not collect sshd_config values. Controls
 * that need those values report `unknown` (evidence gap) rather than inventing
 * a state. Controls whose decision depends on how the host is administered
 * additionally demand operational context and surface as `requires-context`.
 */
import type { ApplicabilityDecision, OperationalContext, RiskLevel, ServerInventory } from "../models";
import {
  alternativeAdminUserPrecondition,
  applicable,
  compliant,
  consoleAccessPrecondition,
  managementPorts,
  missingEvidence,
  nonCompliant,
  notApplicable,
  privilegeEscalationPrecondition,
  ref,
  requiresContext,
  secondaryManagementPathPrecondition,
  unknownApplicability,
  unknownState,
} from "./helpers";
import type { ControlDefinition, ControlStateAssessment } from "./types";

function sshApplicability(inv: ServerInventory): ApplicabilityDecision {
  const section = inv.securityControls;
  const ssh = section.data?.sshServer ?? null;
  if (ssh === null) {
    return unknownApplicability("the SSH server state could not be read from the inventory", [
      ref("securityControls.status", section.status),
    ]);
  }
  if (!ssh.available) {
    return notApplicable("no SSH server was detected on this host", [
      ref("securityControls.data.sshServer.available", "false"),
    ]);
  }
  return applicable("an SSH server is present on this host", [
    ref("securityControls.data.sshServer.available", "true"),
    ref("securityControls.data.sshServer.active", String(ssh.active)),
  ]);
}

function lockoutFromManagement(ctx: OperationalContext, fallback: RiskLevel): RiskLevel {
  const secondary = ctx.management.secondaryPathConfirmed;
  const console = ctx.management.consoleAccess;
  if (secondary === true || console === true) return "low";
  if (secondary === false && console === false) return "critical";
  if (secondary === false || console === false) return "high";
  return fallback;
}

function notObservable(what: string, path: string): ControlStateAssessment {
  return unknownState(
    null,
    `${what} is not part of the current inventory: Phase 1 discovery does not read sshd_config, so the effective value cannot be asserted`,
    [missingEvidence(path, "not collected by current discovery")],
  );
}

export const sshControls: ControlDefinition[] = [
  {
    id: "SSH-001",
    title: "Disable SSH root login",
    category: "ssh",
    platform: ["linux"],
    description: "Direct root login over SSH should be disabled in favour of named administrative accounts.",
    rationale:
      "Direct root login removes individual accountability, prevents per-operator audit, and enlarges the blast radius of a brute-force or credential-stuffing attack. Administrative work should use named accounts plus privilege escalation.",
    desiredState: "PermitRootLogin no",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["ssh", "privileged-access", "high-impact"],
    references: ["OpenSSH sshd_config(5) PermitRootLogin", "NIST SP 800-123 4.4", "CIS Controls v8 5.4"],
    baseRisk: {
      securityImpact: "high",
      availabilityRisk: "medium",
      lockoutRisk: "high",
      operationalComplexity: "low",
    },
    applicability: (inv) => sshApplicability(inv),
    assess: () =>
      notObservable("PermitRootLogin", "securityControls.data.sshServer (sshd_config not collected)"),
    adjustRisk: (_inv, ctx) => ({
      lockoutRisk: lockoutFromManagement(ctx, "unknown"),
      availabilityRisk: ctx.management.secondaryPathConfirmed === true ? "low" : "medium",
    }),
    preconditions: () => [
      alternativeAdminUserPrecondition(),
      privilegeEscalationPrecondition(),
      secondaryManagementPathPrecondition(),
    ],
  },
  {
    id: "SSH-002",
    title: "Disable SSH password authentication",
    category: "ssh",
    platform: ["linux"],
    description:
      "Interactive password authentication over SSH should be disabled when a verified alternative exists.",
    rationale:
      "Password authentication is exposed to brute force, credential stuffing and password reuse. Key-based (or certificate-based) authentication is materially stronger. This is NOT a finding when the alternative management path has not been confirmed: without it, disabling password auth can lock administrators out.",
    desiredState: "PasswordAuthentication no",
    requiresApproval: true,
    reversible: true,
    dependencies: ["SSH-001"],
    tags: ["ssh", "authentication", "lockout-risk"],
    references: ["OpenSSH sshd_config(5) PasswordAuthentication", "NIST SP 800-63B", "CIS Controls v8 4.7"],
    baseRisk: {
      securityImpact: "high",
      availabilityRisk: "medium",
      lockoutRisk: "high",
      operationalComplexity: "low",
    },
    applicability: (inv) => sshApplicability(inv),
    assess: (_inv, ctx) => {
      const state = notObservable(
        "PasswordAuthentication",
        "securityControls.data.sshServer (sshd_config not collected)",
      );
      return requiresContext(
        state.currentState,
        "whether password authentication can be disabled depends entirely on how administrators reach this host; the inventory cannot answer that",
        requiredManagementContext(ctx),
        state.evidence,
      );
    },
    adjustRisk: (_inv, ctx) => ({
      lockoutRisk: lockoutFromManagement(ctx, "unknown"),
      availabilityRisk: ctx.management.secondaryPathConfirmed === true ? "low" : "high",
    }),
    preconditions: () => [
      alternativeAdminUserPrecondition(),
      privilegeEscalationPrecondition(),
      secondaryManagementPathPrecondition(),
      consoleAccessPrecondition(),
    ],
  },
  {
    id: "SSH-003",
    title: "Disable SSH empty passwords",
    category: "ssh",
    platform: ["linux"],
    description: "SSH must never accept accounts with empty password fields.",
    rationale:
      "Permitting empty passwords allows passwordless authentication for any account whose password field is empty. Disabling it cannot lock out a correctly configured host (no valid account should have an empty password).",
    desiredState: "PermitEmptyPasswords no",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["ssh", "authentication"],
    references: ["OpenSSH sshd_config(5) PermitEmptyPasswords", "CIS Controls v8 4.7"],
    baseRisk: {
      securityImpact: "high",
      availabilityRisk: "none",
      lockoutRisk: "none",
      operationalComplexity: "low",
    },
    applicability: (inv) => sshApplicability(inv),
    assess: () =>
      notObservable("PermitEmptyPasswords", "securityControls.data.sshServer (sshd_config not collected)"),
  },
  {
    id: "SSH-004",
    title: "Disable SSH X11 forwarding",
    category: "ssh",
    platform: ["linux"],
    description: "X11 forwarding should be disabled unless explicitly required.",
    rationale:
      "X11 forwarding enlarges the attack surface and can be abused to bypass access controls on the graphical layer. Servers rarely need it.",
    desiredState: "X11Forwarding no",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["ssh", "attack-surface"],
    references: ["OpenSSH sshd_config(5) X11Forwarding"],
    baseRisk: {
      securityImpact: "low",
      availabilityRisk: "low",
      lockoutRisk: "none",
      operationalComplexity: "low",
    },
    applicability: (inv) => sshApplicability(inv),
    assess: () =>
      notObservable("X11Forwarding", "securityControls.data.sshServer (sshd_config not collected)"),
  },
  {
    id: "SSH-005",
    title: "Limit SSH authentication attempts",
    category: "ssh",
    platform: ["linux"],
    description: "MaxAuthTries should be bounded to slow down credential guessing.",
    rationale:
      "Bounding authentication attempts per connection raises the cost of online brute force and reduces log noise. It does not affect legitimate interactive use.",
    desiredState: "MaxAuthTries<=4",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["ssh", "brute-force"],
    references: ["OpenSSH sshd_config(5) MaxAuthTries"],
    baseRisk: {
      securityImpact: "low",
      availabilityRisk: "none",
      lockoutRisk: "none",
      operationalComplexity: "low",
    },
    applicability: (inv) => sshApplicability(inv),
    assess: () =>
      notObservable("MaxAuthTries", "securityControls.data.sshServer (sshd_config not collected)"),
  },
  {
    id: "SSH-006",
    title: "Restrict SSH access to management networks",
    category: "ssh",
    platform: ["linux"],
    description: "SSH should be reachable only from declared administrative networks.",
    rationale:
      "SSH is the primary administrative channel; exposing it to the whole Internet (or to service networks) increases brute-force and exploitation exposure. Restriction is only safe once the authorised management networks are known.",
    desiredState: "SSH bound/filtered to declared administrative networks",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["ssh", "network", "exposure"],
    references: ["CIS Controls v8 4.4", "NIST SP 800-123 4.4"],
    baseRisk: {
      securityImpact: "high",
      availabilityRisk: "medium",
      lockoutRisk: "high",
      operationalComplexity: "medium",
    },
    applicability: (inv) => sshApplicability(inv),
    assess: (inv, ctx) => {
      const adminPorts = new Set(managementPorts(inv, ctx));
      const sshSockets = (inv.sockets.data?.sockets ?? []).filter(
        (s) => s.port !== null && adminPorts.has(s.port),
      );
      const wildcard = sshSockets.filter((s) => s.scope === "wildcard");
      const scopeText =
        sshSockets.length === 0
          ? "no SSH listener observed in the inventory"
          : `listeners: ${sshSockets.map((s) => `${s.address ?? "?"}:${s.port} (${s.scope})`).join(", ")}`;
      if (ctx.networks.administrative.length === 0) {
        return requiresContext(
          scopeText,
          "the declared administrative networks are required to decide whether the current SSH exposure is acceptable",
          ["networks.administrative", "internetExposure"],
          [ref("sockets.data.sockets[sshd]", `${sshSockets.length} listeners, ${wildcard.length} wildcard`)],
        );
      }
      if (wildcard.length > 0) {
        return {
          status: "non-compliant",
          currentState: scopeText,
          evidence: [ref("sockets.data.sockets[sshd]", `${wildcard.length} wildcard listeners`)],
          missingContext: [],
          rationale: "SSH listens on a wildcard address while administrative networks are declared",
        };
      }
      return {
        status: "compliant",
        currentState: scopeText,
        evidence: [ref("sockets.data.sockets[sshd]", "no wildcard listeners")],
        missingContext: [],
        rationale: "SSH does not listen on a wildcard address",
      };
    },
    preconditions: () => [secondaryManagementPathPrecondition(), consoleAccessPrecondition()],
  },
  {
    id: "SSH-007",
    title: "Only administrative SSH ports are exposed",
    category: "ssh",
    platform: ["linux"],
    description: "sshd should listen only on the authorized administrative port(s).",
    rationale:
      "Every additional sshd listening port is extra Internet-facing attack surface (port 22 in particular is scanned constantly). Removing ports the operator does not use reduces exposure without affecting the authorized management port.",
    desiredState: "sshd listens only on the authorized administrative port(s)",
    requiresApproval: true,
    reversible: true,
    dependencies: ["SSH-002"],
    tags: ["ssh", "exposure"],
    references: ["OpenSSH sshd_config(5) Port", "CIS Controls v8 4.4"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "none",
      lockoutRisk: "low",
      operationalComplexity: "low",
    },
    applicability: (inv) => sshApplicability(inv),
    assess: (inv, ctx) => {
      const observed = (inv.sockets.data?.sockets ?? [])
        .filter((s) => s.port !== null && s.processName !== null && /ssh/i.test(s.processName))
        .map((s) => s.port as number);
      const authorized = ctx.management.sshPort ?? null;
      const evidence = [
        ref("sockets.data.sockets[sshd]", observed.join(", ") || "none"),
        ref("context.management.sshPort", authorized === null ? null : String(authorized)),
      ];
      if (authorized === null) {
        return requiresContext(
          `sshd listening on: ${observed.join(", ") || "(none)"}`,
          "the authorized administrative SSH port(s) are needed to identify extra ports",
          ["management.sshPort"],
          evidence,
        );
      }
      const extra = observed.filter((port) => port !== authorized);
      if (extra.length > 0) {
        return nonCompliant(
          `ports: ${observed.join(", ")} (authorized: ${authorized})`,
          `sshd listens on ${extra.join(", ")}, which is not the authorized port`,
          evidence,
        );
      }
      return compliant(
        `ports: ${observed.join(", ")}`,
        "sshd exposes only the authorized administrative port",
        evidence,
      );
    },
  },
];

function requiredManagementContext(ctx: OperationalContext): string[] {
  const missing: string[] = [];
  if (ctx.management.secondaryPathConfirmed === null) missing.push("management.secondaryPathConfirmed");
  if (ctx.management.consoleAccess === null) missing.push("management.consoleAccess");
  if (ctx.management.methods.length === 0) missing.push("management.methods");
  return missing;
}
