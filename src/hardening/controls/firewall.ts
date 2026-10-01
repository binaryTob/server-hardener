/**
 * Firewall controls.
 *
 * The inventory can observe that a host firewall implementation exists and is
 * active, but absence of a host firewall is not proof of exposure (a network
 * firewall may compensate) — the difference is expressed with context.
 */

import {
  applicable,
  compliant,
  nonCompliant,
  ref,
  requiresContext,
  sectionGap,
  unknownState,
} from "./helpers";
import type { ControlDefinition } from "./types";

export const firewallControls: ControlDefinition[] = [
  {
    id: "FW-001",
    title: "Host firewall is active",
    category: "firewall",
    platform: ["linux"],
    description: "An enabled host firewall should be actively filtering traffic.",
    rationale:
      "A host firewall is a defence-in-depth control that limits exposure from misconfigured services and lateral movement. An implementation that is installed but inactive provides no protection.",
    desiredState: "host firewall implementation active",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["firewall", "network"],
    references: ["CIS Controls v8 4.5", "NIST SP 800-41"],
    baseRisk: {
      securityImpact: "high",
      availabilityRisk: "medium",
      lockoutRisk: "medium",
      operationalComplexity: "medium",
    },
    applicability: (inv) => {
      const firewall = inv.securityControls.data?.firewall ?? null;
      if (sectionGap(inv.securityControls) || firewall === null) {
        return {
          status: "unknown",
          rationale: "firewall state could not be read from the inventory",
          evidence: [ref("securityControls.status", inv.securityControls.status)],
          missingContext: [],
          confidence: "unknown",
        };
      }
      return applicable("firewall state is available in the inventory", [
        ref(
          "securityControls.data.firewall.detectedImplementations",
          firewall.detectedImplementations.join(", ") || "none",
        ),
      ]);
    },
    assess: (inv) => {
      const firewall = inv.securityControls.data?.firewall;
      if (!firewall) {
        return unknownState(null, "no firewall data in the inventory");
      }
      const evidence = [
        ref("securityControls.data.firewall.implementation", firewall.implementation.value),
        ref("securityControls.data.firewall.active", String(firewall.active)),
        ref("securityControls.data.firewall.enabled", String(firewall.enabled)),
        ref(
          "securityControls.data.firewall.detectedImplementations",
          firewall.detectedImplementations.join(", ") || "none",
        ),
      ];
      if (firewall.active === true) {
        return compliant(
          `firewall active (${firewall.implementation.value ?? "unknown"})`,
          "the host firewall is active",
          evidence,
        );
      }
      if (firewall.active === false) {
        return nonCompliant(
          `firewall inactive (${firewall.implementation.value ?? "implementation detected"})`,
          "a host firewall implementation is present but not active",
          evidence,
        );
      }
      return unknownState(
        firewall.implementation.value
          ? `implementation present (${firewall.implementation.value}), active state unknown`
          : "no firewall detected",
        "the active state of the host firewall could not be determined",
        evidence,
      );
    },
    preconditions: () => [],
  },
  {
    id: "FW-002",
    title: "Host firewall implementation is present",
    category: "firewall",
    platform: ["linux"],
    description: "Some host firewall implementation should be available on the server.",
    rationale:
      "If no host firewall is present, exposure must be compensated at the network layer. Whether that compensation exists is an operational fact, so its absence is a context-requiring review, not an automatic defect.",
    desiredState: "a host firewall implementation is present",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["firewall", "network"],
    references: ["CIS Controls v8 4.5"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "low",
      lockoutRisk: "low",
      operationalComplexity: "medium",
    },
    applicability: (inv) =>
      sectionGap(inv.securityControls)
        ? {
            status: "unknown",
            rationale: "security controls could not be read reliably",
            evidence: [ref("securityControls.status", inv.securityControls.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("security control state is available"),
    assess: (inv, ctx) => {
      const firewall = inv.securityControls.data?.firewall;
      if (!firewall) return unknownState(null, "no firewall data in the inventory");
      const implementations = firewall.detectedImplementations;
      const evidence = [
        ref("securityControls.data.firewall.detectedImplementations", implementations.join(", ") || "none"),
        ref("context.networks.service", ctx.networks.service.join(", ") || "not declared"),
      ];
      if (implementations.length > 0) {
        return compliant(
          `implementations: ${implementations.join(", ")}`,
          "at least one host firewall implementation was detected",
          evidence,
        );
      }
      return requiresContext(
        "no host firewall implementation detected",
        "network-layer filtering may compensate; declare it before treating this as a defect",
        ["internetExposure", "networks.service"],
        evidence,
      );
    },
  },
  {
    id: "FW-003",
    title: "Management interfaces are restricted to management networks",
    category: "firewall",
    platform: ["linux"],
    description: "Administrative services should be reachable only from authorised networks.",
    rationale:
      "Administrative interfaces (SSH, web consoles, APIs) reachable from wildcard addresses are exposed to every network path the host has. Restricting them is only safe once the authorised management networks are declared.",
    desiredState: "management services reachable only from declared management networks",
    requiresApproval: true,
    reversible: true,
    dependencies: ["SSH-006"],
    tags: ["firewall", "network", "exposure"],
    references: ["CIS Controls v8 4.4", "NIST SP 800-207"],
    baseRisk: {
      securityImpact: "high",
      availabilityRisk: "medium",
      lockoutRisk: "high",
      operationalComplexity: "medium",
    },
    applicability: (inv) =>
      sectionGap(inv.sockets)
        ? {
            status: "unknown",
            rationale: "the listening-socket inventory is not reliable",
            evidence: [ref("sockets.status", inv.sockets.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("listening sockets are available in the inventory"),
    assess: (inv, ctx) => {
      const knownAdminPorts = new Set([22, 6443, 10250, 2376]);
      const adminSockets = (inv.sockets.data?.sockets ?? []).filter(
        (s) => s.port !== null && knownAdminPorts.has(s.port),
      );
      const wildcard = adminSockets.filter((s) => s.scope === "wildcard");
      const evidence = [
        ref(
          "sockets.data.sockets[admin ports]",
          adminSockets.map((s) => `${s.port}(${s.scope})`).join(", ") || "none observed",
        ),
        ref("context.networks.administrative", ctx.networks.administrative.join(", ") || "not declared"),
      ];
      if (ctx.networks.administrative.length === 0) {
        return requiresContext(
          `${wildcard.length} wildcard administrative listener(s)`,
          "declared management networks are required to judge whether this exposure is acceptable",
          ["networks.administrative", "internetExposure"],
          evidence,
        );
      }
      if (wildcard.length > 0) {
        return nonCompliant(
          `${wildcard.length} administrative listener(s) on wildcard addresses`,
          "administrative ports listen on wildcard addresses while management networks are declared",
          evidence,
        );
      }
      return compliant(
        "no wildcard administrative listeners",
        "administrative ports are not on wildcard addresses",
        evidence,
      );
    },
    preconditions: () => [],
  },
];
