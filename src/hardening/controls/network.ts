/**
 * Network exposure controls.
 *
 * Listening on a wildcard address is evidence, not a verdict: many services
 * legitimately listen on all interfaces. These controls separate "please
 * confirm this is intended" from genuinely insecure protocols.
 */

import { applicable, compliant, nonCompliant, ref, requiresReview, sectionGap, sockets } from "./helpers";
import type { ControlDefinition } from "./types";

/** Ports whose protocols are plaintext/obsolete by design. */
const INSECURE_PLAINTEXT_PORTS = new Map<number, string>([
  [21, "FTP"],
  [23, "Telnet"],
  [69, "TFTP"],
  [512, "rexec"],
  [513, "rlogin"],
  [514, "rsh/syslog"],
]);

export const networkControls: ControlDefinition[] = [
  {
    id: "NET-001",
    title: "Wildcard listeners are intentionally exposed",
    category: "network",
    platform: ["linux"],
    description: "Services listening on all interfaces should be intentional.",
    rationale:
      "A wildcard listener is reachable from every network the host can see. This is frequently correct, so the framework flags it for review rather than as a defect.",
    desiredState: "wildcard listeners reviewed and justified",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["network", "review", "exposure"],
    references: ["NIST SP 800-53 SC-7"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "none",
      lockoutRisk: "none",
      operationalComplexity: "low",
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
        : applicable("listening sockets are available"),
    assess: (inv, ctx) => {
      const wildcard = sockets(inv).filter((s) => s.scope === "wildcard");
      const evidence = [
        ref(
          "sockets.data.sockets[scope=wildcard]",
          wildcard.map((s) => `${s.port}/${s.protocol}(${s.processName ?? "?"})`).join(", ") || "none",
        ),
      ];
      if (wildcard.length === 0) {
        return compliant("no wildcard listeners", "no service listens on a wildcard address", evidence);
      }
      if (ctx.internetExposure === "none") {
        return compliant(
          `${wildcard.length} wildcard listeners (host not Internet-exposed)`,
          "wildcard listeners exist but the operator reports no Internet exposure",
          evidence,
        );
      }
      return requiresReview(
        `${wildcard.length} wildcard listener(s)`,
        "confirm each wildcard listener is intended for the host's exposure level",
        evidence,
      );
    },
  },
  {
    id: "NET-002",
    title: "No plaintext management protocols listening",
    category: "network",
    platform: ["linux"],
    description: "Ports associated with plaintext protocols should not be listening.",
    rationale:
      "FTP, Telnet, TFTP, rlogin/rsh and rexec transmit credentials and data in cleartext. Their listening presence is a defect regardless of context.",
    desiredState: "no listener on plaintext/obsolete protocol ports",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["network", "insecure-protocol"],
    references: ["NIST SP 800-53 SC-8", "CIS Controls v8 4.8"],
    baseRisk: {
      securityImpact: "high",
      availabilityRisk: "low",
      lockoutRisk: "none",
      operationalComplexity: "low",
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
        : applicable("listening sockets are available"),
    assess: (inv) => {
      const offenders = sockets(inv).filter((s) => s.port !== null && INSECURE_PLAINTEXT_PORTS.has(s.port));
      const evidence = [
        ref(
          "sockets.data.sockets[plaintext ports]",
          offenders
            .map((s) => `${s.port}/${INSECURE_PLAINTEXT_PORTS.get(s.port ?? -1)}(${s.scope})`)
            .join(", ") || "none",
        ),
      ];
      if (offenders.length === 0) {
        return compliant(
          "no plaintext protocol listeners",
          "no insecure protocol port is listening",
          evidence,
        );
      }
      return nonCompliant(
        `${offenders.length} plaintext protocol listener(s)`,
        "listeners on plaintext/obsolete protocol ports were observed",
        evidence,
      );
    },
  },
];
