/**
 * Auditing controls: availability of the kernel audit subsystem.
 */

import {
  applicable,
  compliant,
  nonCompliant,
  ref,
  requiresReview,
  sectionGap,
  unknownState,
} from "./helpers";
import type { ControlDefinition } from "./types";

export const auditingControls: ControlDefinition[] = [
  {
    id: "AUD-001",
    title: "Audit subsystem is available",
    category: "auditing",
    phase: "logging-visibility",
    order: 40,
    platform: ["linux"],
    description: "The kernel audit subsystem (auditd) should be installed/available.",
    rationale:
      "Kernel auditing records privileged operations, file access and system calls independently of application logs, and is a foundation for detection and forensics.",
    desiredState: "auditd available",
    requiresApproval: false,
    reversible: true,
    dependencies: ["LOG-001"],
    tags: ["auditing", "visibility"],
    references: ["CIS Controls v8 8.5", "NIST SP 800-92"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "none",
      lockoutRisk: "none",
      operationalComplexity: "medium",
    },
    applicability: (inv) =>
      sectionGap(inv.securityControls)
        ? {
            status: "unknown",
            rationale: "security control state could not be read reliably",
            evidence: [ref("securityControls.status", inv.securityControls.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("audit subsystem state is available"),
    assess: (inv) => {
      const auditd = inv.securityControls.data?.auditd;
      if (!auditd) return unknownState(null, "no audit control data in the inventory");
      const evidence = [
        ref("securityControls.data.auditd.available", String(auditd.available)),
        ref("securityControls.data.auditd.active", String(auditd.active)),
      ];
      if (auditd.available) {
        return compliant("auditd available", "the audit subsystem is available", evidence);
      }
      return nonCompliant("auditd unavailable", "no audit subsystem was detected", evidence);
    },
  },
  {
    id: "AUD-002",
    title: "Audit subsystem is active",
    category: "auditing",
    phase: "logging-visibility",
    order: 50,
    platform: ["linux"],
    description: "If the audit subsystem is present, it should be running.",
    rationale:
      "An installed-but-inactive audit daemon records nothing. Its state should be confirmed before relying on it for detection.",
    desiredState: "auditd active",
    requiresApproval: false,
    reversible: true,
    dependencies: ["AUD-001"],
    tags: ["auditing", "visibility"],
    references: ["CIS Controls v8 8.5"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "none",
      lockoutRisk: "none",
      operationalComplexity: "low",
    },
    applicability: (inv) => {
      const auditd = inv.securityControls.data?.auditd;
      if (sectionGap(inv.securityControls) || auditd === undefined) {
        return {
          status: "unknown",
          rationale: "audit subsystem state could not be read reliably",
          evidence: [ref("securityControls.status", inv.securityControls.status)],
          missingContext: [],
          confidence: "unknown",
        };
      }
      if (!auditd.available) {
        return {
          status: "not-applicable",
          rationale: "no audit subsystem is installed",
          evidence: [ref("securityControls.data.auditd.available", "false")],
          missingContext: [],
          confidence: "observed",
        };
      }
      return applicable("the audit subsystem is installed", [
        ref("securityControls.data.auditd.available", "true"),
      ]);
    },
    assess: (inv) => {
      const auditd = inv.securityControls.data?.auditd;
      const evidence = [ref("securityControls.data.auditd.active", String(auditd?.active ?? null))];
      if (auditd?.active === true) {
        return compliant("auditd active", "the audit subsystem is running", evidence);
      }
      return requiresReview(
        "auditd inactive",
        "the audit subsystem is installed but not active; confirm this is intentional",
        evidence,
      );
    },
  },
];
