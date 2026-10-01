/**
 * Logging controls: visibility and persistence.
 *
 * Persistent-storage configuration (Storage= in journald) is not part of the
 * current inventory, so that specific control is `unknown` rather than assumed.
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

export const loggingControls: ControlDefinition[] = [
  {
    id: "LOG-001",
    title: "System logging is active",
    category: "logging",
    platform: ["linux"],
    description: "At least one system logging service (journald or rsyslog) should be active.",
    rationale:
      "Without active logging, security events are lost and post-incident analysis is impossible. Logging is a prerequisite for nearly every other control.",
    desiredState: "journald or rsyslog active",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["logging", "visibility"],
    references: ["CIS Controls v8 8.2", "NIST SP 800-92"],
    baseRisk: {
      securityImpact: "high",
      availabilityRisk: "none",
      lockoutRisk: "none",
      operationalComplexity: "low",
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
        : applicable("logging service state is available"),
    assess: (inv) => {
      const controls = inv.securityControls.data;
      if (!controls) return unknownState(null, "no security control data in the inventory");
      const journald = controls.journald;
      const rsyslog = controls.rsyslog;
      const evidence = [
        ref("securityControls.data.journald.active", String(journald.active)),
        ref("securityControls.data.journald.available", String(journald.available)),
        ref("securityControls.data.rsyslog.active", String(rsyslog.active)),
        ref("securityControls.data.rsyslog.available", String(rsyslog.available)),
      ];
      if (journald.active === true || rsyslog.active === true) {
        const active = [
          journald.active === true ? "journald" : null,
          rsyslog.active === true ? "rsyslog" : null,
        ]
          .filter((x): x is string => x !== null)
          .join(", ");
        return compliant(`active: ${active}`, "at least one system logging service is active", evidence);
      }
      if (journald.active === false && rsyslog.active === false && rsyslog.available) {
        return nonCompliant("no logging service active", "journald and rsyslog are both inactive", evidence);
      }
      return unknownState(
        "logging service state unavailable",
        "no active logging service could be confirmed",
        evidence,
      );
    },
  },
  {
    id: "LOG-002",
    title: "System logging is persistent across reboot",
    category: "logging",
    platform: ["linux"],
    description: "Logs should survive a reboot (persistent journald storage or a log service).",
    rationale: "Volatile-only logs are lost on reboot, which is exactly when incident timelines matter most.",
    desiredState: "persistent logging storage configured",
    requiresApproval: false,
    reversible: true,
    dependencies: ["LOG-001"],
    tags: ["logging", "evidence"],
    references: ["CIS Controls v8 8.2", "NIST SP 800-92"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "none",
      lockoutRisk: "none",
      operationalComplexity: "low",
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
        : applicable("logging service state is available"),
    assess: (inv) => {
      const controls = inv.securityControls.data;
      // rsyslog writing to disk implies persistence; a loaded rsyslog is a proxy.
      if (controls?.rsyslog.active === true) {
        return compliant(
          "rsyslog active (writes to disk)",
          "an active rsyslog strongly implies persistent on-disk logs, but storage configuration was not read",
          [ref("securityControls.data.rsyslog.active", "true")],
        );
      }
      return unknownState(
        "persistence configuration unknown",
        "journald Storage= configuration is not collected by current discovery",
        [
          {
            inventoryPath: "securityControls.data.journald (Storage= not collected)",
            observed: null,
            note: "journald persistence cannot be asserted without reading journald.conf",
          },
        ],
      );
    },
  },
  {
    id: "LOG-003",
    title: "Security monitoring capability is present",
    category: "logging",
    platform: ["linux"],
    description: "A security monitoring/endpoint agent should be detectable where one is deployed.",
    rationale:
      "Centralised detection improves response to compromise. Absence of a detectable agent is not proof that monitoring is missing (it may be network-based), so this is a review item, not a defect.",
    desiredState: "security monitoring/endpoint agent present",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["logging", "monitoring", "review"],
    references: ["CIS Controls v8 8.11", "NIST SP 800-92"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "none",
      lockoutRisk: "none",
      operationalComplexity: "low",
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
        : applicable("endpoint protection inventory is available"),
    assess: (inv) => {
      const capabilities = inv.securityControls.data?.endpointProtection ?? [];
      const evidence = [
        ref(
          "securityControls.data.endpointProtection",
          capabilities.map((c) => `${c.name}(${c.status ?? "?"})`).join(", ") || "none",
        ),
      ];
      if (capabilities.length > 0) {
        return compliant(
          `${capabilities.length} capability(ies) present`,
          "at least one security monitoring/endpoint capability was detected",
          evidence,
        );
      }
      return requiresReview(
        "no endpoint/monitoring agent detected",
        "confirm whether monitoring is provided centrally; absence of a local agent is not proof of no monitoring",
        evidence,
      );
    },
  },
];
