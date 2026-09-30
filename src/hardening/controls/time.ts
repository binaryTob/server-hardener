/**
 * Time controls: synchronization status.
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

export const timeControls: ControlDefinition[] = [
  {
    id: "TIME-001",
    title: "System time is synchronized",
    category: "time",
    phase: "foundational",
    order: 10,
    platform: ["linux"],
    description: "The host clock should be synchronized by an NTP implementation.",
    rationale:
      "Clock drift breaks log correlation, certificate validation and Kerberos-style authentication, and undermines the reliability of every timestamp used for incident analysis.",
    desiredState: "NTP/vendor time source synchronized",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["time", "foundational"],
    references: ["CIS Controls v8 8.4", "NIST SP 800-53 AU-8"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "low",
      lockoutRisk: "none",
      operationalComplexity: "low",
    },
    applicability: (inv) =>
      sectionGap(inv.time)
        ? {
            status: "unknown",
            rationale: "time state could not be read reliably",
            evidence: [ref("time.status", inv.time.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("time state is available"),
    assess: (inv) => {
      const time = inv.time.data;
      if (!time) return unknownState(null, "no time data in the inventory");
      const evidence = [
        ref("time.data.timezone", time.timezone),
        ref("time.data.ntpSynchronized", String(time.ntpSynchronized)),
        ref(
          "time.data.ntpImplementation",
          `${time.ntpImplementation.value ?? "none"} (${time.ntpImplementation.confidence})`,
        ),
      ];
      if (time.ntpSynchronized === true) {
        return compliant("synchronized", "the system clock is synchronized", evidence);
      }
      if (time.ntpSynchronized === false) {
        return nonCompliant(
          "not synchronized",
          time.ntpImplementation.value === null
            ? "no NTP implementation was detected and the clock is not synchronized"
            : "an NTP implementation is present but the clock is not synchronized",
          evidence,
        );
      }
      return requiresReview(
        "synchronization state unknown",
        "the time synchronization state could not be determined from the inventory",
        evidence,
      );
    },
  },
];
