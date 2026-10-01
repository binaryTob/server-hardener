/**
 * Service controls.
 *
 * A service is never called unnecessary merely because it is unrecognised.
 * The catalog only asserts defects for services that are known-insecure by
 * protocol design; everything else is a review item.
 */

import {
  applicable,
  compliant,
  nonCompliant,
  ref,
  requiresContext,
  requiresReview,
  sectionGap,
  services,
} from "./helpers";
import type { ControlDefinition } from "./types";

/** Service name fragments that indicate a plaintext/insecure protocol. */
const INSECURE_SERVICE_FRAGMENTS = [
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

export const serviceControls: ControlDefinition[] = [
  {
    id: "SVC-001",
    title: "No known-insecure network services enabled",
    category: "services",
    platform: ["linux"],
    description: "Services implementing plaintext or obsolete protocols should not be enabled.",
    rationale:
      "Telnet, rlogin/rsh, FTP and TFTP transmit credentials and data in cleartext and have well-known weaknesses. This is asserted only for services whose protocol is insecure by design, never for unrecognised services.",
    desiredState: "no enabled/active service providing a known-insecure protocol",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["services", "insecure-protocol"],
    references: ["NIST SP 800-53 CM-7", "CIS Controls v8 4.8"],
    baseRisk: {
      securityImpact: "high",
      availabilityRisk: "low",
      lockoutRisk: "none",
      operationalComplexity: "low",
    },
    applicability: (inv) =>
      sectionGap(inv.services)
        ? {
            status: "unknown",
            rationale: "the services section is not reliable",
            evidence: [ref("services.status", inv.services.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("the service list is available"),
    assess: (inv) => {
      const offenders = services(inv).filter((s) => {
        const enabledOrActive = s.enabled === true || s.active === true;
        if (!enabledOrActive) return false;
        const name = s.name.toLowerCase();
        return INSECURE_SERVICE_FRAGMENTS.some((fragment) => name.includes(fragment));
      });
      const evidence = [
        ref(
          "services.data.services[insecure protocol]",
          offenders.map((s) => `${s.name}(enabled=${s.enabled},active=${s.active})`).join(", ") || "none",
        ),
      ];
      if (offenders.length === 0) {
        return compliant(
          "no known-insecure service enabled",
          "no service matching a known-insecure protocol was enabled or active",
          evidence,
        );
      }
      return nonCompliant(
        `${offenders.length} known-insecure service(s) enabled`,
        "these services use protocols that are insecure by design",
        evidence,
      );
    },
  },
  {
    id: "SVC-002",
    title: "Enabled services are reviewed against host role",
    category: "services",
    platform: ["linux"],
    description: "The set of enabled services should be reconciled with the server's declared role.",
    rationale:
      "Any enabled service is an attack-surface decision. The framework cannot know which services are required, so this is a review item that becomes actionable once the host role is confirmed — it is never an automatic removal recommendation.",
    desiredState: "enabled services justified by the confirmed role",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["services", "review"],
    references: ["NIST SP 800-53 CM-7"],
    baseRisk: {
      securityImpact: "low",
      availabilityRisk: "medium",
      lockoutRisk: "low",
      operationalComplexity: "high",
    },
    applicability: (inv) =>
      sectionGap(inv.services)
        ? {
            status: "unknown",
            rationale: "the services section is not reliable",
            evidence: [ref("services.status", inv.services.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("the service list is available"),
    assess: (inv, ctx) => {
      const enabled = services(inv).filter((s) => s.enabled === true);
      const evidence = [ref("services.data.services[enabled=true]", `${enabled.length} enabled services`)];
      if (ctx.roles.filter((r) => r.confidence === "confirmed").length === 0) {
        return requiresContext(
          `${enabled.length} enabled services`,
          "no confirmed server role is available to judge which services are required",
          ["roles"],
          evidence,
        );
      }
      return requiresReview(
        `${enabled.length} enabled services`,
        "confirm each enabled service is justified by the host's role; the framework does not recommend disabling unrecognised services",
        evidence,
      );
    },
  },
];
