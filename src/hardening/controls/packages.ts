/**
 * Package controls.
 *
 * Only properties determinable locally are asserted. End-of-life/support
 * status needs repository/vendor data, which this phase deliberately does not
 * fetch, so those controls are `unknown` rather than guessed.
 */

import {
  applicable,
  compliant,
  missingEvidence,
  nonCompliant,
  packages,
  ref,
  requiresReview,
  sectionGap,
  unknownState,
} from "./helpers";
import type { ControlDefinition } from "./types";

export const packageControls: ControlDefinition[] = [
  {
    id: "PKG-001",
    title: "A package manager is available",
    category: "packages",
    phase: "foundational",
    order: 20,
    platform: ["linux"],
    description: "The host should have a working package manager (dpkg or rpm).",
    rationale:
      "Without a package manager, security updates cannot be tracked or applied and installed software becomes unauditable.",
    desiredState: "dpkg or rpm detected",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["packages", "foundational"],
    references: ["CIS Controls v8 7.1"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "none",
      lockoutRisk: "none",
      operationalComplexity: "low",
    },
    applicability: (inv) =>
      sectionGap(inv.packages)
        ? {
            status: "unknown",
            rationale: "the packages section is not reliable",
            evidence: [ref("packages.status", inv.packages.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("package inventory is available"),
    assess: (inv) => {
      const managers = inv.packages.data?.managersDetected ?? [];
      const evidence = [ref("packages.data.managersDetected", managers.join(", ") || "none")];
      if (managers.length > 0) {
        return compliant(`managers: ${managers.join(", ")}`, "a package manager was detected", evidence);
      }
      return nonCompliant("no package manager detected", "neither dpkg nor rpm was detected", evidence);
    },
  },
  {
    id: "PKG-002",
    title: "Installed packages are reviewed",
    category: "packages",
    phase: "services",
    order: 30,
    platform: ["linux"],
    description: "Installed software should be reconciled with the host's role.",
    rationale:
      "Every installed package is attack surface and update burden. The framework cannot know which packages are required, so this is a review item, never an automatic removal suggestion.",
    desiredState: "installed packages justified by the host role",
    requiresApproval: false,
    reversible: false,
    dependencies: [],
    tags: ["packages", "review"],
    references: ["CIS Controls v8 2.1"],
    baseRisk: {
      securityImpact: "low",
      availabilityRisk: "medium",
      lockoutRisk: "none",
      operationalComplexity: "high",
    },
    applicability: (inv) =>
      sectionGap(inv.packages)
        ? {
            status: "unknown",
            rationale: "the packages section is not reliable",
            evidence: [ref("packages.status", inv.packages.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("package inventory is available"),
    assess: (inv) => {
      const count = packages(inv).length;
      return requiresReview(
        `${count} packages installed`,
        "review installed packages against the host's role; no package is assumed unnecessary",
        [ref("packages.data.packages", `${count} entries`)],
      );
    },
  },
  {
    id: "PKG-003",
    title: "No end-of-life or unsupported packages",
    category: "packages",
    phase: "services",
    order: 40,
    platform: ["linux"],
    description: "Installed packages should be within their supported lifecycle.",
    rationale:
      "Unsupported packages no longer receive security fixes. Determining lifecycle status requires vendor/repository metadata, which this phase intentionally does not fetch, so the control is unknown until that evidence exists.",
    desiredState: "all packages supported by their vendor",
    requiresApproval: false,
    reversible: true,
    dependencies: ["PKG-001"],
    tags: ["packages", "lifecycle", "evidence"],
    references: ["CIS Controls v8 7.1"],
    baseRisk: {
      securityImpact: "high",
      availabilityRisk: "medium",
      lockoutRisk: "low",
      operationalComplexity: "medium",
    },
    applicability: (inv) =>
      sectionGap(inv.packages)
        ? {
            status: "unknown",
            rationale: "the packages section is not reliable",
            evidence: [ref("packages.status", inv.packages.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("package inventory is available"),
    assess: () =>
      unknownState(
        null,
        "lifecycle/support status cannot be determined without repository or vendor metadata, which Phase 2 does not fetch",
        [missingEvidence("packages.data.packages[lifecycle]", "no support-status evidence collected")],
      ),
  },
];
