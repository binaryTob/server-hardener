/**
 * Privileged access controls: visibility over who can become root and how.
 *
 * These controls are about REVIEW, not automatic removal: an administrative
 * account is not a defect, it is a fact that needs to be accounted for.
 */

import {
  applicable,
  compliant,
  nonRootAdmins,
  ref,
  requiresReview,
  sectionGap,
  unknownState,
} from "./helpers";
import type { ControlDefinition } from "./types";

export const privilegedAccessControls: ControlDefinition[] = [
  {
    id: "PA-001",
    title: "Administrative group membership is reviewed",
    category: "privileged-access",
    platform: ["linux"],
    description: "Every non-root account with administrative group membership should be accounted for.",
    rationale:
      "Administrative membership grants de facto root. The framework does not assume these accounts are unnecessary; it requires each to be identified and justified before any privileged-access change is considered.",
    desiredState: "every administrative account is known and justified",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["privileged-access", "review"],
    references: ["CIS Controls v8 5.4", "NIST SP 800-53 AC-6"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "none",
      lockoutRisk: "none",
      operationalComplexity: "low",
    },
    applicability: (inv) =>
      sectionGap(inv.privilegedAccess) || sectionGap(inv.users)
        ? {
            status: "unknown",
            rationale: "privileged access or user inventory is not reliable",
            evidence: [
              ref("privilegedAccess.status", inv.privilegedAccess.status),
              ref("users.status", inv.users.status),
            ],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("administrative groups and users are available"),
    assess: (inv) => {
      const admins = nonRootAdmins(inv);
      const evidence = [
        ref(
          "users.data.users[administrative membership]",
          admins.map((a) => a.user.name).join(", ") || "none",
        ),
      ];
      if (admins.length === 0) {
        return compliant("no non-root administrative accounts", "no such account was observed", evidence);
      }
      return requiresReview(
        `${admins.length} non-root administrative account(s)`,
        "confirm each administrative account is still required; the framework does not treat their presence as a defect",
        evidence,
      );
    },
  },
  {
    id: "PA-002",
    title: "Administrative accounts are not abandoned",
    category: "privileged-access",
    platform: ["linux"],
    description: "Administrative accounts should not be left locked/disabled without review.",
    rationale:
      "Locked administrative accounts often indicate abandoned access that should be removed. Since lock state requires elevated privileges to read, unknown lock state is reported as unknown, never assumed.",
    desiredState: "no locked administrative account",
    requiresApproval: false,
    reversible: true,
    dependencies: ["PA-001"],
    tags: ["privileged-access", "review"],
    references: ["CIS Controls v8 5.3"],
    baseRisk: {
      securityImpact: "low",
      availabilityRisk: "none",
      lockoutRisk: "none",
      operationalComplexity: "low",
    },
    applicability: (inv) =>
      sectionGap(inv.users)
        ? {
            status: "unknown",
            rationale: "the users section is not reliable",
            evidence: [ref("users.status", inv.users.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("account records are available"),
    assess: (inv) => {
      const admins = nonRootAdmins(inv);
      if (admins.length === 0) {
        return compliant("no non-root administrative accounts", "nothing to review", [
          ref("users.data.users[administrative membership]", "none"),
        ]);
      }
      const unknown = admins.filter((a) => a.user.locked.confidence !== "observed");
      if (unknown.length > 0) {
        return unknownState(
          `${unknown.length}/${admins.length} admin lock states unknown`,
          "lock state requires elevated privileges; it cannot be asserted from this inventory",
          [
            ref(
              "users.data.users[locked.confidence=observed]",
              `${admins.length - unknown.length}/${admins.length}`,
            ),
          ],
        );
      }
      const locked = admins.filter((a) => a.user.locked.value === true);
      const evidence = [
        ref("users.data.users[admin, locked=true]", locked.map((a) => a.user.name).join(", ") || "none"),
      ];
      if (locked.length === 0) {
        return compliant(
          "no locked administrative accounts",
          "all administrative accounts are unlocked",
          evidence,
        );
      }
      return requiresReview(
        `${locked.length} locked administrative account(s)`,
        "confirm whether these accounts can be removed",
        evidence,
      );
    },
  },
  {
    id: "PA-003",
    title: "Privilege escalation path is documented",
    category: "privileged-access",
    platform: ["linux"],
    description: "The available privilege escalation mechanism should be known and recorded.",
    rationale:
      "Any change that removes direct root access depends on a working escalation path. This control verifies that the inventory actually records one (sudo plus sudoers presence), not that a specific tool is used.",
    desiredState: "privilege escalation mechanism recorded in the inventory",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["privileged-access", "evidence"],
    references: ["NIST SP 800-53 AC-6"],
    baseRisk: {
      securityImpact: "low",
      availabilityRisk: "low",
      lockoutRisk: "medium",
      operationalComplexity: "low",
    },
    applicability: (inv) =>
      sectionGap(inv.privilegedAccess)
        ? {
            status: "unknown",
            rationale: "privileged access inventory is not reliable",
            evidence: [ref("privilegedAccess.status", inv.privilegedAccess.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("privileged access inventory is available"),
    assess: (inv) => {
      const privileged = inv.privilegedAccess.data;
      const evidence = [
        ref("privilegedAccess.data.sudo.available", String(privileged?.sudo.available ?? null)),
        ref(
          "privilegedAccess.data.sudoersFiles",
          (privileged?.sudoersFiles ?? [])
            .filter((f) => f.exists)
            .map((f) => f.path)
            .join(", ") || "none",
        ),
      ];
      if (privileged?.sudo.available) {
        return compliant("sudo present", "a privilege escalation mechanism was recorded", evidence);
      }
      return requiresReview(
        "no privilege escalation mechanism recorded",
        "confirm how administrators are expected to escalate privileges before removing any direct-root path",
        evidence,
      );
    },
  },
];
