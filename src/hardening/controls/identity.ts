/**
 * Identity controls: local account hygiene visible from the inventory.
 *
 * Account lock state is only known when /etc/shadow was readable; wherever it
 * is unknown the control says so instead of assuming.
 */

import {
  applicable,
  compliant,
  isInteractiveShell,
  nonCompliant,
  ref,
  requiresReview,
  sectionGap,
  uidZeroUsers,
  unknownState,
  users,
} from "./helpers";
import type { ControlDefinition } from "./types";

export const identityControls: ControlDefinition[] = [
  {
    id: "ID-001",
    title: "Only one account may have UID 0",
    category: "identity",
    phase: "prerequisites",
    order: 10,
    platform: ["linux"],
    description: "Exactly one account (root) should have UID 0.",
    rationale:
      "Additional UID 0 accounts are equivalent to root but bypass the accountability of the root account, and are a classic persistence mechanism.",
    desiredState: "exactly one account with UID 0",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["identity", "privileged-access", "critical"],
    references: ["CIS Controls v8 5.4", "NIST SP 800-53 AC-6"],
    baseRisk: {
      securityImpact: "critical",
      availabilityRisk: "low",
      lockoutRisk: "medium",
      operationalComplexity: "medium",
    },
    applicability: (inv) =>
      sectionGap(inv.users)
        ? {
            status: "unknown",
            rationale: "the users section is not reliable, so UID 0 duplication cannot be assessed",
            evidence: [ref("users.status", inv.users.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("user accounts are available in the inventory"),
    assess: (inv) => {
      const zeros = uidZeroUsers(inv);
      const evidence = [ref("users.data.users[uid=0]", zeros.map((u) => u.name).join(", ") || "none")];
      if (zeros.length === 1) {
        return compliant("1 account with UID 0", "exactly one UID 0 account is present", evidence);
      }
      return nonCompliant(
        `${zeros.length} accounts with UID 0`,
        "more than one UID 0 account was observed",
        evidence,
      );
    },
  },
  {
    id: "ID-002",
    title: "System accounts must not have interactive shells",
    category: "identity",
    phase: "identity",
    order: 10,
    platform: ["linux"],
    description: "Accounts below the human UID range should not offer interactive login shells.",
    rationale:
      "Service/system accounts with interactive shells are an easy, low-noise persistence and lateral-movement path. Note that account classification here is a heuristic (UID range + shell), which is why the finding reports the raw account names for review.",
    desiredState: "no system account with an interactive login shell",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["identity", "persistence"],
    references: ["CIS Controls v8 5.4", "NIST SP 800-53 AC-6"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "low",
      lockoutRisk: "low",
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
        : applicable("user accounts are available in the inventory"),
    assess: (inv) => {
      const offenders = users(inv).filter(
        (u) => u.uid !== 0 && u.accountType.value === "system" && isInteractiveShell(u),
      );
      const evidence = [
        ref(
          "users.data.users[system with interactive shell]",
          offenders.map((u) => `${u.name}(${u.shell ?? "?"})`).join(", ") || "none",
        ),
      ];
      if (offenders.length === 0) {
        return compliant(
          "0 system accounts with interactive shells",
          "no such account was observed",
          evidence,
        );
      }
      return requiresReview(
        `${offenders.length} system account(s) with interactive shells`,
        "these accounts carry a heuristic classification; confirm whether the interactive shell is intended before changing it",
        evidence,
      );
    },
  },
  {
    id: "ID-003",
    title: "Account lock state is observable",
    category: "identity",
    phase: "identity",
    order: 20,
    platform: ["linux"],
    description: "The framework should be able to determine whether accounts are locked.",
    rationale:
      "Without lock state, abandoned or unused accounts cannot be distinguished from active ones. This is an evidence-availability control, not an assertion about any account.",
    desiredState: "account lock state readable (/etc/shadow accessible to discovery)",
    requiresApproval: false,
    reversible: true,
    dependencies: [],
    tags: ["identity", "evidence"],
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
      const all = users(inv);
      if (all.length === 0) {
        return unknownState(null, "no accounts were present in the inventory", [
          ref("users.data.users", "0"),
        ]);
      }
      const observed = all.filter((u) => u.locked.confidence === "observed").length;
      const evidence = [ref("users.data.users[locked.confidence=observed]", `${observed}/${all.length}`)];
      if (observed === all.length) {
        return compliant(
          `lock state observed for ${observed}/${all.length} accounts`,
          "lock state was readable for every account",
          evidence,
        );
      }
      return requiresReview(
        `lock state observed for ${observed}/${all.length} accounts`,
        "run discovery with sufficient privileges (or accept the gap) to make lock state authoritative",
        evidence,
      );
    },
  },
];
