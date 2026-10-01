/**
 * Filesystem controls.
 *
 * Mount options are directly observable. Whether a writable location can use
 * `noexec` depends on what runs there, so that is a context question, never an
 * automatic recommendation.
 */
import type { MountInfo, OperationalContext, RiskLevel, ServerInventory } from "../models";
import {
  applicable,
  compliant,
  mounts,
  nonCompliant,
  ref,
  requiresContext,
  requiresReview,
  sectionGap,
} from "./helpers";
import type { ControlDefinition, ControlStateAssessment } from "./types";

function mountAt(inv: ServerInventory, target: string): MountInfo | null {
  return mounts(inv).find((m) => m.mountpoint === target) ?? null;
}

function optionCheck(inv: ServerInventory, target: string, required: string[]): ControlStateAssessment {
  const mount = mountAt(inv, target);
  if (mount === null) {
    return requiresReview(
      `${target} is not a separate mount`,
      `${target} is not a dedicated mountpoint; it may be protected by service-level isolation (e.g. systemd PrivateTmp) — confirm before treating this as a defect`,
      [ref(`filesystems.data.mounts[target=${target}]`, "absent")],
    );
  }
  const options = new Set(mount.mountOptions);
  const missing = required.filter((opt) => !options.has(opt));
  const evidence = [ref(`filesystems.data.mounts[target=${target}].options`, mount.mountOptions.join(","))];
  if (missing.length === 0) {
    return compliant(
      `${target} (${mount.mountOptions.join(",")})`,
      `${target} has the required mount options`,
      evidence,
    );
  }
  return nonCompliant(
    `${target} missing ${missing.join(",")}`,
    `${target} is mounted without ${missing.join(", ")}`,
    evidence,
  );
}

function hardeningRisk(): {
  securityImpact: RiskLevel;
  availabilityRisk: RiskLevel;
  lockoutRisk: RiskLevel;
  operationalComplexity: RiskLevel;
} {
  return {
    securityImpact: "medium",
    availabilityRisk: "low",
    lockoutRisk: "none",
    operationalComplexity: "low",
  };
}

const DISTINCT_MOUNT_RISK = {
  securityImpact: "low" as RiskLevel,
  availabilityRisk: "medium" as RiskLevel,
  lockoutRisk: "low" as RiskLevel,
  operationalComplexity: "high" as RiskLevel,
};

export const filesystemControls: ControlDefinition[] = [
  {
    id: "FS-001",
    title: "Temporary directory uses hardening mount options",
    category: "filesystem",
    platform: ["linux"],
    description: "/tmp should be a separate mount with nodev and nosuid.",
    rationale:
      "Temporary directories are world-writable. nodev prevents device-file tricks and nosuid prevents setuid binaries placed there from being honoured.",
    desiredState: "/tmp mounted with nodev,nosuid",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["filesystem", "hardening"],
    references: ["CIS Controls v8 3.3"],
    baseRisk: hardeningRisk(),
    applicability: (inv) =>
      sectionGap(inv.filesystems)
        ? {
            status: "unknown",
            rationale: "the filesystems section is not reliable",
            evidence: [ref("filesystems.status", inv.filesystems.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("mount information is available"),
    assess: (inv) => optionCheck(inv, "/tmp", ["nodev", "nosuid"]),
  },
  {
    id: "FS-002",
    title: "Persistent temporary directory uses hardening mount options",
    category: "filesystem",
    platform: ["linux"],
    description: "/var/tmp should be a separate mount with nodev and nosuid.",
    rationale:
      "Like /tmp, /var/tmp is world-writable and survives reboots, making it a durable staging location for attackers.",
    desiredState: "/var/tmp mounted with nodev,nosuid",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["filesystem", "hardening"],
    references: ["CIS Controls v8 3.3"],
    baseRisk: hardeningRisk(),
    applicability: (inv) =>
      sectionGap(inv.filesystems)
        ? {
            status: "unknown",
            rationale: "the filesystems section is not reliable",
            evidence: [ref("filesystems.status", inv.filesystems.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("mount information is available"),
    assess: (inv) => optionCheck(inv, "/var/tmp", ["nodev", "nosuid"]),
  },
  {
    id: "FS-003",
    title: "Writable system paths use separate mounts",
    category: "filesystem",
    platform: ["linux"],
    description: "Sensitive writable paths should not share the root filesystem.",
    rationale:
      "Separate mounts allow independent mount options and limit the damage of a full filesystem. On existing hosts this is often impractical, so it is a review item.",
    desiredState: "/tmp, /var, /var/tmp and /home are separate mounts",
    requiresApproval: false,
    reversible: false,
    dependencies: [],
    tags: ["filesystem", "review"],
    references: ["CIS Controls v8 3.3"],
    baseRisk: DISTINCT_MOUNT_RISK,
    applicability: (inv) =>
      sectionGap(inv.filesystems)
        ? {
            status: "unknown",
            rationale: "the filesystems section is not reliable",
            evidence: [ref("filesystems.status", inv.filesystems.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("mount information is available"),
    assess: (inv) => {
      const targets = ["/tmp", "/var", "/var/tmp", "/home"];
      const present = targets.filter((t) => mountAt(inv, t) !== null);
      const missing = targets.filter((t) => mountAt(inv, t) === null);
      const evidence = [ref("filesystems.data.mounts", `present: ${present.join(", ") || "none"}`)];
      if (missing.length === 0) {
        return compliant("all paths are separate mounts", "all expected paths are separate mounts", evidence);
      }
      return requiresReview(
        `separate mounts: ${present.length}/${targets.length}`,
        `not separate: ${missing.join(", ")} — confirm whether this is acceptable for the host`,
        evidence,
      );
    },
  },
  {
    id: "FS-004",
    title: "noexec is considered for writable data locations",
    category: "filesystem",
    platform: ["linux"],
    description: "noexec on writable locations should be evaluated against what runs there.",
    rationale:
      "noexec reduces the ability to run dropped binaries, but it breaks any workflow that legitimately executes scripts from temporary or data directories. It cannot be decided without knowing the host's roles.",
    desiredState: "noexec applied where the host's workload allows it",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["filesystem", "context-dependent"],
    references: ["CIS Controls v8 3.3"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "high",
      lockoutRisk: "low",
      operationalComplexity: "medium",
    },
    applicability: (inv) =>
      sectionGap(inv.filesystems)
        ? {
            status: "unknown",
            rationale: "the filesystems section is not reliable",
            evidence: [ref("filesystems.status", inv.filesystems.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("mount information is available"),
    assess: (inv, ctx: OperationalContext) => {
      const candidates = ["/tmp", "/var/tmp", "/home"]
        .map((t) => mountAt(inv, t))
        .filter((m): m is MountInfo => m !== null);
      const withoutNoexec = candidates.filter((m) => !m.mountOptions.includes("noexec"));
      const evidence = [
        ref(
          "filesystems.data.mounts[writable].options",
          candidates.map((m) => `${m.mountpoint}(${m.mountOptions.join(",")})`).join("; ") ||
            "no candidate mounts",
        ),
        ref("context.roles", ctx.roles.map((r) => r.role).join(", ") || "no roles confirmed"),
      ];
      if (candidates.length === 0) {
        return requiresReview(
          "no candidate writable mounts",
          "no writable data mount was found to evaluate",
          evidence,
        );
      }
      if (withoutNoexec.length === 0) {
        return compliant("all writable mounts use noexec", "noexec is already applied", evidence);
      }
      if (ctx.roles.filter((r) => r.confidence === "confirmed").length === 0) {
        return requiresContext(
          `${withoutNoexec.length} writable mount(s) without noexec`,
          "whether noexec is safe depends on whether the host's workloads execute scripts from these locations",
          ["roles"],
          evidence,
        );
      }
      return requiresReview(
        `${withoutNoexec.length} writable mount(s) without noexec`,
        "confirm the workload does not execute scripts from these paths before applying noexec",
        evidence,
      );
    },
  },
];
