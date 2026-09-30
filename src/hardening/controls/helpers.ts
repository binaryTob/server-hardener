/**
 * Shared helpers for control definitions: inventory accessors, applicability
 * short-hands and reusable precondition checks.
 *
 * Pure functions only. No command execution, no host access.
 */
import type {
  ApplicabilityDecision,
  EvidenceRef,
  InventoryUser,
  OperationalContext,
  Section,
  ServerInventory,
} from "../models";
import type { ControlStateAssessment, PreconditionCheck, PreconditionSpec } from "./types";

// --- Applicability short-hands --------------------------------------------

export function applicable(rationale: string, evidence: EvidenceRef[] = []): ApplicabilityDecision {
  return { status: "applicable", rationale, evidence, missingContext: [], confidence: "observed" };
}

export function applicableWithContext(
  rationale: string,
  missingContext: string[],
  evidence: EvidenceRef[] = [],
): ApplicabilityDecision {
  return {
    status: "requires-context",
    rationale,
    evidence,
    missingContext,
    confidence: "derived",
  };
}

export function notApplicable(rationale: string, evidence: EvidenceRef[] = []): ApplicabilityDecision {
  return { status: "not-applicable", rationale, evidence, missingContext: [], confidence: "observed" };
}

export function unknownApplicability(rationale: string, evidence: EvidenceRef[] = []): ApplicabilityDecision {
  return { status: "unknown", rationale, evidence, missingContext: [], confidence: "unknown" };
}

export function unsupported(rationale: string): ApplicabilityDecision {
  return { status: "unsupported", rationale, evidence: [], missingContext: [], confidence: "unknown" };
}

// --- Evidence --------------------------------------------------------------

export function ref(inventoryPath: string, observed: string | null, note?: string): EvidenceRef {
  return note === undefined ? { inventoryPath, observed } : { inventoryPath, observed, note };
}

/** An evidence reference marking a value that the inventory does not contain. */
export function missingEvidence(path: string, note: string): EvidenceRef {
  return { inventoryPath: path, observed: null, note };
}

export function booleanText(value: boolean | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  return value ? "true" : "false";
}

// --- Inventory accessors ---------------------------------------------------

export function osFamily(inv: ServerInventory): string {
  return inv.operatingSystem.data?.family ?? "unknown";
}

export function systemdRunning(inv: ServerInventory): boolean {
  return inv.services.data?.serviceManager === "systemd";
}

export function sockets(inv: ServerInventory): NonNullable<ServerInventory["sockets"]["data"]>["sockets"] {
  return inv.sockets.data?.sockets ?? [];
}

export function users(inv: ServerInventory): InventoryUser[] {
  return inv.users.data?.users ?? [];
}

export function mounts(inv: ServerInventory): NonNullable<ServerInventory["filesystems"]["data"]>["mounts"] {
  return inv.filesystems.data?.mounts ?? [];
}

export function services(inv: ServerInventory): NonNullable<ServerInventory["services"]["data"]>["services"] {
  return inv.services.data?.services ?? [];
}

export function packages(inv: ServerInventory): NonNullable<ServerInventory["packages"]["data"]>["packages"] {
  return inv.packages.data?.packages ?? [];
}

/** True when a section could not be read reliably (evidence gap). */
export function sectionGap<T>(section: Section<T>): boolean {
  return section.status !== "success" && section.status !== "partial";
}

// --- Users / privileged access --------------------------------------------

const ADMIN_GROUP_FALLBACK = ["wheel", "sudo", "adm", "disk", "admin", "root"];

export function adminGroupNames(inv: ServerInventory): Set<string> {
  const fromInventory = (inv.privilegedAccess.data?.administrativeGroups ?? []).map((g) => g.name);
  const names = fromInventory.length > 0 ? fromInventory : ADMIN_GROUP_FALLBACK;
  return new Set(names);
}

/** Usernames that are members of any administrative group. */
export function adminUsernames(inv: ServerInventory): Set<string> {
  const adminGroups = adminGroupNames(inv);
  const names = new Set<string>();
  for (const group of inv.users.data?.groups ?? []) {
    if (!adminGroups.has(group.name)) continue;
    for (const member of group.members) names.add(member);
  }
  for (const user of users(inv)) {
    if (user.uid === 0) names.add(user.name);
    if (user.primaryGroup && adminGroups.has(user.primaryGroup)) names.add(user.name);
    if (user.supplementaryGroups.some((g) => adminGroups.has(g))) names.add(user.name);
  }
  return names;
}

export interface AdminCandidate {
  user: InventoryUser;
  reasons: string[];
}

/** Non-root accounts with administrative access. */
export function nonRootAdmins(inv: ServerInventory): AdminCandidate[] {
  const candidates: AdminCandidate[] = [];
  for (const user of users(inv)) {
    if (user.uid === 0) continue;
    const reasons: string[] = [];
    if (user.primaryGroup && adminGroupNames(inv).has(user.primaryGroup)) {
      reasons.push(`primary group ${user.primaryGroup}`);
    }
    for (const group of user.supplementaryGroups) {
      if (adminGroupNames(inv).has(group)) reasons.push(`member of ${group}`);
    }
    if (reasons.length > 0) candidates.push({ user, reasons });
  }
  return candidates;
}

export function uidZeroUsers(inv: ServerInventory): InventoryUser[] {
  return users(inv).filter((u) => u.uid === 0);
}

export function isInteractiveShell(user: InventoryUser): boolean {
  const shell = user.shell ?? "";
  return !(shell.endsWith("nologin") || shell.endsWith("false") || shell === "");
}

// --- Reusable preconditions ------------------------------------------------

/**
 * An alternative administrative account must exist and be usable (not locked).
 * Lock state is only known when /etc/shadow was readable; otherwise unknown.
 */
export function alternativeAdminUserPrecondition(): PreconditionSpec {
  return {
    id: "alternative-admin-user",
    description: "a non-root administrative account exists and is not locked",
    critical: true,
    check: (inv): PreconditionCheck => {
      if (sectionGap(inv.users)) {
        return {
          status: "unknown",
          evidence: [ref("users.status", inv.users.status, "user inventory is not reliable")],
          missingContext: [],
          reason: "the users section could not be collected reliably",
        };
      }
      const candidates = nonRootAdmins(inv);
      if (candidates.length === 0) {
        return {
          status: "unsatisfied",
          evidence: [
            ref("users.data.users", `${users(inv).length} accounts, none administrative and non-root`),
          ],
          missingContext: [],
          reason: "no non-root administrative account was found in the inventory",
        };
      }
      const evidence = candidates.map((c) =>
        ref(
          `users.data.users[name=${c.user.name}]`,
          `uid=${c.user.uid}, locked=${String(c.user.locked.value)}`,
        ),
      );
      const usable = candidates.filter((c) => c.user.locked.value === false);
      if (usable.length > 0) {
        return { status: "satisfied", evidence, missingContext: [], reason: null };
      }
      const anyUnknown = candidates.some((c) => c.user.locked.confidence === "unknown");
      if (anyUnknown) {
        return {
          status: "unknown",
          evidence,
          missingContext: [],
          reason:
            "administrative accounts exist but their lock state could not be read (requires elevated privileges)",
        };
      }
      return {
        status: "unsatisfied",
        evidence,
        missingContext: [],
        reason: "all non-root administrative accounts appear locked",
      };
    },
  };
}

/** sudo/privilege escalation must be available for a non-root admin path. */
export function privilegeEscalationPrecondition(): PreconditionSpec {
  return {
    id: "privilege-escalation-available",
    description: "a privilege escalation mechanism (sudo) is available",
    critical: true,
    check: (inv): PreconditionCheck => {
      const privileged = inv.privilegedAccess.data;
      if (privileged === null) {
        return {
          status: "unknown",
          evidence: [ref("privilegedAccess.data", null, "section unavailable")],
          missingContext: [],
          reason: "privileged access could not be determined from the inventory",
        };
      }
      const sudoers = privileged.sudoersFiles.filter((f) => f.exists);
      const evidence = [
        ref("privilegedAccess.data.sudo.available", String(privileged.sudo.available)),
        ref("privilegedAccess.data.sudoersFiles", sudoers.map((f) => f.path).join(", ") || "none"),
      ];
      if (!privileged.sudo.available) {
        return {
          status: "unsatisfied",
          evidence,
          missingContext: [],
          reason: "no sudo/privilege escalation mechanism was detected",
        };
      }
      return { status: "satisfied", evidence, missingContext: [], reason: null };
    },
  };
}

/** The operator must confirm a secondary management path exists. */
export function secondaryManagementPathPrecondition(): PreconditionSpec {
  return {
    id: "secondary-management-path",
    description: "a secondary management path is confirmed by the operator",
    critical: true,
    check: (_inv, ctx): PreconditionCheck => {
      if (ctx.management.secondaryPathConfirmed === true) {
        return {
          status: "satisfied",
          evidence: [ref("context.management.secondaryPathConfirmed", "true")],
          missingContext: [],
          reason: null,
        };
      }
      if (ctx.management.secondaryPathConfirmed === false) {
        return {
          status: "unsatisfied",
          evidence: [ref("context.management.secondaryPathConfirmed", "false")],
          missingContext: [],
          reason: "the operator reported that no secondary management path exists",
        };
      }
      return {
        status: "unknown",
        evidence: [ref("context.management.secondaryPathConfirmed", null)],
        missingContext: ["management.secondaryPathConfirmed"],
        reason: "no secondary management path has been confirmed",
      };
    },
  };
}

/** A console (out-of-band) access path removes much of the lockout risk. */
export function consoleAccessPrecondition(): PreconditionSpec {
  return {
    id: "console-access-confirmed",
    description: "console/out-of-band access is confirmed by the operator",
    critical: false,
    check: (_inv, ctx): PreconditionCheck => {
      if (ctx.management.consoleAccess === true) {
        return {
          status: "satisfied",
          evidence: [ref("context.management.consoleAccess", "true")],
          missingContext: [],
          reason: null,
        };
      }
      if (ctx.management.consoleAccess === false) {
        return {
          status: "unsatisfied",
          evidence: [ref("context.management.consoleAccess", "false")],
          missingContext: [],
          reason: "the operator reported that no console access is available",
        };
      }
      return {
        status: "unknown",
        evidence: [ref("context.management.consoleAccess", null)],
        missingContext: ["management.consoleAccess"],
        reason: "console access has not been confirmed",
      };
    },
  };
}

/** A maintenance window must be available for disruptive changes. */
export function maintenanceWindowPrecondition(): PreconditionSpec {
  return {
    id: "maintenance-window-available",
    description: "a maintenance window is available for disruptive changes",
    critical: true,
    check: (_inv, ctx): PreconditionCheck => {
      if (ctx.reboot.maintenanceWindowAvailable === true) {
        return {
          status: "satisfied",
          evidence: [ref("context.reboot.maintenanceWindowAvailable", "true")],
          missingContext: [],
          reason: null,
        };
      }
      if (ctx.reboot.maintenanceWindowAvailable === false) {
        return {
          status: "unsatisfied",
          evidence: [ref("context.reboot.maintenanceWindowAvailable", "false")],
          missingContext: [],
          reason: "the operator reported that no maintenance window is available",
        };
      }
      return {
        status: "unknown",
        evidence: [ref("context.reboot.maintenanceWindowAvailable", null)],
        missingContext: ["reboot.maintenanceWindowAvailable"],
        reason: "maintenance window availability has not been confirmed",
      };
    },
  };
}

// --- Assessment short-hands ----------------------------------------------

export function compliant(
  currentState: string,
  rationale: string,
  evidence: EvidenceRef[] = [],
): ControlStateAssessment {
  return { status: "compliant", currentState, evidence, missingContext: [], rationale };
}

export function nonCompliant(
  currentState: string,
  rationale: string,
  evidence: EvidenceRef[] = [],
): ControlStateAssessment {
  return { status: "non-compliant", currentState, evidence, missingContext: [], rationale };
}

export function requiresReview(
  currentState: string,
  rationale: string,
  evidence: EvidenceRef[] = [],
): ControlStateAssessment {
  return { status: "requires-review", currentState, evidence, missingContext: [], rationale };
}

export function unknownState(
  currentState: string | null,
  rationale: string,
  evidence: EvidenceRef[] = [],
): ControlStateAssessment {
  return { status: "unknown", currentState, evidence, missingContext: [], rationale };
}

export function requiresContext(
  currentState: string | null,
  rationale: string,
  missingContext: string[],
  evidence: EvidenceRef[] = [],
): ControlStateAssessment {
  return { status: "requires-context", currentState, evidence, missingContext, rationale };
}

export function assessmentError(rationale: string, evidence: EvidenceRef[] = []): ControlStateAssessment {
  return { status: "error", currentState: null, evidence, missingContext: [], rationale };
}

// --- Context helpers -------------------------------------------------------

export function hasConfirmedRole(ctx: OperationalContext, role: string): boolean {
  return ctx.roles.some((r) => r.role === role && r.confidence === "confirmed");
}

export function hasRole(ctx: OperationalContext, role: string): boolean {
  return ctx.roles.some((r) => r.role === role);
}
