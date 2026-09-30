/**
 * Helpers for planning tests: a full sample inventory and context, plus
 * deterministic clone/mutation helpers. No real command runs.
 */

import { getControl } from "../src/hardening/controls/catalog";
import type { ControlDefinition } from "../src/hardening/controls/types";
import { runDiscovery } from "../src/hardening/inventory";
import type { OperationalContext, ServerInventory, ServerRole } from "../src/hardening/models";
import { emptyContext } from "../src/hardening/planning/context";
import { successfulScenario } from "./helpers";

export const NOW = "2025-03-04T05:06:07.000Z";

export function mustControl(controlId: string): ControlDefinition {
  const control = getControl(controlId);
  if (!control) throw new Error(`control ${controlId} not found in catalog`);
  return control;
}

export async function sampleInventory(): Promise<ServerInventory> {
  const { runner, files } = successfulScenario();
  return runDiscovery({ runner, files, now: () => NOW, platform: "linux" });
}

export function clone<T>(value: T): T {
  return structuredClone(value);
}

export interface SampleContextOptions {
  serverId?: string;
  environment?: OperationalContext["environment"];
  internetExposure?: OperationalContext["internetExposure"];
  secondaryPathConfirmed?: boolean | null;
  consoleAccess?: boolean | null;
  roles?: ServerRole[];
  confirmedRoles?: ServerRole[];
}

export function sampleContext(options: SampleContextOptions = {}): OperationalContext {
  const serverId = options.serverId ?? "srv-0123456789abcdef";
  const base = emptyContext(serverId, NOW);
  const confirmed = options.confirmedRoles ?? options.roles ?? ["generic-server"];
  return {
    ...base,
    environment: options.environment ?? "production",
    criticality: "high",
    internetExposure: options.internetExposure ?? "none",
    roles: confirmed.map((role) => ({ role, confidence: "confirmed" as const, source: "test" })),
    management: {
      methods: ["ssh"],
      secondaryPathConfirmed:
        options.secondaryPathConfirmed === undefined ? true : options.secondaryPathConfirmed,
      consoleAccess: options.consoleAccess === undefined ? true : options.consoleAccess,
    },
    networks: { administrative: ["10.0.0.0/8"], service: ["10.0.0.0/8"] },
    reboot: { allowed: true, maintenanceWindowAvailable: true },
    highAvailability: false,
    operatorNotes: null,
  };
}

/** Remove every non-root administrative account from an inventory copy. */
export function withoutAdministrativeUsers(inventory: ServerInventory): ServerInventory {
  const copy = clone(inventory);
  if (copy.users.data) {
    copy.users.data.users = copy.users.data.users.map((user) =>
      user.uid === 0
        ? user
        : {
            ...user,
            supplementaryGroups: [],
            primaryGroup: "users",
          },
    );
    copy.users.data.groups = copy.users.data.groups.map((group) => ({ ...group, members: [] }));
  }
  if (copy.privilegedAccess.data) {
    copy.privilegedAccess.data.administrativeGroups = [];
  }
  return copy;
}

/** Mark every account's lock state as unobservable (shadow unreadable). */
export function withUnknownLockState(inventory: ServerInventory): ServerInventory {
  const copy = clone(inventory);
  if (copy.users.data) {
    copy.users.data.users = copy.users.data.users.map((user) => ({
      ...user,
      locked: { value: null, confidence: "unknown" as const, source: "/etc/shadow", collectedAt: NOW },
    }));
  }
  return copy;
}
