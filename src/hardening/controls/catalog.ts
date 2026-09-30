/**
 * Control catalog aggregation.
 *
 * The catalog is composed from per-domain modules so each control group is
 * independently testable. `CONTROL_CATALOG` is the single source of truth used
 * by the planning engines.
 */
import { auditingControls } from "./auditing";
import { containerControls } from "./containers";
import { filesystemControls } from "./filesystem";
import { firewallControls } from "./firewall";
import { identityControls } from "./identity";
import { kernelControls } from "./kernel";
import { loggingControls } from "./logging";
import { networkControls } from "./network";
import { packageControls } from "./packages";
import { privilegedAccessControls } from "./privileged";
import { serviceControls } from "./services";
import { sshControls } from "./ssh";
import { timeControls } from "./time";
import type { ControlDefinition } from "./types";

export type { ControlDefinition } from "./types";

/** Bump when control semantics change (recorded inside each generated plan). */
export const CATALOG_VERSION = "2026.09.1";

export const CONTROL_CATALOG: ControlDefinition[] = [
  ...identityControls,
  ...privilegedAccessControls,
  ...sshControls,
  ...serviceControls,
  ...firewallControls,
  ...networkControls,
  ...loggingControls,
  ...auditingControls,
  ...timeControls,
  ...kernelControls,
  ...filesystemControls,
  ...packageControls,
  ...containerControls,
];

export function getControl(controlId: string): ControlDefinition | undefined {
  return CONTROL_CATALOG.find((c) => c.id === controlId);
}

export interface CatalogIssue {
  controlId: string;
  problem: string;
}

/** Structural integrity checks (used by tests and the plan tool). */
export function validateCatalog(catalog: ControlDefinition[] = CONTROL_CATALOG): CatalogIssue[] {
  const issues: CatalogIssue[] = [];
  const seen = new Set<string>();
  for (const control of catalog) {
    if (seen.has(control.id)) {
      issues.push({ controlId: control.id, problem: "duplicate control id" });
    }
    seen.add(control.id);
    if (!/^[A-Z]{2,5}-\d{3}$/.test(control.id)) {
      issues.push({ controlId: control.id, problem: "control id does not match AB-000 / ABC-000" });
    }
    if (control.platform.length === 0) {
      issues.push({ controlId: control.id, problem: "no platform declared" });
    }
    for (const dependency of control.dependencies) {
      if (!catalog.some((c) => c.id === dependency)) {
        issues.push({ controlId: control.id, problem: `unknown dependency ${dependency}` });
      }
    }
  }
  return issues;
}
