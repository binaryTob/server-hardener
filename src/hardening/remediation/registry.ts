/**
 * Remediation registry: control id -> remediation implementation.
 *
 * Controls without a safe automatic remediation get a manual placeholder that
 * explains why and refuses to apply.
 */

import { filesystemRemediations } from "./filesystem";
import { firewallRemediations } from "./firewall";
import { loggingRemediations } from "./logging";
import { serviceRemediations } from "./services";
import { sshRemediations } from "./ssh";
import { sysctlRemediations } from "./sysctl";
import { manualRemediation, type Remediation } from "./types";

const REMEDIATIONS: Record<string, Remediation> = {
  ...sysctlRemediations,
  ...sshRemediations,
  ...firewallRemediations,
  ...serviceRemediations,
  ...loggingRemediations,
  ...filesystemRemediations,
};

const MANUAL_REASONS: Record<string, string> = {
  "SSH-006": "network-level restriction requires firewall rules reviewed for this host; apply manually",
  "FW-002": "deciding on a firewall implementation is an operational decision; apply manually",
  "FW-003": "management network restriction requires reviewed firewall rules; apply manually",
  "SVC-002": "service justification is a human decision; select and disable specific services explicitly",
  "LOG-002": "persistent logging configuration is environment-specific; apply manually",
  "LOG-003": "deploying a monitoring agent is an operational decision; apply manually",
  "FS-003": "re-partitioning/mounting is disruptive and not automated",
  "FS-004": "noexec depends on the workload and can break it; apply manually after review",
  "PKG-001": "package manager state requires manual remediation",
  "PKG-002": "package removal requires explicit review and is not automated",
  "PKG-003": "package lifecycle requires repository metadata and review; apply manually",
  "CTN-001": "Docker daemon configuration change requires review; apply manually",
  "CTN-002": "Kubernetes API binding change requires review; apply manually",
  "CTN-003": "container runtime isolation configuration is not automated in Phase 3",
  "NET-001": "wildcard listeners require per-service review; apply manually",
  "NET-002": "removing a plaintext service requires service-specific review; apply manually",
  "ID-001": "removing a UID 0 account is high-risk and requires manual approval",
  "ID-002": "changing a system account shell requires review; apply manually",
  "ID-003": "re-running discovery with privileges is required, not a change",
  "PA-001": "administrative membership changes require manual approval",
  "PA-002": "administrative account removal requires manual approval",
  "PA-003": "documenting the escalation path is a process action, not a host change",
  "TIME-001": "time source configuration is environment-specific; apply manually",
};

export function getRemediation(controlId: string): Remediation {
  const implemented = REMEDIATIONS[controlId];
  if (implemented) return implemented;
  const reason =
    MANUAL_REASONS[controlId] ??
    "no automatic remediation is implemented for this control in Phase 3; review and apply manually";
  return manualRemediation(controlId, reason);
}

export function hasAutomaticRemediation(controlId: string): boolean {
  return controlId in REMEDIATIONS;
}

export function automaticRemediationIds(): string[] {
  return Object.keys(REMEDIATIONS).sort();
}
