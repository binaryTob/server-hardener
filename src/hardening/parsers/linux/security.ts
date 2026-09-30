/**
 * Parsers for security controls.
 *
 * Detection only — this module never modifies, enables, disables, or
 * configures any control. Endpoint protection tools (antivirus/EDR/HIDS,
 * including Wazuh) are represented as detected capabilities, never assumed
 * from absence of evidence.
 */

import type { LinuxRaw } from "../../collectors/linux";
import { OBSERVED_UNITS } from "../../collectors/linux";
import type {
  DetectedCapability,
  EndpointKind,
  Evidence,
  Section,
  SecurityControlsData,
  ServiceControlState,
} from "../../models";
import { combinedStatus, failureNote, fileFailureNote, fileReadStatus, makeSection } from "./shared";

export interface UnitStates {
  active: Map<string, string>;
  enabled: Map<string, string>;
  complete: boolean;
}

/**
 * Parse `systemctl is-active` / `is-enabled` multi-unit output. Both commands
 * print exactly one line per requested unit, in the same order.
 */
export function parseUnitStates(
  isActive: { outcome: { status: string; stdout: string } },
  isEnabled: { outcome: { status: string; stdout: string } },
): UnitStates {
  const active = new Map<string, string>();
  const enabled = new Map<string, string>();
  const activeLines = isActive.outcome.stdout
    .trim()
    .split("\n")
    .filter((l) => l.length > 0);
  const enabledLines = isEnabled.outcome.stdout
    .trim()
    .split("\n")
    .filter((l) => l.length > 0);
  let complete = true;
  for (let i = 0; i < OBSERVED_UNITS.length; i++) {
    const unit = OBSERVED_UNITS[i];
    if (unit === undefined) continue;
    const activeLine = activeLines[i];
    const enabledLine = enabledLines[i];
    if (activeLine !== undefined) active.set(unit, activeLine.trim());
    if (enabledLine !== undefined) enabled.set(unit, enabledLine.trim());
  }
  if (activeLines.length !== OBSERVED_UNITS.length || enabledLines.length !== OBSERVED_UNITS.length) {
    complete = false;
  }
  return { active, enabled, complete };
}

function serviceControl(states: UnitStates, unit: string): ServiceControlState {
  const enabledState = states.enabled.get(unit);
  const activeState = states.active.get(unit);
  if (enabledState === undefined && activeState === undefined) {
    return { available: false, active: null, enabled: null };
  }
  return {
    available: enabledState !== "not-found",
    active:
      activeState === "active" ? true : activeState === "inactive" || activeState === "failed" ? false : null,
    enabled:
      enabledState === "enabled" || enabledState === "enabled-runtime"
        ? true
        : enabledState === "disabled" || enabledState === "masked"
          ? false
          : null,
  };
}

function selinuxState(raw: LinuxRaw["security"]) {
  const ok = raw.getenforce.outcome.status === "ok";
  const status = ok ? raw.getenforce.outcome.stdout.trim() || null : null;
  return { available: ok && status !== null, status };
}

function appArmorState(raw: LinuxRaw["security"]) {
  if (raw.appArmorEnabled.ok) {
    const value = raw.appArmorEnabled.content.trim();
    return { available: true, status: value || null };
  }
  return { available: false, status: null };
}

interface FirewallImpl {
  name: string;
  units: string[];
  binaries: string[];
}

const FIREWALL_IMPLS: FirewallImpl[] = [
  { name: "firewalld", units: ["firewalld.service"], binaries: ["firewall-cmd"] },
  { name: "ufw", units: ["ufw.service"], binaries: ["ufw"] },
  { name: "nftables", units: ["nftables.service"], binaries: ["nft"] },
  { name: "iptables (legacy)", units: [], binaries: ["iptables"] },
];

function firewallState(
  raw: LinuxRaw["security"],
  states: UnitStates,
  collectedAt: string,
): SecurityControlsData["firewall"] {
  const detected: string[] = [];
  for (const impl of FIREWALL_IMPLS) {
    const unitAvailable = impl.units.some((u) => {
      const enabled = states.enabled.get(u);
      return enabled !== undefined && enabled !== "not-found";
    });
    const binaryAvailable = impl.binaries.some((b) => (raw.detectedBinaries[b] ?? null) !== null);
    if (unitAvailable || binaryAvailable) detected.push(impl.name);
  }

  // Wildcard-address listeners do NOT prove an active firewall; this value is
  // always derived from unit + binary evidence and labeled as such.
  const evidence: Evidence<string | null> = {
    value: detected[0] ?? null,
    source: "systemctl is-enabled + binary presence (firewalld, ufw, nft, iptables)",
    confidence: "derived",
    collectedAt,
  };

  const primaryUnit = FIREWALL_IMPLS.find((i) => i.name === (detected[0] ?? ""))?.units[0];
  const control = primaryUnit ? serviceControl(states, primaryUnit) : null;

  return {
    implementation: evidence,
    active: control ? control.active : null,
    enabled: control ? control.enabled : null,
    detectedImplementations: detected,
  };
}

interface EndpointCandidate {
  name: string;
  kind: EndpointKind;
  units: string[];
  binaries: string[];
}

const ENDPOINT_CANDIDATES: EndpointCandidate[] = [
  { name: "Wazuh agent", kind: "hids", units: ["wazuh-agent.service"], binaries: ["wazuh-control"] },
  { name: "ClamAV", kind: "antivirus", units: ["clamav-daemon.service"], binaries: ["clamscan"] },
  { name: "ossec", kind: "hids", units: ["ossec.service"], binaries: [] },
  { name: "SentinelOne", kind: "edr", units: ["sentinelone.service"], binaries: ["sentinelctl"] },
  { name: "CrowdStrike Falcon", kind: "edr", units: ["falcon-sensor.service"], binaries: ["falconctl"] },
  { name: "Microsoft Defender for Endpoint", kind: "edr", units: ["mdatp.service"], binaries: ["mdatp"] },
];

function endpointProtection(raw: LinuxRaw["security"], states: UnitStates): DetectedCapability[] {
  const capabilities: DetectedCapability[] = [];
  for (const candidate of ENDPOINT_CANDIDATES) {
    const sources: string[] = [];
    let status: string | null = null;
    for (const unit of candidate.units) {
      const enabled = states.enabled.get(unit);
      if (enabled !== undefined && enabled !== "not-found") {
        sources.push(`systemctl is-enabled ${unit}`);
        const active = states.active.get(unit) ?? null;
        if (status === null) status = active ?? "installed";
      }
    }
    for (const binary of candidate.binaries) {
      const path = raw.detectedBinaries[binary] ?? null;
      if (path !== null) {
        sources.push(`binary: ${path}`);
        if (status === null) status = "installed";
      }
    }
    if (sources.length > 0) {
      capabilities.push({
        name: candidate.name,
        kind: candidate.kind,
        status,
        source: sources.join(" | "),
        confidence: "observed",
      });
    }
  }
  return capabilities;
}

export function parseSecurityControls(
  raw: LinuxRaw["security"],
  services: LinuxRaw["services"],
  collectedAt: string,
): Section<SecurityControlsData> {
  const notes: string[] = [];

  const systemdAvailable = services.systemdRunning;
  const states = parseUnitStates(services.isActive, services.isEnabled);
  if (!states.complete)
    notes.push("systemctl is-active/is-enabled output incomplete; some unit states unknown");

  const sshControl = (() => {
    const ssh = serviceControl(states, "ssh.service");
    const sshd = serviceControl(states, "sshd.service");
    const chosen = ssh.available
      ? { control: ssh, unit: "ssh.service" }
      : sshd.available
        ? { control: sshd, unit: "sshd.service" }
        : null;
    if (chosen) return { ...chosen.control, unit: chosen.unit };
    return { available: false, active: null, enabled: null, unit: null };
  })();

  const firewall = firewallState(raw, states, collectedAt);
  if (firewall.detectedImplementations.length === 0) {
    notes.push("no firewall implementation detected (absence of evidence, not evidence of absence)");
  }

  if (!systemdAvailable) {
    notes.push("systemd not running: service-dependent control states could not be determined");
  }
  if (raw.getenforce.outcome.status !== "ok") {
    const note = failureNote(raw.getenforce.display, raw.getenforce.outcome);
    if (note) notes.push(note);
  }
  if (!raw.appArmorEnabled.ok) {
    const note = fileFailureNote("/sys/module/apparmor/parameters/enabled", raw.appArmorEnabled.status);
    if (note) notes.push(note);
  }

  const data: SecurityControlsData = {
    selinux: selinuxState(raw),
    appArmor: appArmorState(raw),
    firewall,
    auditd: serviceControl(states, "auditd.service"),
    journald: serviceControl(states, "systemd-journald.service"),
    rsyslog: serviceControl(states, "rsyslog.service"),
    sshServer: sshControl,
    endpointProtection: endpointProtection(raw, states),
  };

  const status = combinedStatus([
    raw.getenforce.outcome.status === "ok" ? "success" : "unavailable",
    fileReadStatus(raw.appArmorEnabled),
    systemdAvailable ? "success" : "unavailable",
  ]);

  return makeSection(status, data, notes);
}
