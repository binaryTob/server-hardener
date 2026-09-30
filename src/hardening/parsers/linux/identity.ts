/**
 * Parsers for identity and operating system discovery.
 *
 * Sources: hostnamectl (auxiliary), hostname, uname, systemd-detect-virt
 * (auxiliary), /etc/machine-id, /etc/os-release.
 */

import type { LinuxRaw, RawCommand } from "../../collectors/linux";
import type { CommandOutcome } from "../../exec";
import type { CollectionStatus, IdentityData, OperatingSystemData, Section } from "../../models";
import {
  auxiliaryStatus,
  combinedStatus,
  failureNote,
  firstLine,
  makeSection,
  primaryStatus,
  stdoutOf,
} from "./shared";

interface HostnamectlFields {
  staticHostname: string | null;
  virtualization: string | null;
  architecture: string | null;
  kernel: string | null;
}

function parseHostnamectl(raw: RawCommand): HostnamectlFields {
  const fields: HostnamectlFields = {
    staticHostname: null,
    virtualization: null,
    architecture: null,
    kernel: null,
  };
  for (const line of stdoutOf(raw.outcome).split("\n")) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (value.length === 0) continue;
    if (key === "Static hostname") fields.staticHostname = value;
    else if (key === "Virtualization") fields.virtualization = value;
    else if (key === "Architecture") fields.architecture = value;
    else if (key === "Kernel") fields.kernel = value;
  }
  return fields;
}

/** Parse "Linux 6.8.0-45-generic x86_64" from `uname -srm`. */
export function parseUnameSrm(text: string): {
  kernel: string | null;
  release: string | null;
  arch: string | null;
} {
  const parts = text.trim().split(/\s+/);
  if (parts.length < 3) return { kernel: null, release: null, arch: null };
  return { kernel: parts[0] ?? null, release: parts[1] ?? null, arch: parts[2] ?? null };
}

export function parseIdentity(raw: LinuxRaw["identity"], collectedAt: string): Section<IdentityData> {
  const hostnamectl = parseHostnamectl(raw.hostnamectl);
  const hostname = firstLine(raw.hostname.outcome);
  const fqdn = firstLine(raw.hostnameFqdn.outcome);
  const uname = parseUnameSrm(raw.unameSrm.outcome.stdout);
  const machineId = raw.machineId.ok ? raw.machineId.content.trim() || null : null;

  const virtualization = virtualizationEvidence(raw, hostnamectl, collectedAt);

  const notes: string[] = [];
  const hostnamectlNote = failureNote(raw.hostnamectl.display, raw.hostnamectl.outcome);
  if (hostnamectlNote) notes.push(hostnamectlNote);
  if (!fqdn) notes.push("fqdn could not be determined");

  const status = combinedStatus([
    auxiliaryStatus(raw.hostnamectl.outcome),
    primaryStatus(raw.hostname.outcome),
    primaryStatus(raw.hostnameFqdn.outcome),
    primaryStatus(raw.unameSrm.outcome),
    detectVirtStatus(raw.detectVirt.outcome),
    raw.machineId.ok ? "success" : "unavailable",
  ]);

  return makeSection(
    status,
    {
      hostname: hostnamectl.staticHostname ?? hostname,
      fqdn,
      machineId,
      virtualization,
      architecture: uname.arch ?? hostnamectl.architecture,
    },
    notes,
  );
}

/**
 * systemd-detect-virt exits 1 (printing "none") on bare metal. That is a
 * successful observation of the absence of virtualization, not a failure.
 */
function detectVirtStatus(outcome: CommandOutcome): CollectionStatus {
  if (outcome.status === "ok") return "success";
  if (outcome.exitCode === 1 && outcome.stdout.trim().length > 0) return "success";
  return auxiliaryStatus(outcome);
}

function virtualizationEvidence(
  raw: LinuxRaw["identity"],
  hostnamectl: HostnamectlFields,
  collectedAt: string,
): IdentityData["virtualization"] {
  if (hostnamectl.virtualization !== null) {
    return {
      value: hostnamectl.virtualization,
      source: raw.hostnamectl.display,
      confidence: "observed",
      collectedAt,
    };
  }
  const detectVirt = raw.detectVirt.outcome.stdout.trim();
  if (detectVirt) {
    // systemd-detect-virt prints "none" (and exits 1) on bare metal: that is
    // an observation of the absence of virtualization, not a failure.
    const value = detectVirt === "none" ? null : detectVirt;
    return { value, source: raw.detectVirt.display, confidence: "observed", collectedAt };
  }
  return {
    value: null,
    source: `${raw.hostnamectl.display} / ${raw.detectVirt.display}`,
    confidence: "unknown",
    collectedAt,
  };
}

interface OsReleaseFields {
  prettyName: string | null;
  name: string | null;
  version: string | null;
  versionId: string | null;
}

/** Parse /etc/os-release content. */
export function parseOsRelease(text: string): OsReleaseFields {
  const fields: OsReleaseFields = { prettyName: null, name: null, version: null, versionId: null };
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq);
    const value = stripQuotes(trimmed.slice(eq + 1));
    if (value.length === 0) continue;
    if (key === "PRETTY_NAME") fields.prettyName = value;
    else if (key === "NAME") fields.name = value;
    else if (key === "VERSION") fields.version = value;
    else if (key === "VERSION_ID") fields.versionId = value;
  }
  return fields;
}

function stripQuotes(value: string): string {
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1);
  }
  return value;
}

export function parseOperatingSystem(raw: LinuxRaw["operatingSystem"]): Section<OperatingSystemData> {
  const uname = parseUnameSrm(raw.unameSrm.outcome.stdout);
  const hostnamectl = parseHostnamectl(raw.hostnamectl);
  const osRelease = raw.osRelease.ok ? parseOsRelease(raw.osRelease.content) : null;

  const notes: string[] = [];
  if (!osRelease) notes.push("/etc/os-release: not available");
  const unameNote = failureNote(raw.unameSrm.display, raw.unameSrm.outcome);
  if (unameNote) notes.push(unameNote);

  const status = combinedStatus([
    raw.osRelease.ok ? "success" : "unavailable",
    primaryStatus(raw.unameSrm.outcome),
    auxiliaryStatus(raw.hostnamectl.outcome),
  ]);

  return makeSection(
    status,
    {
      family: "linux",
      distribution: osRelease?.prettyName ?? osRelease?.name ?? null,
      version: osRelease?.version ?? null,
      versionId: osRelease?.versionId ?? null,
      kernel: uname.kernel ?? hostnamectl.kernel?.split(" ")[0] ?? null,
      kernelRelease: uname.release ?? hostnamectl.kernel?.split(" ")[1] ?? null,
    },
    notes,
  );
}
