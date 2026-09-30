/**
 * Parsers for container runtime presence (Docker, Podman, containerd,
 * Kubernetes/k3s).
 *
 * Phase 1 records presence and version only. Workloads, images, networks and
 * orchestrator configuration are NOT inspected.
 */

import type { LinuxRaw, RawCommand } from "../../collectors/linux";
import type { ContainerRuntime, ContainersData, Section } from "../../models";
import { parseUnitStates } from "./security";
import { failureNote, makeSection, trimForNote } from "./shared";

function versionOf(raw: RawCommand, pattern: RegExp): string | null {
  if (raw.outcome.status !== "ok") return null;
  const match = pattern.exec(raw.outcome.stdout);
  return match ? (match[1] ?? null) : null;
}

export function parseContainers(
  raw: LinuxRaw["containers"],
  rawSecurity: LinuxRaw["security"],
  services: LinuxRaw["services"],
): Section<ContainersData> {
  const runtimes: ContainerRuntime[] = [];
  const states = parseUnitStates(services.isActive, services.isEnabled);

  const activeOf = (unit: string): boolean | null => {
    const value = states.active.get(unit);
    if (value === "active") return true;
    if (value === "inactive" || value === "failed") return false;
    return null;
  };

  const dockerVersion = versionOf(raw.dockerVersion, /Docker version (\S+),/);
  if (dockerVersion !== null) {
    runtimes.push({
      name: "docker",
      version: dockerVersion,
      active: activeOf("docker.service"),
      detectedVia: raw.dockerVersion.display,
    });
  }
  const podmanVersion = versionOf(raw.podmanVersion, /podman version (\S+)/i);
  if (podmanVersion !== null) {
    runtimes.push({
      name: "podman",
      version: podmanVersion,
      active: null,
      detectedVia: raw.podmanVersion.display,
    });
  }
  const containerdVersion = versionOf(raw.containerdVersion, /containerd .*?v(\d+\.\d+\.\d+)/i);
  if (containerdVersion !== null) {
    runtimes.push({
      name: "containerd",
      version: containerdVersion,
      active: activeOf("containerd.service"),
      detectedVia: raw.containerdVersion.display,
    });
  }
  const k3sVersion = versionOf(raw.k3sVersion, /k3s version (\S+)/i);
  if (k3sVersion !== null) {
    runtimes.push({
      name: "k3s",
      version: k3sVersion,
      active: activeOf("k3s.service"),
      detectedVia: raw.k3sVersion.display,
    });
  }
  const kubeletVersion = versionOf(raw.kubeletVersion, /Kubernetes v(\S+)/i);
  if (kubeletVersion !== null) {
    runtimes.push({
      name: "kubelet",
      version: kubeletVersion,
      active: activeOf("kubelet.service"),
      detectedVia: raw.kubeletVersion.display,
    });
  }

  // Binaries present whose --version failed (odd states) still count as
  // presence evidence, with version unknown.
  const binaryOnly: { name: ContainerRuntime["name"]; binary: string; unit: string | null }[] = [
    { name: "docker", binary: "docker", unit: "docker.service" },
    { name: "podman", binary: "podman", unit: null },
    { name: "containerd", binary: "containerd", unit: "containerd.service" },
    { name: "k3s", binary: "k3s", unit: "k3s.service" },
    { name: "kubelet", binary: "kubelet", unit: "kubelet.service" },
  ];
  for (const entry of binaryOnly) {
    if (runtimes.some((r) => r.name === entry.name)) continue;
    const path = rawSecurity.detectedBinaries[entry.binary] ?? null;
    if (path !== null) {
      runtimes.push({
        name: entry.name,
        version: null,
        active: entry.unit ? activeOf(entry.unit) : null,
        detectedVia: `binary presence: ${path}`,
      });
    }
  }

  const notes: string[] = [];
  const errored = [
    raw.dockerVersion,
    raw.podmanVersion,
    raw.containerdVersion,
    raw.k3sVersion,
    raw.kubeletVersion,
  ].filter((cmd) => cmd.outcome.status === "error" || cmd.outcome.status === "timeout");
  for (const cmd of errored) {
    const note = failureNote(cmd.display, cmd.outcome);
    if (note) notes.push(note);
  }
  const denied = [
    raw.dockerVersion,
    raw.podmanVersion,
    raw.containerdVersion,
    raw.k3sVersion,
    raw.kubeletVersion,
  ].filter((cmd) => cmd.outcome.status === "insufficient-permissions");
  for (const cmd of denied) {
    notes.push(`${cmd.display}: insufficient permissions ${trimForNote(cmd.outcome.stderr)}`);
  }
  if (runtimes.length === 0) {
    notes.push("no container runtimes detected (absence of evidence, not evidence of absence)");
  }

  const status = errored.length > 0 ? "error" : denied.length > 0 ? "insufficient-permissions" : "success";

  return makeSection(status, { runtimes }, notes);
}
