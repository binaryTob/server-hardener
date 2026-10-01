/**
 * Local discovery orchestrator.
 *
 * Pipeline (one direction, no shortcuts):
 *   Collector (read-only commands + file reads)
 *     -> raw results
 *     -> Parsers (pure functions)
 *     -> domain model (ServerInventory)
 *
 * The orchestrator never persists anything and never runs a command the
 * collectors did not hardcode. A failing parser degrades to a single section
 * with status "error"; it never aborts the inspection.
 */

import { collectLinuxRaw } from "./collectors/linux";
import { type CommandRunner, ExecCommandRunner } from "./exec";
import { type FileReader, NodeFileReader } from "./fsio";
import type {
  CollectionStatus,
  ContainersData,
  FilesystemsData,
  IdentityData,
  NetworkData,
  OperatingSystemData,
  PackagesData,
  PrivilegedAccessData,
  Section,
  SectionName,
  SecurityControlsData,
  ServerInventory,
  ServicesData,
  SocketData,
  TimeData,
  UsersData,
} from "./models";
import { parseContainers } from "./parsers/linux/containers";
import { parseIdentity, parseOperatingSystem } from "./parsers/linux/identity";
import { parseFilesystems } from "./parsers/linux/mounts";
import { parseNetwork } from "./parsers/linux/network";
import { parsePackages } from "./parsers/linux/packages";
import { parsePrivilegedAccess } from "./parsers/linux/privileged";
import { parseSecurityControls } from "./parsers/linux/security";
import { parseServices } from "./parsers/linux/services";
import { parseSockets } from "./parsers/linux/sockets";
import { parseTime } from "./parsers/linux/time";
import { parseUsers } from "./parsers/linux/users";

export interface DiscoveryDependencies {
  runner?: CommandRunner;
  files?: FileReader;
  now?: () => string;
  /** Override the platform (Node's process.platform by default). */
  platform?: string;
}

export async function runDiscovery(deps: DiscoveryDependencies = {}): Promise<ServerInventory> {
  const runner = deps.runner ?? new ExecCommandRunner();
  const files = deps.files ?? new NodeFileReader();
  const now = deps.now ?? (() => new Date().toISOString());
  const platform = deps.platform ?? process.platform;
  const collectedAt = now();

  if (platform !== "linux") {
    return unsupportedInventory(platform, collectedAt);
  }

  let raw: Awaited<ReturnType<typeof collectLinuxRaw>>;
  try {
    raw = await collectLinuxRaw({ runner, files, now: () => collectedAt });
  } catch (err) {
    return erroredInventory(collectedAt, err);
  }

  const users = safeSection("users", () => parseUsers(raw.users, collectedAt));

  const inventory: ServerInventory = {
    generatedAt: collectedAt,
    identity: safeSection("identity", () => parseIdentity(raw.identity, collectedAt)),
    operatingSystem: safeSection("operatingSystem", () => parseOperatingSystem(raw.operatingSystem)),
    network: safeSection("network", () => parseNetwork(raw.network)),
    sockets: safeSection("sockets", () => parseSockets(raw.sockets)),
    users,
    privilegedAccess: safeSection("privilegedAccess", () =>
      parsePrivilegedAccess(raw.privilegedAccess, users.data),
    ),
    services: safeSection("services", () => parseServices(raw.services)),
    packages: safeSection("packages", () => parsePackages(raw.packages)),
    securityControls: safeSection("securityControls", () =>
      parseSecurityControls(raw.security, raw.services, collectedAt),
    ),
    filesystems: safeSection("filesystems", () => parseFilesystems(raw.filesystems)),
    time: safeSection("time", () => parseTime(raw.time, raw.services, collectedAt)),
    containers: safeSection("containers", () => parseContainers(raw.containers, raw.security, raw.services)),
  };

  // Enrich socket executables via /proc (best effort, read-only).
  if (inventory.sockets.status === "success" || inventory.sockets.status === "partial") {
    await enrichSocketExecutables(inventory.sockets, files);
  }

  return inventory;
}

/**
 * Wrap a parser so an unexpected exception degrades to a single error
 * section instead of aborting the whole inspection.
 */
function safeSection<T>(name: SectionName, parse: () => Section<T>): Section<T> {
  try {
    return parse();
  } catch (err) {
    return {
      status: "error",
      data: null,
      error: `section "${name}" failed to parse: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function enrichSocketExecutables(section: Section<SocketData>, files: FileReader): Promise<void> {
  const sockets = section.data?.sockets;
  if (!sockets) return;
  for (const socket of sockets) {
    if (socket.processPid === null) continue;
    const link = await files.readlink(`/proc/${socket.processPid}/exe`);
    if (link.ok) {
      socket.executable = link.content.replace(/ \(deleted\)$/, "") || null;
    }
  }
}

function unsupportedInventory(platform: string, generatedAt: string): ServerInventory {
  const note = `inspection is only implemented for Linux; detected platform "${platform}"`;
  const unsupported = <T>(): Section<T> => ({ status: "unsupported", data: null, notes: [note] });
  return {
    generatedAt,
    identity: unsupported<IdentityData>(),
    operatingSystem: {
      status: "unsupported",
      data: {
        family: "unknown",
        distribution: null,
        version: null,
        versionId: null,
        kernel: null,
        kernelRelease: null,
      },
      notes: [note],
    },
    network: unsupported<NetworkData>(),
    sockets: unsupported<SocketData>(),
    users: unsupported<UsersData>(),
    privilegedAccess: unsupported<PrivilegedAccessData>(),
    services: unsupported<ServicesData>(),
    packages: unsupported<PackagesData>(),
    securityControls: unsupported<SecurityControlsData>(),
    filesystems: unsupported<FilesystemsData>(),
    time: unsupported<TimeData>(),
    containers: unsupported<ContainersData>(),
  };
}

function erroredInventory(generatedAt: string, cause: unknown): ServerInventory {
  const message = `inspection collector failed: ${cause instanceof Error ? cause.message : String(cause)}`;
  const failed = <T>(): Section<T> => ({ status: "error", data: null, error: message });
  return {
    generatedAt,
    identity: failed<IdentityData>(),
    operatingSystem: failed<OperatingSystemData>(),
    network: failed<NetworkData>(),
    sockets: failed<SocketData>(),
    users: failed<UsersData>(),
    privilegedAccess: failed<PrivilegedAccessData>(),
    services: failed<ServicesData>(),
    packages: failed<PackagesData>(),
    securityControls: failed<SecurityControlsData>(),
    filesystems: failed<FilesystemsData>(),
    time: failed<TimeData>(),
    containers: failed<ContainersData>(),
  };
}

// ---------------------------------------------------------------------------
// Summary (presentation)
// ---------------------------------------------------------------------------

export const ALL_SECTIONS: SectionName[] = [
  "identity",
  "operatingSystem",
  "network",
  "sockets",
  "users",
  "privilegedAccess",
  "services",
  "packages",
  "securityControls",
  "filesystems",
  "time",
  "containers",
];

export interface InventorySummary {
  generatedAt: string;
  hostname: string | null;
  osDistribution: string | null;
  kernelRelease: string | null;
  sectionStatuses: Record<SectionName, CollectionStatus>;
  counts: {
    interfaces: number;
    listeningSockets: number;
    users: number;
    groups: number;
    services: number;
    packages: number;
    mounts: number;
    blockDevices: number;
    containerRuntimes: number;
  };
  gaps: string[];
}

export function summarizeInventory(inventory: ServerInventory): InventorySummary {
  const sectionStatuses = {} as Record<SectionName, CollectionStatus>;
  const gaps: string[] = [];
  for (const name of ALL_SECTIONS) {
    const section = inventory[name];
    sectionStatuses[name] = section.status;
    if (section.status !== "success") gaps.push(`${name}: ${section.status}`);
    for (const note of section.notes ?? []) gaps.push(`${name}: ${note}`);
  }

  return {
    generatedAt: inventory.generatedAt,
    hostname: inventory.identity.data?.hostname ?? null,
    osDistribution: inventory.operatingSystem.data?.distribution ?? null,
    kernelRelease: inventory.operatingSystem.data?.kernelRelease ?? null,
    sectionStatuses,
    counts: {
      interfaces: inventory.network.data?.interfaces.length ?? 0,
      listeningSockets: inventory.sockets.data?.sockets.length ?? 0,
      users: inventory.users.data?.users.length ?? 0,
      groups: inventory.users.data?.groups.length ?? 0,
      services: inventory.services.data?.services.length ?? 0,
      packages: inventory.packages.data?.packages.length ?? 0,
      mounts: inventory.filesystems.data?.mounts.length ?? 0,
      blockDevices: inventory.filesystems.data?.blockDevices.length ?? 0,
      containerRuntimes: inventory.containers.data?.runtimes.length ?? 0,
    },
    gaps,
  };
}

export function formatSummary(summary: InventorySummary): string {
  const lines: string[] = [];
  lines.push(`hostname: ${summary.hostname ?? "(unknown)"}`);
  lines.push(`os: ${summary.osDistribution ?? "(unknown)"}`);
  lines.push(`kernel: ${summary.kernelRelease ?? "(unknown)"}`);
  lines.push("collection status:");
  for (const [name, status] of Object.entries(summary.sectionStatuses)) {
    lines.push(`  ${name}: ${status}`);
  }
  lines.push("detected:");
  lines.push(`  interfaces: ${summary.counts.interfaces}`);
  lines.push(`  listening sockets: ${summary.counts.listeningSockets}`);
  lines.push(`  users: ${summary.counts.users} · groups: ${summary.counts.groups}`);
  lines.push(`  services: ${summary.counts.services}`);
  lines.push(`  packages: ${summary.counts.packages}`);
  lines.push(`  mounts: ${summary.counts.mounts} · block devices: ${summary.counts.blockDevices}`);
  lines.push(`  container runtimes: ${summary.counts.containerRuntimes}`);
  if (summary.gaps.length > 0) {
    lines.push("gaps:");
    for (const gap of summary.gaps) lines.push(`  - ${gap}`);
  }
  return lines.join("\n");
}
