/**
 * Parsers for filesystem discovery: findmnt, df, lsblk, /proc/mounts.
 *
 * Mount metadata only: this module never reads file contents under any
 * mountpoint and never walks arbitrary trees.
 */

import type { LinuxRaw } from "../../collectors/linux";
import type { BlockDevice, FilesystemsData, MountInfo, Section } from "../../models";
import { combinedStatus, failureNote, fileFailureNote, makeSection, primaryStatus } from "./shared";

function emptyToNull(value: string | undefined): string | null {
  if (value === undefined) return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/**
 * Parse `findmnt -l -o TARGET,SOURCE,FSTYPE,OPTIONS` output.
 *
 * Columns are padded with spaces, but padding can collapse to a single space
 * when a value fills its column. Parsing from the right keeps mountpoints
 * containing spaces intact: OPTIONS and FSTYPE never contain spaces, so the
 * remainder is the target.
 */
export function parseFindmnt(text: string): { mounts: MountInfo[]; skipped: number } {
  const mounts: MountInfo[] = [];
  let skipped = 0;
  for (const line of text.split("\n")) {
    const trimmed = line.trimEnd();
    if (!trimmed || trimmed.startsWith("TARGET")) continue;
    const parsed = parseFindmntLine(trimmed);
    if (parsed === null) {
      skipped += 1;
      continue;
    }
    mounts.push(parsed);
  }
  return { mounts, skipped };
}

function parseFindmntLine(line: string): MountInfo | null {
  const tokens = line.split(/\s+/);
  if (tokens.length < 4) return null;
  const options = tokens[tokens.length - 1] ?? "";
  const filesystemType = tokens[tokens.length - 2] ?? "";
  const source = tokens[tokens.length - 3] ?? "";
  const mountpoint = tokens.slice(0, tokens.length - 3).join(" ");
  if (!mountpoint) return null;
  return {
    mountpoint: decodePath(mountpoint),
    source: emptyToNull(source),
    filesystemType: emptyToNull(filesystemType),
    mountOptions: options.split(",").filter((o) => o.length > 0),
    capacityBytes: null,
    usedBytes: null,
    availableBytes: null,
    usedPercent: null,
  };
}

/** Parse /proc/mounts fallback: "dev / fstype opts 0 0". */
export function parseProcMounts(text: string): MountInfo[] {
  const mounts: MountInfo[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const fields = trimmed.split(/\s+/);
    if (fields.length < 4) continue;
    const mountpoint = decodePath(fields[1] ?? "");
    if (!mountpoint) continue;
    mounts.push({
      mountpoint,
      source: emptyToNull(fields[0]),
      filesystemType: emptyToNull(fields[2]),
      mountOptions: (fields[3] ?? "").split(",").filter((o) => o.length > 0),
      capacityBytes: null,
      usedBytes: null,
      availableBytes: null,
      usedPercent: null,
    });
  }
  return mounts;
}

/** Decode the octal escape used for spaces in /proc/mounts. */
function decodePath(path: string): string {
  return path.replaceAll("\\040", " ").replaceAll("\\011", "\t");
}

/**
 * Parse `df -l --output=target,source,fstype,size,used,avail,pcent -B1`.
 *
 * The numeric columns are separated by single spaces when values are wide, so
 * the line is parsed from the right: the last five fields are
 * size/used/avail/percent, then fstype and source; the remainder is the target
 * (which may contain spaces).
 */
export function parseDf(text: string): Map<string, Omit<MountInfo, "mountpoint">> {
  const capacities = new Map<string, Omit<MountInfo, "mountpoint">>();
  for (const line of text.split("\n")) {
    const trimmed = line.trimEnd();
    if (!trimmed || trimmed.startsWith("Mounted on") || trimmed.startsWith("Filesystem")) continue;
    const tokens = trimmed.split(/\s+/);
    if (tokens.length < 7) continue;
    const percent = tokens[tokens.length - 1] ?? "";
    const available = parseInteger(tokens[tokens.length - 2]);
    const used = parseInteger(tokens[tokens.length - 3]);
    const capacity = parseInteger(tokens[tokens.length - 4]);
    const filesystemType = tokens[tokens.length - 5] ?? "";
    const source = tokens[tokens.length - 6] ?? "";
    const target = tokens
      .slice(0, tokens.length - 6)
      .join(" ")
      .trim();
    if (!target) continue;
    const percentMatch = /^(\d+)%$/.exec(percent.trim());
    capacities.set(target, {
      source: emptyToNull(source),
      filesystemType: emptyToNull(filesystemType),
      mountOptions: [],
      capacityBytes: capacity,
      usedBytes: used,
      availableBytes: available,
      usedPercent: percentMatch ? Number.parseInt(percentMatch[1] ?? "0", 10) : null,
    });
  }
  return capacities;
}

function parseInteger(value: string | undefined): number | null {
  if (!value) return null;
  const parsed = Number.parseInt(value.trim(), 10);
  return Number.isInteger(parsed) ? parsed : null;
}

interface LsblkDevice {
  name?: string;
  type?: string;
  size?: string;
  fstype?: string | null;
  mountpoint?: string | null;
  children?: LsblkDevice[];
}

/** Parse `lsblk --json` output into a flat block device list. */
export function parseLsblk(text: string): { devices: BlockDevice[]; error: string | null } {
  let parsed: { blockdevices?: LsblkDevice[] };
  try {
    parsed = JSON.parse(text) as { blockdevices?: LsblkDevice[] };
  } catch {
    return { devices: [], error: "lsblk output was not valid JSON" };
  }
  const devices: BlockDevice[] = [];
  const walk = (device: LsblkDevice): void => {
    devices.push({
      name: device.name ?? "",
      type: device.type ?? null,
      size: device.size ?? null,
      filesystemType: device.fstype ?? null,
      mountpoint: device.mountpoint ?? null,
    });
    for (const child of device.children ?? []) walk(child);
  };
  for (const device of parsed.blockdevices ?? []) walk(device);
  return { devices, error: null };
}

export function parseFilesystems(raw: LinuxRaw["filesystems"]): Section<FilesystemsData> {
  const notes: string[] = [];

  let mounts: MountInfo[] = [];
  let mountsStatus: ReturnType<typeof primaryStatus> = "unavailable";
  if (raw.findmnt.outcome.status === "ok") {
    const parsed = parseFindmnt(raw.findmnt.outcome.stdout);
    mounts = parsed.mounts;
    mountsStatus = "success";
    if (parsed.skipped > 0) {
      notes.push(`findmnt: ${parsed.skipped} lines skipped (unparseable)`);
      mountsStatus = "partial";
    }
  } else if (raw.procMounts.ok) {
    mounts = parseProcMounts(raw.procMounts.content);
    mountsStatus = "partial";
    const note = failureNote(raw.findmnt.display, raw.findmnt.outcome);
    if (note) notes.push(note);
    notes.push("mount list parsed from /proc/mounts fallback");
  } else {
    const note = failureNote(raw.findmnt.display, raw.findmnt.outcome);
    if (note) notes.push(note);
    const procNote = fileFailureNote("/proc/mounts", raw.procMounts.status);
    if (procNote) notes.push(procNote);
  }

  if (raw.df.outcome.status === "ok") {
    const capacities = parseDf(raw.df.outcome.stdout);
    for (const mount of mounts) {
      const capacity = capacities.get(mount.mountpoint);
      if (!capacity) continue;
      mount.capacityBytes = capacity.capacityBytes;
      mount.usedBytes = capacity.usedBytes;
      mount.availableBytes = capacity.availableBytes;
      mount.usedPercent = capacity.usedPercent;
    }
  } else {
    const note = failureNote(raw.df.display, raw.df.outcome);
    if (note) notes.push(note);
  }

  let blockDevices: BlockDevice[] = [];
  let lsblkStatus: ReturnType<typeof primaryStatus> = primaryStatus(raw.lsblk.outcome);
  if (raw.lsblk.outcome.status === "ok") {
    const parsed = parseLsblk(raw.lsblk.outcome.stdout);
    blockDevices = parsed.devices;
    if (parsed.error) {
      lsblkStatus = "error";
      notes.push(parsed.error);
    }
  } else {
    const note = failureNote(raw.lsblk.display, raw.lsblk.outcome);
    if (note) notes.push(note);
  }

  const status = combinedStatus([mountsStatus, primaryStatus(raw.df.outcome), lsblkStatus]);
  return makeSection(status, { mounts, blockDevices }, notes);
}
