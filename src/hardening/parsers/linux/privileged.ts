/**
 * Parsers for privileged access discovery.
 *
 * Never reads or persists sudoers file CONTENTS (they can encode sensitive
 * policy like NOPASSWD entries): only path existence is recorded. Never runs
 * sudo interactively or attempts privilege escalation.
 */

import type { LinuxRaw } from "../../collectors/linux";
import type { AdminGroup, PrivilegedAccessData, Section, SudoersFileRef, UsersData } from "../../models";
import { auxiliaryStatus, combinedStatus, makeSection, stdoutOf } from "./shared";

const ADMIN_GROUP_NAMES = ["wheel", "sudo", "adm", "disk", "admin"];

export function parsePrivilegedAccess(
  raw: LinuxRaw["privilegedAccess"],
  users: UsersData | null,
): Section<PrivilegedAccessData> {
  const notes: string[] = [];

  const rootAccountExists = users ? users.users.some((u) => u.uid === 0) || null : null;

  const administrativeGroups: AdminGroup[] = [];
  if (users) {
    for (const group of users.groups) {
      if (ADMIN_GROUP_NAMES.includes(group.name)) {
        administrativeGroups.push({ name: group.name, gid: group.gid, members: group.members });
      }
    }
  } else {
    notes.push("administrative groups could not be determined (users data unavailable)");
  }

  const sudoAvailable = raw.sudoBinary !== null || raw.sudoVersion.outcome.status === "ok";
  const versionMatch = /Sudo version (\S+)/.exec(stdoutOf(raw.sudoVersion.outcome));
  const sudoVersion = versionMatch ? (versionMatch[1] ?? null) : null;

  const sudoersFiles: SudoersFileRef[] = [
    { path: "/etc/sudoers", exists: raw.sudoersMainExists, kind: "main" },
  ];
  if (raw.sudoersDir.ok) {
    for (const name of raw.sudoersDir.names.sort()) {
      if (name.endsWith(".rpmsave") || name.endsWith(".rpmnew")) continue;
      sudoersFiles.push({ path: `/etc/sudoers.d/${name}`, exists: true, kind: "drop-in" });
    }
  } else {
    notes.push("/etc/sudoers.d: contents could not be listed");
  }
  if (!sudoAvailable) notes.push("sudo binary not detected on PATH");

  const status = combinedStatus([
    auxiliaryStatus(raw.sudoVersion.outcome),
    raw.sudoersDir.ok ? "success" : "partial",
    users ? "success" : "unavailable",
  ]);

  return makeSection(
    status,
    {
      rootAccountExists,
      administrativeGroups,
      sudo: { available: sudoAvailable, version: sudoVersion },
      sudoersFiles,
    },
    notes,
  );
}
