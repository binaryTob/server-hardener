/**
 * Parsers for users and groups (/etc/passwd, /etc/group, /etc/shadow).
 *
 * Rules:
 * - `locked` is only reported when /etc/shadow was readable; otherwise it is
 *   `unknown`. We never guess lock state.
 * - `accountType` is ALWAYS a derived heuristic: a UID threshold plus an
 *   interactive shell never proves that an account belongs to a human.
 */

import type { LinuxRaw } from "../../collectors/linux";
import type { AccountType, Evidence, InventoryGroup, InventoryUser, Section, UsersData } from "../../models";
import { combinedStatus, fileFailureNote, fileReadStatus, makeSection } from "./shared";

const INTERACTIVE_SHELLS = new Set([
  "/bin/sh",
  "/bin/bash",
  "/bin/dash",
  "/bin/zsh",
  "/bin/fish",
  "/bin/ksh",
  "/usr/bin/sh",
  "/usr/bin/bash",
  "/usr/bin/zsh",
  "/usr/bin/fish",
  "/usr/bin/ksh",
]);

/** Parse /etc/passwd-style lines into raw user entries. */
export interface PasswdEntry {
  name: string;
  uid: number;
  gid: number;
  home: string | null;
  shell: string | null;
}

export function parsePasswd(text: string): { users: PasswdEntry[]; malformed: number } {
  const users: PasswdEntry[] = [];
  let malformed = 0;
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const fields = trimmed.split(":");
    if (fields.length < 7) {
      malformed += 1;
      continue;
    }
    const name = fields[0] ?? "";
    const uid = Number.parseInt(fields[2] ?? "", 10);
    const gid = Number.parseInt(fields[3] ?? "", 10);
    if (!name || !Number.isInteger(uid) || !Number.isInteger(gid)) {
      malformed += 1;
      continue;
    }
    users.push({
      name,
      uid,
      gid,
      home: fields[5] ?? null,
      shell: fields[6] ?? null,
    });
  }
  return { users, malformed };
}

export interface GroupEntry {
  name: string;
  gid: number;
  members: string[];
}

export function parseGroup(text: string): { groups: GroupEntry[]; malformed: number } {
  const groups: GroupEntry[] = [];
  let malformed = 0;
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const fields = trimmed.split(":");
    if (fields.length < 3) {
      malformed += 1;
      continue;
    }
    const name = fields[0] ?? "";
    const gid = Number.parseInt(fields[2] ?? "", 10);
    if (!name || !Number.isInteger(gid)) {
      malformed += 1;
      continue;
    }
    const members = (fields[3] ?? "").split(",").filter((m) => m.length > 0);
    groups.push({ name, gid, members });
  }
  return { groups, malformed };
}

/**
 * Parse /etc/shadow into lock states. Keys are user names; value is true when
 * the password field indicates a locked/disabled account ("!", "!!", "*").
 * `empty` marks accounts with an empty password field (evidence, no judgment).
 */
export function parseShadowLocks(text: string): {
  locked: Map<string, boolean>;
  empty: string[];
  malformed: number;
} {
  const locked = new Map<string, boolean>();
  const empty: string[] = [];
  let malformed = 0;
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const fields = trimmed.split(":");
    if (fields.length < 2 || !fields[0]) {
      malformed += 1;
      continue;
    }
    const pw = fields[1] ?? "";
    if (pw === "") {
      empty.push(fields[0]);
      locked.set(fields[0], false);
      continue;
    }
    locked.set(fields[0], pw.startsWith("!") || pw.startsWith("*"));
  }
  return { locked, empty, malformed };
}

function accountTypeHeuristic(uid: number, shell: string | null): AccountType {
  if (uid === 0) return "system";
  const interactive = shell !== null && INTERACTIVE_SHELLS.has(shell);
  if (uid < 1000) return "system";
  return interactive ? "human-like" : "service";
}

export function parseUsers(raw: LinuxRaw["users"], collectedAt: string): Section<UsersData> {
  const notes: string[] = [];
  const users: InventoryUser[] = [];
  const groups: InventoryGroup[] = [];

  const lockedEvidenceSource = "/etc/shadow";
  let lockedObserved = false;
  let locks = new Map<string, boolean>();
  let emptyPasswords: string[] = [];

  if (raw.shadow.ok) {
    lockedObserved = true;
    const parsed = parseShadowLocks(raw.shadow.content);
    locks = parsed.locked;
    emptyPasswords = parsed.empty;
    if (parsed.malformed > 0) notes.push(`/etc/shadow: ${parsed.malformed} malformed lines skipped`);
    if (emptyPasswords.length > 0) {
      notes.push(
        `/etc/shadow: accounts with an EMPTY password field observed: ${emptyPasswords.join(", ")} (evidence only)`,
      );
    }
  } else {
    const note = fileFailureNote("/etc/shadow", raw.shadow.status);
    if (note) notes.push(note);
  }

  const groupByGid = new Map<number, GroupEntry>();
  if (raw.group.ok) {
    const parsed = parseGroup(raw.group.content);
    if (parsed.malformed > 0) notes.push(`/etc/group: ${parsed.malformed} malformed lines skipped`);
    for (const g of parsed.groups) {
      groupByGid.set(g.gid, g);
      groups.push({ name: g.name, gid: g.gid, members: g.members });
    }
  } else {
    const note = fileFailureNote("/etc/group", raw.group.status);
    if (note) notes.push(note);
  }

  const supplementary = new Map<string, string[]>();
  for (const g of groups) {
    for (const member of g.members) {
      const list = supplementary.get(member) ?? [];
      list.push(g.name);
      supplementary.set(member, list);
    }
  }

  if (raw.passwd.ok) {
    const parsed = parsePasswd(raw.passwd.content);
    if (parsed.malformed > 0) notes.push(`/etc/passwd: ${parsed.malformed} malformed lines skipped`);
    for (const entry of parsed.users) {
      const locked: Evidence<boolean | null> = lockedObserved
        ? {
            value: locks.get(entry.name) ?? null,
            source: lockedEvidenceSource,
            confidence: "observed",
            collectedAt,
          }
        : {
            value: null,
            source: lockedEvidenceSource,
            confidence: "unknown",
            collectedAt,
          };
      users.push({
        name: entry.name,
        uid: entry.uid,
        gid: entry.gid,
        primaryGroup: groupByGid.get(entry.gid)?.name ?? null,
        supplementaryGroups: supplementary.get(entry.name) ?? [],
        shell: entry.shell,
        home: entry.home,
        locked,
        accountType: {
          value: accountTypeHeuristic(entry.uid, entry.shell),
          source: "heuristic(uid>=1000 AND interactive shell => human-like)",
          confidence: "derived",
          collectedAt,
        },
      });
    }
  } else {
    const note = fileFailureNote("/etc/passwd", raw.passwd.status);
    if (note) notes.push(note);
  }

  const status = combinedStatus([
    fileReadStatus(raw.passwd),
    fileReadStatus(raw.group),
    fileReadStatus(raw.shadow),
  ]);

  return makeSection(status, { users, groups }, notes);
}
