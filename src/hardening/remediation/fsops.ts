/**
 * Filesystem operations for remediation, performed on the TARGET host.
 *
 * Backups live on the target (content + hash + owner/group/mode), so rollback
 * works even though the agent runs on the workstation, and secrets are not
 * pulled to the workstation unnecessarily.
 */
import { createHash } from "node:crypto";
import path from "node:path";
import { StateError } from "../errors";
import type { BackupRecord } from "../models";
import { newBackupId } from "../store";
import { validateBackupRecord } from "../validation";
import type { RemediationContext } from "./types";

export function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

/** Read a config file: unprivileged first, then privileged when available. */
export async function readConfig(ctx: RemediationContext, file: string): Promise<string | null> {
  const plain = await ctx.host.readText(file);
  if (plain.ok) return plain.content;
  if (ctx.sudo || ctx.hasRoot) {
    const privileged = await ctx.host.readTextPrivileged(file);
    if (privileged.ok) return privileged.content;
  }
  return null;
}

export async function readText(ctx: RemediationContext, file: string): Promise<string | null> {
  const read = await ctx.host.readText(file);
  return read.ok ? read.content : null;
}

export async function writeConfig(
  ctx: RemediationContext,
  file: string,
  content: string,
  mode = 0o644,
): Promise<void> {
  await ctx.host.writeTextPrivileged(file, content, mode);
}

export async function deleteConfig(ctx: RemediationContext, file: string): Promise<void> {
  await ctx.host.removePrivileged(file);
}

export async function configExists(ctx: RemediationContext, file: string): Promise<boolean> {
  return ctx.host.exists(file);
}

export async function listDir(ctx: RemediationContext, dir: string): Promise<string[]> {
  const read = await ctx.host.readDir(dir);
  return read.ok ? read.names : [];
}

function backupFilePath(backupDir: string, backupId: string): string {
  return path.posix.join(backupDir, `${backupId}.json`);
}

/** Read a target file and persist a BackupRecord ON THE TARGET. */
export async function createBackup(
  ctx: Pick<RemediationContext, "host" | "control" | "now" | "backupDir" | "sudo" | "hasRoot">,
  file: string,
): Promise<BackupRecord> {
  const read =
    ctx.sudo || ctx.hasRoot ? await ctx.host.readTextPrivileged(file) : await ctx.host.readText(file);
  if (!read.ok) {
    throw new StateError(`cannot read ${file} on target for backup`);
  }
  const info = await ctx.host.stat(file);
  const record: BackupRecord = {
    backupId: newBackupId(),
    controlId: ctx.control.controlId,
    originalPath: file,
    createdAt: ctx.now(),
    sha256: sha256Hex(read.content),
    bytes: Buffer.byteLength(read.content, "utf8"),
    mode: info?.mode ?? null,
    uid: info?.uid ?? null,
    gid: info?.gid ?? null,
    content: read.content,
  };
  validateBackupRecord(record);
  if (!ctx.backupDir) throw new StateError("no backup directory available on the target");
  await ctx.host.mkdirpPrivileged(ctx.backupDir);
  await ctx.host.writeTextPrivileged(
    backupFilePath(ctx.backupDir, record.backupId),
    `${JSON.stringify(record, null, 2)}\n`,
    0o600,
  );
  return record;
}

/** Restore a backup recorded on the target, preserving owner and mode. */
export async function restoreBackup(ctx: RemediationContext, backupId: string): Promise<string> {
  if (!ctx.backupDir) throw new StateError("no backup directory available on the target");
  const read = await ctx.host.readTextPrivileged(backupFilePath(ctx.backupDir, backupId));
  if (!read.ok) throw new StateError(`backup ${backupId} is not readable on the target`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(read.content);
  } catch (err) {
    throw new StateError(`backup ${backupId} is corrupt`, { cause: err });
  }
  const backup = validateBackupRecord(parsed);
  await ctx.host.writeTextPrivileged(backup.originalPath, backup.content, backup.mode ?? 0o644);
  if (backup.mode !== null) await ctx.host.chmod(backup.originalPath, backup.mode);
  if (backup.uid !== null && backup.gid !== null)
    await ctx.host.chown(backup.originalPath, backup.uid, backup.gid);
  return backup.originalPath;
}
