/**
 * Filesystem remediation: add safe mount options to /etc/fstab entries.
 *
 * Only edits fstab (with backup); it never remounts automatically and clearly
 * warns that a remount (or reboot) is required for the change to take effect.
 * Mountpoints that are not present in fstab are left for manual work.
 */
import type { VerificationResult } from "../models";
import { newVerificationId } from "../store";
import { readFstabOptions, setFstabOptions } from "./config";
import { createBackup, readConfig, restoreBackup, writeConfig } from "./fsops";
import type {
  AppliedChange,
  Remediation,
  RemediationApplyResult,
  RemediationContext,
  RemediationPreview,
} from "./types";

const FS_CONTROLS: Record<string, { mountpoint: string; options: string[] }> = {
  "FS-001": { mountpoint: "/tmp", options: ["nodev", "nosuid"] },
  "FS-002": { mountpoint: "/var/tmp", options: ["nodev", "nosuid"] },
};

function spec(ctx: RemediationContext): { mountpoint: string; options: string[] } {
  const found = FS_CONTROLS[ctx.control.controlId];
  if (!found) throw new Error(`no fstab spec for ${ctx.control.controlId}`);
  return found;
}

async function preview(ctx: RemediationContext): Promise<RemediationPreview> {
  const current = spec(ctx);
  const text = await readConfig(ctx, ctx.paths.fstab);
  const options = text ? readFstabOptions(text, current.mountpoint) : null;
  if (options === null) {
    return {
      controlId: ctx.control.controlId,
      title: ctx.control.title,
      manual: true,
      manualReason: `${current.mountpoint} is not present in ${ctx.paths.fstab}; add it manually`,
      currentState: "not present in fstab",
      desiredState: `${current.mountpoint} with ${current.options.join(",")}`,
      steps: [],
      files: [],
      commands: [],
      warnings: [],
      risk: ctx.control.risk,
      requiresRoot: true,
    };
  }
  return {
    controlId: ctx.control.controlId,
    title: ctx.control.title,
    manual: false,
    manualReason: null,
    currentState: `${current.mountpoint}: ${options.join(",")}`,
    desiredState: `${current.mountpoint}: ${[...new Set([...options, ...current.options])].join(",")}`,
    steps: [
      `back up ${ctx.paths.fstab}`,
      `add ${current.options.join(",")} to the ${current.mountpoint} options`,
    ],
    files: [{ path: ctx.paths.fstab, willBackup: true }],
    commands: [],
    warnings: [
      "a remount (or reboot) is required for the new options to take effect; this remediation does NOT remount",
    ],
    risk: ctx.control.risk,
    requiresRoot: true,
  };
}

async function verify(ctx: RemediationContext): Promise<VerificationResult> {
  const current = spec(ctx);
  const text = await readConfig(ctx, ctx.paths.fstab);
  const options = text ? readFstabOptions(text, current.mountpoint) : null;
  const missing = current.options.filter((o) => !(options ?? []).includes(o));
  const passed = options !== null && missing.length === 0;
  return {
    verificationId: newVerificationId(),
    timestamp: ctx.now(),
    target: ctx.paths.fstab,
    check: "fstab entry has the required mount options",
    expected: current.options.join(","),
    observed: options?.join(",") ?? "no entry",
    passed,
    evidence: [`${current.mountpoint}: ${options?.join(",") ?? "not in fstab"}`],
    error: passed ? null : `missing options: ${missing.join(",") || "entry not found"}`,
  };
}

async function apply(ctx: RemediationContext): Promise<RemediationApplyResult> {
  const current = spec(ctx);
  const text = await readConfig(ctx, ctx.paths.fstab);
  if (text === null) {
    return refused(ctx, `${ctx.paths.fstab} is not readable`);
  }
  if (readFstabOptions(text, current.mountpoint) === null) {
    return refused(ctx, `${current.mountpoint} is not present in fstab; add it manually`);
  }
  const backup = await createBackup(ctx, ctx.paths.fstab);
  const { content, previousOptions, changed } = setFstabOptions(text, current.mountpoint, current.options);
  if (changed) await writeConfig(ctx, ctx.paths.fstab, content);
  return {
    changed,
    target: ctx.paths.fstab,
    before: JSON.stringify({
      mountpoint: current.mountpoint,
      options: previousOptions,
      backupId: backup.backupId,
    }),
    after: JSON.stringify({
      mountpoint: current.mountpoint,
      options: desiredOptions(previousOptions, current.options),
    }),
    backupIds: [backup.backupId],
    verification: await verify(ctx),
    strategy: "restore-fstab-from-backup",
    reversible: true,
    message: changed
      ? "fstab updated; a remount or reboot is required to take effect"
      : "fstab already contains the required options",
  };
}

function desiredOptions(previous: string[] | null, add: string[]): string[] {
  return [...new Set([...(previous ?? []), ...add])];
}

async function rollback(ctx: RemediationContext, change: AppliedChange): Promise<RemediationApplyResult> {
  const before = JSON.parse(change.before ?? "{}") as { backupId?: string };
  if (!before.backupId) return refused(ctx, "no fstab backup recorded; manual rollback required");
  await restoreBackup(ctx, before.backupId);
  return {
    changed: true,
    target: ctx.paths.fstab,
    before: change.after,
    after: change.before,
    backupIds: [],
    verification: await verify(ctx),
    strategy: "restore-fstab-from-backup",
    reversible: true,
    message: "fstab restored from backup",
  };
}

function refused(ctx: RemediationContext, reason: string): RemediationApplyResult {
  return {
    changed: false,
    target: ctx.paths.fstab,
    before: null,
    after: null,
    backupIds: [],
    verification: {
      verificationId: newVerificationId(),
      timestamp: ctx.now(),
      target: ctx.control.controlId,
      check: "apply refused",
      expected: ctx.control.desiredState,
      observed: null,
      passed: false,
      evidence: [reason],
      error: reason,
    },
    strategy: null,
    reversible: false,
    message: reason,
  };
}

export const filesystemRemediations: Record<string, Remediation> = Object.fromEntries(
  Object.keys(FS_CONTROLS).map((id) => [
    id,
    {
      controlId: id,
      requiresRoot: true,
      manual: false,
      manualReason: null,
      preview,
      apply,
      verify,
      rollback,
    } satisfies Remediation,
  ]),
);
