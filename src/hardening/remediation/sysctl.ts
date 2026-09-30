/**
 * sysctl (kernel) remediation.
 *
 * Persists the desired values in a managed drop-in
 * (/etc/sysctl.d/99-server-hardener.conf) and applies them at runtime with
 * `sysctl -w` (never `sysctl --system`, to avoid touching unrelated settings).
 * Detects conflicting settings in other sysctl files before writing.
 */
import type { VerificationResult } from "../models";
import { newVerificationId } from "../state";
import { buildManagedSysctlFile, removeManagedSysctlBlock, type SysctlEntry } from "./config";
import { createBackup, deleteFile, listDir, readTextOrNull, restoreBackup, writeTextAtomic } from "./fsops";
import type { Remediation, RemediationApplyResult, RemediationContext, RemediationPreview } from "./types";

interface SysctlSpec {
  entries: SysctlEntry[];
}

const SYSCTL_CONTROLS: Record<string, SysctlSpec> = {
  "KRN-001": {
    entries: [
      { key: "net.ipv4.conf.all.accept_source_route", value: "0" },
      { key: "net.ipv4.conf.default.accept_source_route", value: "0" },
    ],
  },
  "KRN-002": {
    entries: [
      { key: "net.ipv4.conf.all.accept_redirects", value: "0" },
      { key: "net.ipv4.conf.default.accept_redirects", value: "0" },
    ],
  },
  "KRN-003": { entries: [{ key: "kernel.randomize_va_space", value: "2" }] },
  "KRN-004": {
    entries: [
      { key: "kernel.kptr_restrict", value: "1" },
      { key: "kernel.yama.ptrace_scope", value: "1" },
      { key: "kernel.dmesg_restrict", value: "1" },
    ],
  },
};

async function readSysctl(ctx: RemediationContext, key: string): Promise<string | null> {
  const outcome = await ctx.runner.run("sysctl", ["-n", key]);
  if (outcome.status !== "ok") return null;
  const value = outcome.stdout.trim().split("\n")[0];
  return value && value.length > 0 ? value : null;
}

/** Keys we manage that are set to a different value in other sysctl files. */
async function findConflicts(
  ctx: RemediationContext,
  keys: string[],
): Promise<{ file: string; key: string; value: string }[]> {
  const conflicts: { file: string; key: string; value: string }[] = [];
  const candidates: string[] = ["/etc/sysctl.conf"];
  for (const name of await listDir(ctx.paths.sysctlConfDir)) {
    if (!name.endsWith(".conf")) continue;
    const full = `${ctx.paths.sysctlConfDir.replace(/\/$/, "")}/${name}`;
    if (full === ctx.paths.sysctlManagedFile) continue;
    candidates.push(full);
  }
  for (const file of candidates) {
    const text = await readTextOrNull(file);
    if (!text) continue;
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) continue;
      const match = /^([\w.]+)\s*=\s*(\S+)/.exec(trimmed);
      if (!match?.[1] || !match[2]) continue;
      const key = match[1];
      if (!keys.includes(key)) continue;
      const desired = SYSCTL_CONTROLS[ctx.control.controlId]?.entries.find((e) => e.key === key)?.value;
      if (desired !== undefined && desired !== match[2]) {
        conflicts.push({ file, key, value: match[2] });
      }
    }
  }
  return conflicts;
}

async function preview(ctx: RemediationContext): Promise<RemediationPreview> {
  const spec = SYSCTL_CONTROLS[ctx.control.controlId];
  if (!spec) throw new Error(`no sysctl spec for ${ctx.control.controlId}`);
  const current: string[] = [];
  const commands: string[] = [];
  for (const entry of spec.entries) {
    const value = await readSysctl(ctx, entry.key);
    current.push(`${entry.key} = ${value ?? "(unavailable)"}`);
    commands.push(`sysctl -w ${entry.key}=${entry.value}`);
  }
  const conflicts = await findConflicts(
    ctx,
    spec.entries.map((e) => e.key),
  );
  const warnings = conflicts.map(
    (c) => `conflicting setting in ${c.file}: ${c.key} = ${c.value} (may override the managed file)`,
  );
  const alreadyCompliant = await isCompliant(ctx);
  return {
    controlId: ctx.control.controlId,
    title: ctx.control.title,
    manual: false,
    manualReason: null,
    currentState: current.join("; "),
    desiredState: spec.entries.map((e) => `${e.key} = ${e.value}`).join("; "),
    steps: [
      alreadyCompliant
        ? "already compliant at runtime; persistence will still be ensured"
        : "apply the values at runtime with sysctl -w",
      `persist them in ${ctx.paths.sysctlManagedFile} (managed block)`,
    ],
    files: [{ path: ctx.paths.sysctlManagedFile, willBackup: true }],
    commands,
    warnings,
    risk: ctx.control.risk,
    requiresRoot: true,
  };
}

async function isCompliant(ctx: RemediationContext): Promise<boolean> {
  const spec = SYSCTL_CONTROLS[ctx.control.controlId];
  if (!spec) return false;
  for (const entry of spec.entries) {
    if ((await readSysctl(ctx, entry.key)) !== entry.value) return false;
  }
  return true;
}

async function verify(ctx: RemediationContext): Promise<VerificationResult> {
  const spec = SYSCTL_CONTROLS[ctx.control.controlId];
  const checks: string[] = [];
  let passed = true;
  for (const entry of spec?.entries ?? []) {
    const value = await readSysctl(ctx, entry.key);
    const ok = value === entry.value;
    if (!ok) passed = false;
    checks.push(`${entry.key}=${value ?? "?"} (expected ${entry.value})`);
  }
  return {
    schemaVersion: 1,
    verificationId: newVerificationId(),
    serverId: ctx.serverId,
    timestamp: ctx.now(),
    target: ctx.control.controlId,
    check: "runtime sysctl values match desired state",
    expected: (spec?.entries ?? []).map((e) => `${e.key}=${e.value}`).join(", "),
    observed: checks.join(", "),
    passed,
    evidence: checks,
    error: null,
  };
}

async function apply(ctx: RemediationContext): Promise<RemediationApplyResult> {
  const spec = SYSCTL_CONTROLS[ctx.control.controlId];
  if (!spec) throw new Error(`no sysctl spec for ${ctx.control.controlId}`);
  const before: Record<string, string | null> = {};
  const backupIds: string[] = [];

  for (const entry of spec.entries) before[entry.key] = await readSysctl(ctx, entry.key);

  const existingManaged = await readTextOrNull(ctx.paths.sysctlManagedFile);
  let backupId: string | null = null;
  if (existingManaged !== null) {
    backupId = (await createBackup(ctx, ctx.paths.sysctlManagedFile)).backupId;
    backupIds.push(backupId);
  }
  const content = buildManagedSysctlFile(existingManaged, spec.entries);
  await writeTextAtomic(ctx.paths.sysctlManagedFile, content);

  let allOk = true;
  for (const entry of spec.entries) {
    const outcome = await ctx.runner.run("sysctl", ["-w", `${entry.key}=${entry.value}`]);
    if (outcome.status !== "ok") allOk = false;
  }

  const verification = await verify(ctx);
  const desiredByKey = new Map(spec.entries.map((e) => [e.key, e.value]));
  const runtimeChanged = Object.entries(before).some(([key, value]) => value !== desiredByKey.get(key));
  const changed = existingManaged !== content || runtimeChanged;
  const after: Record<string, string> = {};
  for (const entry of spec.entries) after[entry.key] = entry.value;

  return {
    changed,
    target: ctx.paths.sysctlManagedFile,
    before: JSON.stringify({ values: before, managedFileBackupId: backupId }),
    after: JSON.stringify({ values: after }),
    backupIds,
    verification,
    strategy: "restore-sysctl-file-and-runtime-values",
    reversible: true,
    message: allOk
      ? "sysctl values applied and persisted"
      : "sysctl file written but runtime application reported errors; verify output",
  };
}

async function rollback(
  ctx: RemediationContext,
  change: import("../models").ChangeRecord,
): Promise<RemediationApplyResult> {
  const before = JSON.parse(change.before ?? "{}") as {
    values?: Record<string, string | null>;
    managedFileBackupId?: string | null;
  };
  if (before.managedFileBackupId) {
    await restoreBackup(ctx.stateRoot, ctx.serverId, before.managedFileBackupId);
  } else {
    const existing = await readTextOrNull(ctx.paths.sysctlManagedFile);
    const { content } = removeManagedSysctlBlock(existing);
    if (content === null) await deleteFile(ctx.paths.sysctlManagedFile);
    else await writeTextAtomic(ctx.paths.sysctlManagedFile, content);
  }
  for (const [key, value] of Object.entries(before.values ?? {})) {
    if (value !== null) await ctx.runner.run("sysctl", ["-w", `${key}=${value}`]);
  }
  const verification = await verify(ctx);
  return {
    changed: true,
    target: ctx.paths.sysctlManagedFile,
    before: null,
    after: change.before,
    backupIds: [],
    verification,
    strategy: "restore-sysctl-file-and-runtime-values",
    reversible: true,
    message: "sysctl state restored from backup",
  };
}

function makeSysctlRemediation(controlId: string): Remediation {
  if (!(controlId in SYSCTL_CONTROLS)) throw new Error(`unknown sysctl control ${controlId}`);
  return {
    controlId,
    requiresRoot: true,
    manual: false,
    manualReason: null,
    preview,
    apply,
    verify,
    rollback,
  };
}

export const sysctlRemediations: Record<string, Remediation> = Object.fromEntries(
  Object.keys(SYSCTL_CONTROLS).map((id) => [id, makeSysctlRemediation(id)]),
);
