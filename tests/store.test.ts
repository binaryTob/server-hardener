/**
 * Local store tests: backups (content + metadata), last-run and optional context.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { PathSafetyError, StateError, ValidationFailureError } from "../src/hardening/errors";
import type { BackupRecord } from "../src/hardening/models";
import {
  appendLastRun,
  assertSafeId,
  clearLastRun,
  defaultStoreRoot,
  listBackups,
  loadBackup,
  newBackupId,
  readContext,
  readLastRun,
  saveBackup,
  saveContext,
} from "../src/hardening/store";
import { sampleContext } from "./support";

const roots: string[] = [];
async function tempRoot(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "hardener-store-"));
  roots.push(root);
  return root;
}
afterEach(async () => {
  while (roots.length > 0) {
    const root = roots.pop();
    if (root) await rm(root, { recursive: true, force: true });
  }
});

function backup(overrides: Partial<BackupRecord> = {}): BackupRecord {
  return {
    backupId: newBackupId(),
    controlId: "SSH-005",
    originalPath: "/etc/ssh/sshd_config",
    createdAt: "2025-04-01T00:00:00.000Z",
    sha256: "a".repeat(64),
    bytes: 12,
    mode: 0o644,
    uid: 0,
    gid: 0,
    content: "MaxAuthTries 6\n",
    ...overrides,
  };
}

describe("defaults", () => {
  test("store lives under .server-hardener", () => {
    expect(defaultStoreRoot("/srv")).toBe("/srv/.server-hardener");
  });
});

describe("backups", () => {
  test("round-trip preserves content and metadata", async () => {
    const root = await tempRoot();
    const record = backup();
    await saveBackup(root, record);
    const loaded = await loadBackup(root, record.backupId);
    expect(loaded).toEqual(record);
    expect((await listBackups(root)).length).toBe(1);
  });

  test("invalid backup is rejected before writing", async () => {
    const root = await tempRoot();
    await expect(saveBackup(root, backup({ bytes: -1 }))).rejects.toBeInstanceOf(ValidationFailureError);
  });

  test("corrupt backup is reported explicitly", async () => {
    const root = await tempRoot();
    const record = backup();
    await saveBackup(root, record);
    await writeFile(path.join(root, "backups", `${record.backupId}.json`), "{bad", "utf8");
    await expect(loadBackup(root, record.backupId)).rejects.toBeInstanceOf(StateError);
  });

  test("traversal backup ids are rejected", () => {
    for (const bad of ["../../etc", "../bkp", "/tmp/bkp", "bkp", "bkp/a"]) {
      expect(() => assertSafeId(bad, /^bkp-[a-z0-9][a-z0-9-]{7,63}$/, "backup id")).toThrow(PathSafetyError);
    }
  });
});

describe("last-run", () => {
  test("starts empty and records entries", async () => {
    const root = await tempRoot();
    expect(await readLastRun(root)).toBeNull();
    await appendLastRun(
      root,
      {
        at: "2025-04-01T00:00:00.000Z",
        controlId: "SSH-005",
        action: "apply",
        target: "/etc/ssh/sshd_config",
        result: "applied",
        changed: true,
        message: "done",
        before: null,
        after: null,
        verification: { check: "c", expected: "e", observed: "o", passed: true },
        backupIds: [],
      },
      { hostname: "srv-01", evaluated: 39 },
    );
    const run = await readLastRun(root);
    expect(run?.entries.length).toBe(1);
    expect(run?.entries[0]?.result).toBe("applied");
    await clearLastRun(root);
    expect(await readLastRun(root)).toBeNull();
  });
});

describe("optional context", () => {
  test("missing context returns null, saved context round-trips", async () => {
    const root = await tempRoot();
    expect(await readContext(root)).toBeNull();
    const context = sampleContext();
    await saveContext(root, context);
    expect(await readContext(root)).toEqual(context);
  });

  test("invalid context is rejected; corrupt context errors", async () => {
    const root = await tempRoot();
    const context = sampleContext();
    await expect(
      saveContext(root, { ...context, environment: "nope" as unknown as typeof context.environment }),
    ).rejects.toBeInstanceOf(ValidationFailureError);
    await saveContext(root, context);
    await writeFile(path.join(root, "optional-context.json"), "{bad", "utf8");
    await expect(readContext(root)).rejects.toBeInstanceOf(StateError);
  });
});

describe("store layout", () => {
  test("backups directory is created", async () => {
    const root = await tempRoot();
    const record = backup();
    await saveBackup(root, record);
    const text = await readFile(path.join(root, "backups", `${record.backupId}.json`), "utf8");
    expect(text).toContain("originalPath");
  });
});
