/**
 * Local state tests: session, last-run and optional context.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { StateError, ValidationFailureError } from "../src/hardening/errors";
import {
  appendLastRun,
  clearSession,
  defaultStoreRoot,
  newBackupId,
  readContext,
  readLastRun,
  readSession,
  saveContext,
  writeSession,
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

describe("defaults", () => {
  test("store lives under .server-hardener", () => {
    expect(defaultStoreRoot("/srv")).toBe("/srv/.server-hardener");
  });
});

describe("session", () => {
  test("round-trips and clears", async () => {
    const root = await tempRoot();
    expect(await readSession(root)).toBeNull();
    await writeSession(root, {
      target: "admin@server.example",
      connectedAt: "2025-04-01T00:00:00.000Z",
      hostname: "admin@server.example",
      root: false,
      sudo: true,
      isLocalhost: false,
    });
    const session = await readSession(root);
    expect(session?.target).toBe("admin@server.example");
    await clearSession(root);
    expect(await readSession(root)).toBeNull();
  });
});

describe("last-run", () => {
  test("records entries with host, target and backupDir", async () => {
    const root = await tempRoot();
    expect(await readLastRun(root)).toBeNull();
    await appendLastRun(
      root,
      {
        at: "2025-04-01T00:00:00.000Z",
        host: "admin@server.example",
        controlId: "SSH-005",
        action: "apply",
        target: "/etc/ssh/sshd_config",
        result: "applied",
        changed: true,
        message: "done",
        before: null,
        after: null,
        backupDir: "/var/backups/server-hardener/run-1",
        verification: { check: "c", expected: "e", observed: "o", passed: true },
        backupIds: [newBackupId()],
      },
      { hostname: "server", evaluated: 39 },
    );
    const run = await readLastRun(root);
    expect(run?.entries[0]?.host).toBe("admin@server.example");
    expect(run?.entries[0]?.backupDir).toContain("/var/backups/server-hardener/");
  });
});

describe("optional context", () => {
  test("missing context returns null; saved context round-trips", async () => {
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

describe("layout", () => {
  test("store root file is written atomically", async () => {
    const root = await tempRoot();
    await writeSession(root, {
      target: "localhost",
      connectedAt: "t",
      hostname: "localhost",
      root: false,
      sudo: false,
      isLocalhost: true,
    });
    const text = await readFile(path.join(root, "session.json"), "utf8");
    expect(text).toContain('"target": "localhost"');
  });
});
