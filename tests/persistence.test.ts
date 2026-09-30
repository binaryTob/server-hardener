/**
 * Persistence tests: atomic writes, layout, corruption handling, schema
 * version gating, path safety and traversal rejection.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  PathSafetyError,
  StateError,
  UnsupportedSchemaVersionError,
  ValidationFailureError,
} from "../src/hardening/errors";
import { runDiscovery } from "../src/hardening/inventory";
import type { ServerInventory } from "../src/hardening/models";
import {
  inventoryPath,
  listInventories,
  loadInventory,
  parseInventoryDocument,
  readLatestInventory,
  resolveServerDir,
  saveInventory,
  validateAllInventories,
} from "../src/hardening/state";
import { successfulScenario } from "./helpers";

const roots: string[] = [];

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "hardener-test-"));
  roots.push(root);
  return root;
}

afterEach(async () => {
  while (roots.length > 0) {
    const root = roots.pop();
    if (root) await rm(root, { recursive: true, force: true });
  }
});

async function validInventory(): Promise<ServerInventory> {
  const { runner, files } = successfulScenario();
  return runDiscovery({ runner, files, now: () => "2025-01-02T03:04:05.000Z", platform: "linux" });
}

describe("save / load round trip", () => {
  test("persists and reads back an identical inventory", async () => {
    const root = await tempRoot();
    const inventory = await validInventory();
    const target = await saveInventory(root, inventory);
    expect(target).toBe(inventoryPath(root, inventory.serverId));

    const loaded = await loadInventory(root, inventory.serverId);
    expect(loaded).toEqual(inventory);
  });

  test("creates the full per-server directory layout", async () => {
    const root = await tempRoot();
    const inventory = await validInventory();
    await saveInventory(root, inventory);
    const dir = resolveServerDir(root, inventory.serverId);
    const entries = (await readdir(dir)).sort();
    expect(entries).toEqual(
      ["changes", "exceptions", "inventory.json", "plans", "rollbacks", "verification"].sort(),
    );
  });

  test("writes no temporary files behind", async () => {
    const root = await tempRoot();
    const inventory = await validInventory();
    await saveInventory(root, inventory);
    const dir = resolveServerDir(root, inventory.serverId);
    const entries = await readdir(dir);
    expect(entries.some((e) => e.includes(".tmp-"))).toBe(false);
  });

  test("file permissions are restrictive (owner-only)", async () => {
    const root = await tempRoot();
    const inventory = await validInventory();
    await saveInventory(root, inventory);
    const info = await stat(inventoryPath(root, inventory.serverId));
    // 0o600 & 0o077 should be zero: no group/other access.
    expect(info.mode & 0o077).toBe(0);
  });
});

describe("corruption and versioning", () => {
  test("corrupt JSON produces an explicit StateError", async () => {
    const root = await tempRoot();
    const inventory = await validInventory();
    await saveInventory(root, inventory);
    await writeFile(inventoryPath(root, inventory.serverId), "{ not json", "utf8");
    await expect(loadInventory(root, inventory.serverId)).rejects.toBeInstanceOf(StateError);
  });

  test("incompatible schemaVersion produces UnsupportedSchemaVersionError", async () => {
    const root = await tempRoot();
    const inventory = await validInventory();
    await saveInventory(root, inventory);
    const file = inventoryPath(root, inventory.serverId);
    const text = await readFile(file, "utf8");
    await writeFile(file, text.replace('"schemaVersion": 1', '"schemaVersion": 999'), "utf8");
    await expect(loadInventory(root, inventory.serverId)).rejects.toBeInstanceOf(
      UnsupportedSchemaVersionError,
    );
  });

  test("structurally invalid document produces ValidationFailureError with paths", async () => {
    const inventory = await validInventory();
    const broken = structuredClone(inventory) as unknown as Record<string, unknown>;
    (broken.services as { status: string }).status = "definitely-not-a-status";
    expect(() => parseInventoryDocument(JSON.stringify(broken))).toThrow(ValidationFailureError);
    try {
      parseInventoryDocument(JSON.stringify(broken));
    } catch (err) {
      expect((err as ValidationFailureError).issues.join(" ")).toContain("services.status");
    }
  });
});

describe("atomic write guarantees", () => {
  test("validation happens before any file is written", async () => {
    const root = await tempRoot();
    const inventory = await validInventory();
    const invalid = structuredClone(inventory);
    // Break a nested field so validation fails.
    (invalid.network.data as { interfaces: unknown }).interfaces = "not-an-array";
    await expect(saveInventory(root, invalid)).rejects.toBeInstanceOf(ValidationFailureError);
    await expect(readdir(root)).resolves.toEqual([]);
  });

  test("a failed write leaves no partial inventory.json", async () => {
    const root = await tempRoot();
    const inventory = await validInventory();
    // Invalid serverId passes validation? No: it fails path safety first.
    const rogue = structuredClone(inventory);
    rogue.serverId = "../../escape";
    await expect(saveInventory(root, rogue)).rejects.toBeInstanceOf(PathSafetyError);
    await expect(readdir(root)).resolves.toEqual([]);
  });
});

describe("path safety", () => {
  const rejected = ["../../etc", "../server", "/tmp/foo", "..", "", "UPPER", "srv a", "a.b"];
  for (const bad of rejected) {
    test(`rejects server id ${JSON.stringify(bad)}`, () => {
      const root = path.join(tmpdir(), "hardener-root");
      expect(() => resolveServerDir(root, bad)).toThrow(PathSafetyError);
    });
  }

  test("accepts a well-formed id and keeps it inside the root", () => {
    const root = path.join(tmpdir(), "hardener-root");
    const dir = resolveServerDir(root, "srv-0123456789abcdef");
    expect(dir.startsWith(path.resolve(root) + path.sep)).toBe(true);
  });
});

describe("listing and validation of state", () => {
  test("lists valid inventories and detects corruption", async () => {
    const root = await tempRoot();
    const first = await validInventory();
    await saveInventory(root, first);
    const second = structuredClone(first);
    second.serverId = "srv-ffffffffffffffff";
    second.inventoryId = "inv-22222222-2222-2222-2222-222222222222";
    second.generatedAt = "2025-02-02T00:00:00.000Z";
    await saveInventory(root, second);

    let listings = await listInventories(root);
    expect(listings).toHaveLength(2);
    expect(listings.every((l) => l.state === "valid")).toBe(true);
    expect(listings[0]?.serverId).toBe("srv-ffffffffffffffff"); // sorted by date

    await writeFile(inventoryPath(root, first.serverId), "{bad", "utf8");
    listings = await listInventories(root);
    const corrupted = listings.find((l) => l.serverId === first.serverId);
    expect(corrupted?.state).toBe("corrupt");

    const results = await validateAllInventories(root);
    expect(results.find((r) => r.serverId === first.serverId)?.valid).toBe(false);
    expect(results.find((r) => r.serverId === second.serverId)?.valid).toBe(true);
  });

  test("readLatestInventory returns the newest valid inventory", async () => {
    const root = await tempRoot();
    const first = await validInventory();
    await saveInventory(root, first);
    const second = structuredClone(first);
    second.serverId = "srv-ffffffffffffffff";
    second.generatedAt = "2025-06-06T00:00:00.000Z";
    await saveInventory(root, second);

    const latest = await readLatestInventory(root);
    expect(latest?.serverId).toBe("srv-ffffffffffffffff");
  });

  test("empty state root yields an empty listing, not an error", async () => {
    const root = await tempRoot();
    await expect(listInventories(root)).resolves.toEqual([]);
    await expect(readLatestInventory(root)).resolves.toBeNull();
  });
});
