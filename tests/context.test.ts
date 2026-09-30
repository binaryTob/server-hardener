/**
 * Operational context tests: construction, validation, role proposals,
 * answer application and persistence.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { StateError, UnsupportedSchemaVersionError, ValidationFailureError } from "../src/hardening/errors";
import {
  applyContextPath,
  contextCompleteness,
  detectRoles,
  emptyContext,
  withDetectedRoles,
} from "../src/hardening/planning/context";
import { contextPath, loadContext, readContext, saveContext } from "../src/hardening/state";
import { validateOperationalContext } from "../src/hardening/validation";
import { clone, sampleContext, sampleInventory } from "./planning-helpers";

const roots: string[] = [];
async function tempRoot(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "hardener-ctx-"));
  roots.push(root);
  return root;
}
afterEach(async () => {
  while (roots.length > 0) {
    const root = roots.pop();
    if (root) await rm(root, { recursive: true, force: true });
  }
});

describe("context model and validation", () => {
  test("an empty context is valid and explicitly unknown", () => {
    const context = emptyContext("srv-0123456789abcdef", "2025-01-01T00:00:00.000Z");
    expect(() => validateOperationalContext(context)).not.toThrow();
    expect(context.environment).toBe("unknown");
    expect(context.management.secondaryPathConfirmed).toBeNull();
    const completeness = contextCompleteness(context);
    expect(completeness.complete).toBe(false);
    expect(completeness.missing).toContain("management.secondaryPathConfirmed");
    expect(completeness.missing).toContain("roles");
  });

  test("invalid values are rejected", () => {
    const base = sampleContext();
    expect(() => validateOperationalContext({ ...base, environment: "prod" })).toThrow(
      ValidationFailureError,
    );
    expect(() =>
      validateOperationalContext({ ...base, networks: { administrative: ["not-cidr"], service: [] } }),
    ).toThrow(ValidationFailureError);
    expect(() => validateOperationalContext({ ...base, extra: true })).toThrow(ValidationFailureError);
  });

  test("partial context is valid and reports its gaps", () => {
    const partial = {
      ...sampleContext(),
      environment: "unknown" as const,
      internetExposure: "unknown" as const,
    };
    expect(() => validateOperationalContext(partial)).not.toThrow();
    const completeness = contextCompleteness(partial);
    expect(completeness.missing).toContain("environment");
    expect(completeness.missing).toContain("internetExposure");
  });
});

describe("applying answers", () => {
  test("sets scalar, boolean and array fields", () => {
    let context = emptyContext("srv-0123456789abcdef", "2025-01-01T00:00:00.000Z");
    context = applyContextPath(context, "environment", "production");
    context = applyContextPath(context, "internetExposure", "direct");
    context = applyContextPath(context, "management.secondaryPathConfirmed", true);
    context = applyContextPath(context, "management.consoleAccess", false);
    context = applyContextPath(context, "networks.administrative", ["10.0.0.0/8"]);
    context = applyContextPath(context, "reboot.maintenanceWindowAvailable", true);
    context = applyContextPath(context, "highAvailability", false);

    expect(context.environment).toBe("production");
    expect(context.management.secondaryPathConfirmed).toBe(true);
    expect(context.management.consoleAccess).toBe(false);
    expect(context.networks.administrative).toEqual(["10.0.0.0/8"]);
    expect(validateOperationalContext(context)).toBeTruthy();
  });

  test("roles become confirmed assignments", () => {
    const context = applyContextPath(sampleContext(), "roles", ["database", "container-host"]);
    expect(context.roles.every((r) => r.confidence === "confirmed")).toBe(true);
    expect(context.roles.map((r) => r.role)).toEqual(["database", "container-host"]);
  });

  test("unknown path and invalid values throw", () => {
    const context = sampleContext();
    expect(() => applyContextPath(context, "management.unknown", true)).toThrow();
    expect(() => applyContextPath(context, "environment", "nope")).toThrow();
    expect(() => applyContextPath(context, "management.consoleAccess", "yes")).toThrow();
  });
});

describe("role detection", () => {
  test("proposes derived roles from evidence without confirming them", async () => {
    const inventory = await sampleInventory();
    const roles = detectRoles(inventory);
    expect(roles.length).toBeGreaterThan(0);
    expect(roles.every((r) => r.confidence === "derived")).toBe(true);
    // The sample inventory runs Docker and containerd.
    expect(roles.map((r) => r.role)).toContain("container-host");
  });

  test("withDetectedRoles adds proposals but never overwrites confirmed roles", async () => {
    const inventory = await sampleInventory();
    const context = sampleContext({ confirmedRoles: ["database"] });
    const merged = withDetectedRoles(context, inventory);
    const database = merged.roles.filter((r) => r.role === "database");
    expect(database).toHaveLength(1);
    expect(database[0]?.confidence).toBe("confirmed");
    expect(merged.roles.some((r) => r.role === "container-host" && r.confidence === "derived")).toBe(true);
  });
});

describe("context persistence", () => {
  test("round-trips through save/load", async () => {
    const root = await tempRoot();
    const context = sampleContext();
    await saveContext(root, context);
    const loaded = await loadContext(root, context.serverId);
    expect(loaded).toEqual(context);
  });

  test("readContext returns null when missing", async () => {
    const root = await tempRoot();
    expect(await readContext(root, "srv-0123456789abcdef")).toBeNull();
  });

  test("corrupt context is reported explicitly", async () => {
    const root = await tempRoot();
    const context = sampleContext();
    await saveContext(root, context);
    await writeFile(contextPath(root, context.serverId), "{not json", "utf8");
    await expect(loadContext(root, context.serverId)).rejects.toBeInstanceOf(StateError);
  });

  test("schema version mismatch is rejected", async () => {
    const root = await tempRoot();
    const context = sampleContext();
    await saveContext(root, context);
    const file = contextPath(root, context.serverId);
    const text = await readFile(file, "utf8");
    await writeFile(file, text.replace('"schemaVersion": 1', '"schemaVersion": 2'), "utf8");
    await expect(loadContext(root, context.serverId)).rejects.toBeInstanceOf(UnsupportedSchemaVersionError);
  });

  test("invalid context is rejected before writing", async () => {
    const root = await tempRoot();
    const context = clone(sampleContext());
    (context as { environment: string }).environment = "invalid";
    await expect(saveContext(root, context)).rejects.toBeInstanceOf(ValidationFailureError);
  });
});
