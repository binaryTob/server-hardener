/**
 * Security tests: the tools must not accept arbitrary shell, unexpected
 * arguments, path traversal or malformed identifiers.
 */
import { describe, expect, test } from "bun:test";
import { tmpdir } from "node:os";
import path from "node:path";
import inventoryTool from "../.opencode/tools/hardening_inventory";
import stateTool from "../.opencode/tools/hardening_state";
import { CommandSafetyError, PathSafetyError, ToolArgumentError } from "../src/hardening/errors";
import { assertSafeCommand, COMMAND_NAME_PATTERN, ExecCommandRunner } from "../src/hardening/exec";
import { deriveServerId, resolveServerDir, SERVER_ID_PATTERN } from "../src/hardening/state";

describe("command safety", () => {
  const rejected = [
    "ls; rm -rf /",
    "/bin/ls",
    "ls -la",
    "sh -c whoami",
    "",
    "a b",
    "$(whoami)",
    "`id`",
    "rm -rf /",
  ];
  for (const command of rejected) {
    test(`rejects unsafe command ${JSON.stringify(command)}`, () => {
      expect(() => assertSafeCommand(command, [])).toThrow(CommandSafetyError);
    });
  }

  test("accepts only bare executable names", () => {
    expect(() => assertSafeCommand("ss", ["-tulpn"])).not.toThrow();
    expect(() => assertSafeCommand("dpkg-query", ["-W"])).not.toThrow();
    expect(COMMAND_NAME_PATTERN.test("systemctl")).toBe(true);
    expect(COMMAND_NAME_PATTERN.test("../../bin/sh")).toBe(false);
  });

  test("rejects NUL bytes in args", () => {
    expect(() => assertSafeCommand("ls", ["a\0b"])).toThrow(CommandSafetyError);
  });

  test("runner never uses a shell: metacharacters are literal args", async () => {
    const runner = new ExecCommandRunner({ timeoutMs: 5000 });
    // Passing metacharacters as argv must not execute them.
    const outcome = await runner.run("printf", ["%s", "$(whoami); `id`"]);
    expect(outcome.status).toBe("ok");
    expect(outcome.stdout).toBe("$(whoami); `id`");
  });

  test("missing binary normalizes to unavailable", async () => {
    const runner = new ExecCommandRunner({ timeoutMs: 5000 });
    const outcome = await runner.run("this-binary-does-not-exist-xyz", []);
    expect(outcome.status).toBe("unavailable");
    expect(outcome.notRun).toBe(true);
  });

  test("timeout is enforced and normalized", async () => {
    const runner = new ExecCommandRunner({ timeoutMs: 150 });
    const outcome = await runner.run("sleep", ["5"]);
    expect(outcome.status).toBe("timeout");
  });
});

describe("server id and path safety", () => {
  const rejected = ["../../etc", "../server", "/tmp/foo", "..", "", "UPPER", "srv a", "srv/x"];
  for (const bad of rejected) {
    test(`rejects unsafe serverId ${JSON.stringify(bad)}`, () => {
      expect(() => resolveServerDir(path.join(tmpdir(), "root"), bad)).toThrow(PathSafetyError);
    });
  }

  test("derived server ids always satisfy the safe pattern", () => {
    const derived = deriveServerId({ machineId: "abc", hostname: "host" });
    expect(SERVER_ID_PATTERN.test(derived.serverId)).toBe(true);
    expect(derived.serverId).toMatch(/^srv-[0-9a-f]{16}$/);
  });

  test("derivation is deterministic and does not leak the machine-id", () => {
    const a = deriveServerId({ machineId: "secret-machine-id", hostname: "h" });
    const b = deriveServerId({ machineId: "secret-machine-id", hostname: "h" });
    expect(a.serverId).toBe(b.serverId);
    expect(a.serverId).not.toContain("secret-machine-id");
    expect(a.stable).toBe(true);
  });

  test("falls back to hostname hash and flags instability", () => {
    const derived = deriveServerId({ machineId: null, hostname: "host-1" });
    expect(derived.stable).toBe(false);
    expect(derived.basis).toBe("hostname-fallback");
    expect(SERVER_ID_PATTERN.test(derived.serverId)).toBe(true);
  });

  test("different identities produce different ids", () => {
    const a = deriveServerId({ machineId: "one", hostname: "h" });
    const b = deriveServerId({ machineId: "two", hostname: "h" });
    expect(a.serverId).not.toBe(b.serverId);
  });
});

describe("tool argument contracts", () => {
  test("inventory tool exposes only bounded arguments", () => {
    expect(Object.keys(inventoryTool.args).sort()).toEqual(["action", "serverId"]);
    expect(typeof inventoryTool.description).toBe("string");
    // No free-form command field exists.
    expect(Object.keys(inventoryTool.args)).not.toContain("command");
    expect(Object.keys(inventoryTool.args)).not.toContain("args");
  });

  test("state tool exposes only bounded arguments", () => {
    expect(Object.keys(stateTool.args).sort()).toEqual(["action", "serverId"]);
    expect(Object.keys(stateTool.args)).not.toContain("command");
  });

  test("inventory tool rejects unexpected arguments", async () => {
    const execute = inventoryTool.execute as (args: unknown) => Promise<string>;
    await expect(execute({ action: "show", command: "rm -rf /" })).rejects.toBeInstanceOf(ToolArgumentError);
    await expect(execute({ action: "show", shell: "bash" })).rejects.toBeInstanceOf(ToolArgumentError);
  });

  test("inventory tool rejects unknown actions", async () => {
    const execute = inventoryTool.execute as (args: unknown) => Promise<string>;
    await expect(execute({ action: "run_shell" })).rejects.toBeInstanceOf(ToolArgumentError);
    await expect(execute({ action: "remediate" })).rejects.toBeInstanceOf(ToolArgumentError);
  });

  test("inventory tool rejects traversal serverIds", async () => {
    const execute = inventoryTool.execute as (args: unknown) => Promise<string>;
    for (const bad of ["../../etc", "../server", "/tmp/foo"]) {
      await expect(execute({ action: "show", serverId: bad })).rejects.toBeInstanceOf(ToolArgumentError);
    }
  });

  test("state tool rejects unexpected arguments and unknown actions", async () => {
    const execute = stateTool.execute as (args: unknown) => Promise<string>;
    await expect(execute({ action: "status", extra: 1 })).rejects.toBeInstanceOf(ToolArgumentError);
    await expect(execute({ action: "delete-everything" })).rejects.toBeInstanceOf(ToolArgumentError);
  });

  test("state tool requires a serverId for load-inventory", async () => {
    const execute = stateTool.execute as (args: unknown) => Promise<string>;
    await expect(execute({ action: "load-inventory" })).rejects.toBeInstanceOf(ToolArgumentError);
  });

  test("state tool rejects traversal serverIds", async () => {
    const execute = stateTool.execute as (args: unknown) => Promise<string>;
    await expect(execute({ action: "load-inventory", serverId: "../../etc" })).rejects.toBeInstanceOf(
      ToolArgumentError,
    );
  });
});
