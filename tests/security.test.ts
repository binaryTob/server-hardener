/**
 * Security tests: tools expose bounded arguments, require confirmation and
 * cannot be pointed outside their domain. Path safety for state ids.
 */
import { describe, expect, test } from "bun:test";
import hardenService from "../.opencode/tools/harden_service";
import hardenSsh from "../.opencode/tools/harden_ssh";
import hardenSysctl from "../.opencode/tools/harden_sysctl";
import inspectSecurity from "../.opencode/tools/inspect_security";
import inspectSystem from "../.opencode/tools/inspect_system";
import { controlBelongsToDomain } from "../src/hardening/agent";
import { CommandSafetyError, PathSafetyError, ToolArgumentError } from "../src/hardening/errors";
import { assertSafeCommand, ExecCommandRunner } from "../src/hardening/exec";
import { assertSafeId } from "../src/hardening/store";

describe("tool argument contracts", () => {
  test("inspect_system exposes only 'action'", () => {
    expect(Object.keys(inspectSystem.args)).toEqual(["action"]);
  });

  test("inspect_security exposes action + controlId", () => {
    expect(Object.keys(inspectSecurity.args).sort()).toEqual(["action", "controlId"]);
  });

  test("harden tools expose only bounded arguments", () => {
    for (const tool of [hardenSysctl, hardenSsh, hardenService]) {
      expect(Object.keys(tool.args).sort()).toEqual(["action", "confirm", "controlId", "target"]);
      expect(Object.keys(tool.args)).not.toContain("command");
      expect(Object.keys(tool.args)).not.toContain("path");
    }
  });

  test("unknown arguments are rejected", async () => {
    const execute = hardenSysctl.execute as (args: unknown) => Promise<string>;
    await expect(
      execute({ action: "preview", controlId: "KRN-003", command: "rm -rf /" }),
    ).rejects.toBeInstanceOf(ToolArgumentError);
  });

  test("apply and rollback require confirm:true", async () => {
    const execute = hardenSysctl.execute as (args: unknown) => Promise<string>;
    await expect(execute({ action: "apply", controlId: "KRN-003" })).rejects.toBeInstanceOf(
      ToolArgumentError,
    );
    await expect(execute({ action: "rollback", controlId: "KRN-003" })).rejects.toBeInstanceOf(
      ToolArgumentError,
    );
  });
});

describe("domain confinement", () => {
  test("control ids belong only to their domain", () => {
    expect(controlBelongsToDomain("sysctl", "KRN-003")).toBe(true);
    expect(controlBelongsToDomain("sysctl", "SSH-005")).toBe(false);
    expect(controlBelongsToDomain("ssh", "SSH-002")).toBe(true);
    expect(controlBelongsToDomain("service", "SVC-001")).toBe(true);
    expect(controlBelongsToDomain("logging", "AUD-001")).toBe(true);
    expect(controlBelongsToDomain("logging", "LOG-001")).toBe(true);
    expect(controlBelongsToDomain("filesystem", "FS-001")).toBe(true);
    expect(controlBelongsToDomain("firewall", "FW-001")).toBe(true);
  });
});

describe("command safety", () => {
  test("shell-shaped commands are rejected before execution", () => {
    for (const bad of ["ls; rm -rf /", "/bin/ls", "sh -c whoami", "a b", ""]) {
      expect(() => assertSafeCommand(bad, [])).toThrow(CommandSafetyError);
    }
    expect(() => assertSafeCommand("sysctl", ["-n", "kernel.randomize_va_space"])).not.toThrow();
  });

  test("argv metacharacters are literal (no shell)", async () => {
    const runner = new ExecCommandRunner({ timeoutMs: 5000 });
    const outcome = await runner.run("printf", ["%s", "$(whoami); `id`"]);
    expect(outcome.status).toBe("ok");
    expect(outcome.stdout).toBe("$(whoami); `id`");
  });
});

describe("state path safety", () => {
  test("backup ids cannot escape the store", () => {
    const pattern = /^bkp-[a-z0-9][a-z0-9-]{7,63}$/;
    for (const bad of ["../../etc", "../bkp", "/tmp/bkp", "bkp", "bkp/a"]) {
      expect(() => assertSafeId(bad, pattern, "backup id")).toThrow(PathSafetyError);
    }
    expect(() => assertSafeId("bkp-0123456789abcdef", pattern, "backup id")).not.toThrow();
  });
});
