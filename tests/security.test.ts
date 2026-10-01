/**
 * Security tests: target validation, safe ssh argv, no arbitrary shell,
 * connection/host-key failure handling, and — critically — that no tool ever
 * assumes localhost implicitly.
 */
import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import hardenSysctl from "../.opencode/tools/harden_sysctl";
import inspectSystem from "../.opencode/tools/inspect_system";
import targetTool from "../.opencode/tools/target";
import { assess, controlBelongsToDomain } from "../src/hardening/agent";
import {
  CommandSafetyError,
  NoTargetError,
  TargetValidationError,
  ToolArgumentError,
} from "../src/hardening/errors";
import { assertSafeCommand, ExecCommandRunner } from "../src/hardening/exec";
import { assertSafeId } from "../src/hardening/store";
import { buildRemoteCommand } from "../src/hardening/transport/quote";
import { buildSshArgv, classifySshFailure } from "../src/hardening/transport/ssh";
import { parseTarget } from "../src/hardening/transport/target";

describe("target validation", () => {
  test("accepts alias, user@host, user@ip and bare host", () => {
    expect(parseTarget("db.example").host).toBe("db.example");
    expect(parseTarget("admin@server.example").user).toBe("admin");
    expect(parseTarget("root@server.example").host).toBe("server.example");
    expect(parseTarget("192.0.2.10").isLocalhost).toBe(false);
    expect(parseTarget("localhost").isLocalhost).toBe(true);
  });

  test("rejects injection and option-shaped targets", () => {
    for (const bad of [
      "-oProxyCommand=evil",
      "user@host; rm -rf /",
      "host && whoami",
      "host`id`",
      "user@host$(id)",
      "a b",
      "user@@host",
      "user@",
      "@host",
      "host|nc",
    ]) {
      expect(() => parseTarget(bad)).toThrow(TargetValidationError);
    }
  });
});

describe("safe ssh argv", () => {
  test("argv is an array; the remote command is quoted", () => {
    const argv = buildSshArgv("admin@server.example", ["cat", "/etc/ssh/sshd_config"], false);
    expect(argv).toContain("--");
    expect(argv.at(-1)).toBe("'cat' '/etc/ssh/sshd_config'");
    expect(argv).toContain("-o");
    expect(argv).toContain("admin@server.example");
  });

  test("sudo uses non-interactive sudo -n", () => {
    const argv = buildSshArgv("admin@server.example", ["sysctl", "-w", "kernel.randomize_va_space=2"], true);
    expect(argv.at(-1)).toBe("sudo -n 'sysctl' '-w' 'kernel.randomize_va_space=2'");
  });

  test("quoting neutralises shell metacharacters in args", () => {
    expect(buildRemoteCommand(["printf", "%s", "$(whoami); `id`"])).toBe("'printf' '%s' '$(whoami); `id`'");
    expect(buildRemoteCommand(["echo", "it's"])).toBe("'echo' 'it'\\''s'");
  });
});

describe("ssh failure classification", () => {
  test("host key, auth, connection and timeout", () => {
    expect(classifySshFailure("Host key verification failed.", false)).toBe("host-key");
    expect(classifySshFailure("Permission denied (publickey).", false)).toBe("auth");
    expect(classifySshFailure("ssh: Could not resolve hostname x", false)).toBe("connection");
    expect(classifySshFailure("", true)).toBe("timeout");
  });
});

describe("no arbitrary shell", () => {
  test("shell-shaped commands are rejected before execution", () => {
    for (const bad of ["ls; rm -rf /", "/bin/ls", "sh -c whoami", "a b", ""]) {
      expect(() => assertSafeCommand(bad, [])).toThrow(CommandSafetyError);
    }
    expect(() => assertSafeCommand("sysctl", ["-n", "kernel.randomize_va_space"])).not.toThrow();
  });

  test("local argv metacharacters are literal", async () => {
    const runner = new ExecCommandRunner({ timeoutMs: 5000 });
    const outcome = await runner.run("printf", ["%s", "$(whoami); `id`"]);
    expect(outcome.status).toBe("ok");
    expect(outcome.stdout).toBe("$(whoami); `id`");
  });
});

describe("never assume localhost", () => {
  test("assess without a target or session asks for one", async () => {
    const storeRoot = await mkdtemp(path.join(tmpdir(), "hardener-notarget-"));
    try {
      await expect(assess({ storeRoot })).rejects.toBeInstanceOf(NoTargetError);
    } finally {
      await rm(storeRoot, { recursive: true, force: true });
    }
  });

  test("target tool exposes only action + target", () => {
    expect(Object.keys(targetTool.args).sort()).toEqual(["action", "target"]);
  });
});

describe("tool argument contracts", () => {
  test("harden tools expose only bounded arguments", () => {
    expect(Object.keys(hardenSysctl.args).sort()).toEqual([
      "action",
      "confirm",
      "controlId",
      "target",
      "targetUnit",
    ]);
    expect(Object.keys(hardenSysctl.args)).not.toContain("command");
  });

  test("inspect_system exposes action + target", () => {
    expect(Object.keys(inspectSystem.args).sort()).toEqual(["action", "target"]);
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
    expect(controlBelongsToDomain("logging", "AUD-001")).toBe(true);
    expect(controlBelongsToDomain("firewall", "FW-001")).toBe(true);
  });
});

describe("state id safety", () => {
  test("backup/verification ids cannot escape the store", () => {
    const pattern = /^(bkp|ver)-[a-z0-9][a-z0-9-]{7,63}$/;
    for (const bad of ["../../etc", "../bkp", "/tmp/bkp", "bkp", "bkp/a"]) {
      expect(() => assertSafeId(bad, pattern, "id")).toThrow();
    }
    expect(() => assertSafeId("bkp-0123456789abcdef", pattern, "id")).not.toThrow();
  });
});
