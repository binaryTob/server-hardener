/**
 * Phase 3 execution tests: preview, backup, apply, verify, rollback, SSH
 * syntax failure, sysctl, service change, firewall safety and refusal to apply
 * controls the plan did not approve.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import executeTool from "../.opencode/tools/hardening_execute";
import { ToolArgumentError } from "../src/hardening/errors";
import { getRemediation } from "../src/hardening/remediation/registry";
import {
  applyControl,
  type ExecuteRequest,
  previewControl,
  rollbackControl,
  verifyControl,
} from "../src/hardening/remediation/run";
import { loadBackup, readLatestChange } from "../src/hardening/state";
import { cleanupExecEnv, type ExecEnv, makeExecEnv, withStatus } from "./execution-helpers";

const envs: ExecEnv[] = [];
async function env(): Promise<ExecEnv> {
  const created = await makeExecEnv();
  envs.push(created);
  return created;
}
afterEach(async () => {
  while (envs.length > 0) {
    const current = envs.pop();
    if (current) await cleanupExecEnv(current);
  }
});

function request(current: ExecEnv, plan = current.plan, controlId: string, target?: string): ExecuteRequest {
  const base: ExecuteRequest = {
    stateRoot: current.stateRoot,
    serverId: current.inventory.serverId,
    inventory: current.inventory,
    context: current.context,
    plan,
    controlId,
    runner: current.runner,
    paths: current.paths,
    hasRoot: true,
    now: () => "2025-04-01T00:00:00.000Z",
  };
  if (target !== undefined) base.target = target;
  return base;
}

describe("preview is read-only", () => {
  test("SSH preview changes nothing and reports the planned edit", async () => {
    const current = await env();
    const before = await readFile(current.paths.sshdConfig, "utf8");
    const outcome = await previewControl(
      request(current, withStatus(current.plan, "SSH-005", "non-compliant"), "SSH-005"),
    );
    expect(outcome.preview?.manual).toBe(false);
    expect(outcome.preview?.desiredState).toContain("MaxAuthTries 4");
    expect((await readFile(current.paths.sshdConfig, "utf8")) === before).toBe(true);
  });
});

describe("SSH apply / verify / rollback", () => {
  test("apply edits sshd_config, backs it up, verifies and records the change", async () => {
    const current = await env();
    const plan = withStatus(current.plan, "SSH-005", "non-compliant");
    const outcome = await applyControl(request(current, plan, "SSH-005"));

    expect(outcome.changed).toBe(true);
    expect(outcome.verification?.passed).toBe(true);
    expect(await readFile(current.paths.sshdConfig, "utf8")).toContain("MaxAuthTries 4");

    const backup = await loadBackup(
      current.stateRoot,
      current.inventory.serverId,
      outcome.backupIds[0] ?? "",
    );
    expect(backup.originalPath).toBe(current.paths.sshdConfig);
    expect(backup.content).toContain("MaxAuthTries 6");
    expect(backup.sha256.length).toBe(64);

    const change = await readLatestChange(current.stateRoot, current.inventory.serverId, "SSH-005");
    expect(change?.result).toBe("applied");
    expect(change?.rollbackId).not.toBeNull();
  });

  test("rollback restores the previous sshd_config from the backup", async () => {
    const current = await env();
    const plan = withStatus(current.plan, "SSH-005", "non-compliant");
    await applyControl(request(current, plan, "SSH-005"));
    expect(await readFile(current.paths.sshdConfig, "utf8")).toContain("MaxAuthTries 4");

    const outcome = await rollbackControl(request(current, plan, "SSH-005"));
    expect(outcome.changed).toBe(true);
    expect(await readFile(current.paths.sshdConfig, "utf8")).toContain("MaxAuthTries 6");
  });

  test("sshd -t failure restores the backup and keeps no change", async () => {
    const current = await env();
    current.runner.sshdSyntaxOk = false;
    const plan = withStatus(current.plan, "SSH-004", "non-compliant");
    const original = await readFile(current.paths.sshdConfig, "utf8");

    const outcome = await applyControl(request(current, plan, "SSH-004"));
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("sshd -t failed");
    expect(await readFile(current.paths.sshdConfig, "utf8")).toBe(original);
  });

  test("disabling SSH password auth is refused without a confirmed secondary path", async () => {
    const current = await env();
    const plan = withStatus(current.plan, "SSH-002", "non-compliant");
    const context = {
      ...current.context,
      management: { ...current.context.management, secondaryPathConfirmed: false },
    };
    const outcome = await applyControl({ ...request(current, plan, "SSH-002"), context });
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("secondary management path");
    expect(await readFile(current.paths.sshdConfig, "utf8")).toContain("PasswordAuthentication yes");
  });
});

describe("sysctl apply and rollback", () => {
  test("KRN-003 sets the runtime value and persists a managed drop-in", async () => {
    const current = await env();
    const plan = withStatus(current.plan, "KRN-003", "non-compliant");
    const outcome = await applyControl(request(current, plan, "KRN-003"));

    expect(outcome.changed).toBe(true);
    expect(current.runner.sysctl.get("kernel.randomize_va_space")).toBe("2");
    expect(await readFile(current.paths.sysctlManagedFile, "utf8")).toContain(
      "kernel.randomize_va_space = 2",
    );
    expect(outcome.verification?.passed).toBe(true);
  });

  test("sysctl rollback restores the previous runtime value", async () => {
    const current = await env();
    const plan = withStatus(current.plan, "KRN-003", "non-compliant");
    await applyControl(request(current, plan, "KRN-003"));
    await rollbackControl(request(current, plan, "KRN-003"));
    expect(current.runner.sysctl.get("kernel.randomize_va_space")).toBe("0");
  });
});

describe("service change", () => {
  test("SVC-001 disables and stops the requested service", async () => {
    const current = await env();
    current.runner.services.set("telnet.socket", { enabled: true, active: true });
    const plan = withStatus(current.plan, "SVC-001", "non-compliant");
    const outcome = await applyControl(request(current, plan, "SVC-001", "telnet.socket"));

    expect(outcome.changed).toBe(true);
    expect(current.runner.services.get("telnet.socket")).toEqual({ enabled: false, active: false });
    expect(outcome.verification?.passed).toBe(true);
  });

  test("service rollback re-enables a previously enabled service", async () => {
    const current = await env();
    current.runner.services.set("telnet.socket", { enabled: true, active: true });
    const plan = withStatus(current.plan, "SVC-001", "non-compliant");
    await applyControl(request(current, plan, "SVC-001", "telnet.socket"));
    await rollbackControl(request(current, plan, "SVC-001", "telnet.socket"));
    expect(current.runner.services.get("telnet.socket")).toEqual({ enabled: true, active: true });
  });
});

describe("firewall safety", () => {
  test("nftables is never changed automatically", async () => {
    const current = await env();
    const inventory = structuredClone(current.inventory);
    if (inventory.securityControls.data?.firewall) {
      inventory.securityControls.data.firewall.detectedImplementations = ["nftables"];
    }
    const plan = withStatus(current.plan, "FW-001", "non-compliant");
    const preview = await previewControl({ ...request(current, plan, "FW-001"), inventory });
    expect(preview.preview?.manual).toBe(true);
    const outcome = await applyControl({ ...request(current, plan, "FW-001"), inventory });
    expect(outcome.changed).toBe(false);
  });

  test("ufw is enabled only after allowing the SSH port", async () => {
    const current = await env();
    const inventory = structuredClone(current.inventory);
    if (inventory.securityControls.data?.firewall) {
      inventory.securityControls.data.firewall.detectedImplementations = ["ufw"];
    }
    const plan = withStatus(current.plan, "FW-001", "non-compliant");
    const outcome = await applyControl({ ...request(current, plan, "FW-001"), inventory });
    expect(current.runner.ufwStatusText).toContain("active");
    expect(outcome.verification?.passed).toBe(true);
  });
});

describe("filesystem fstab change", () => {
  test("FS-001 adds nodev,nosuid to /tmp fstab entry after backup", async () => {
    const current = await env();
    const plan = withStatus(current.plan, "FS-001", "requires-review");
    const outcome = await applyControl(request(current, plan, "FS-001"));
    expect(outcome.changed).toBe(true);
    const fstab = await readFile(current.paths.fstab, "utf8");
    expect(fstab).toContain("/tmp ext4");
    expect(fstab).toContain("nodev");
    expect(fstab).toContain("nosuid");
    expect(outcome.backupIds.length).toBe(1);
  });
});

describe("safety gates", () => {
  test("a control the plan did not approve is refused", async () => {
    const current = await env();
    const outcome = await applyControl(request(current, current.plan, "KRN-003")); // plan status unknown
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("refusing to apply");
  });

  test("apply without root is refused", async () => {
    const current = await env();
    const plan = withStatus(current.plan, "KRN-003", "non-compliant");
    const outcome = await applyControl({ ...request(current, plan, "KRN-003"), hasRoot: false });
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("requires root");
  });

  test("manual-only controls preview as manual and never apply", async () => {
    const current = await env();
    const remediation = getRemediation("NET-001");
    expect(remediation.manual).toBe(true);
    const preview = await previewControl(
      request(current, withStatus(current.plan, "NET-001", "requires-review"), "NET-001"),
    );
    expect(preview.preview?.manual).toBe(true);
  });
});

describe("hardening_execute tool contracts", () => {
  const execute = executeTool.execute as (args: unknown) => Promise<string>;

  test("arguments are bounded (no shell, no unknown keys)", async () => {
    await expect(
      execute({ action: "preview", controlId: "SSH-005", command: "rm -rf /" }),
    ).rejects.toBeInstanceOf(ToolArgumentError);
  });

  test("unknown actions are rejected", async () => {
    await expect(execute({ action: "run" })).rejects.toBeInstanceOf(ToolArgumentError);
  });

  test("apply and rollback require confirm:true", async () => {
    await expect(execute({ action: "apply", controlId: "SSH-005" })).rejects.toBeInstanceOf(
      ToolArgumentError,
    );
    await expect(execute({ action: "rollback", controlId: "SSH-005" })).rejects.toBeInstanceOf(
      ToolArgumentError,
    );
  });
});

describe("verification records", () => {
  test("verify returns a persisted verification result", async () => {
    const current = await env();
    const plan = withStatus(current.plan, "SSH-005", "non-compliant");
    await applyControl(request(current, plan, "SSH-005"));
    const outcome = await verifyControl(request(current, plan, "SSH-005"));
    expect(outcome.verification?.verificationId.startsWith("ver-")).toBe(true);
  });
});
