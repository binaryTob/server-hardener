/**
 * Execution tests: preview, backup, apply, verify, rollback and safety gates.
 * Uses a temporary system tree + stateful fake runner; never touches the host.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import type { ControlEvaluationStatus, EvaluatedControl } from "../src/hardening/models";
import {
  applyControl,
  type ExecuteRequest,
  previewControl,
  rollbackControl,
  verifyControl,
} from "../src/hardening/remediation/run";
import { loadBackup, readLastRun } from "../src/hardening/store";
import { cleanupExecEnv, type ExecEnv, evaluate, makeExecEnv } from "./support";

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

function withStatus(control: EvaluatedControl, status: ControlEvaluationStatus): EvaluatedControl {
  return { ...control, status };
}

function request(current: ExecEnv, control: EvaluatedControl, target?: string): ExecuteRequest {
  const base: ExecuteRequest = {
    storeRoot: current.storeRoot,
    inventory: current.inventory,
    context: current.context,
    control,
    runner: current.runner,
    paths: current.paths,
    hasRoot: true,
    now: () => "2025-04-01T00:00:00.000Z",
  };
  if (target !== undefined) base.target = target;
  return base;
}

describe("preview is read-only", () => {
  test("SSH preview changes nothing and reports the edit", async () => {
    const current = await env();
    const before = await readFile(current.paths.sshdConfig, "utf8");
    const control = withStatus(evaluate("SSH-005", current.inventory, current.context), "non-compliant");
    const outcome = await previewControl(request(current, control));
    expect(outcome.preview?.manual).toBe(false);
    expect(outcome.preview?.desiredState).toContain("MaxAuthTries 4");
    expect(await readFile(current.paths.sshdConfig, "utf8")).toBe(before);
    expect(await readLastRun(current.storeRoot)).toBeNull();
  });
});

describe("SSH apply / verify / rollback", () => {
  test("apply edits config, backs it up, verifies and records the run", async () => {
    const current = await env();
    const control = withStatus(evaluate("SSH-005", current.inventory, current.context), "non-compliant");
    const outcome = await applyControl(request(current, control));

    expect(outcome.changed).toBe(true);
    expect(outcome.verification?.passed).toBe(true);
    expect(await readFile(current.paths.sshdConfig, "utf8")).toContain("MaxAuthTries 4");

    const backup = await loadBackup(current.storeRoot, outcome.backupIds[0] ?? "");
    expect(backup.originalPath).toBe(current.paths.sshdConfig);
    expect(backup.content).toContain("MaxAuthTries 6");
    expect(backup.mode).not.toBeNull();

    const run = await readLastRun(current.storeRoot);
    expect(run?.entries.at(-1)?.result).toBe("applied");
  });

  test("rollback restores the previous config", async () => {
    const current = await env();
    const control = withStatus(evaluate("SSH-005", current.inventory, current.context), "non-compliant");
    await applyControl(request(current, control));
    const outcome = await rollbackControl(request(current, control));
    expect(outcome.changed).toBe(true);
    expect(await readFile(current.paths.sshdConfig, "utf8")).toContain("MaxAuthTries 6");
  });

  test("sshd -t failure restores the backup and keeps no change", async () => {
    const current = await env();
    current.runner.sshdSyntaxOk = false;
    const original = await readFile(current.paths.sshdConfig, "utf8");
    const control = withStatus(evaluate("SSH-004", current.inventory, current.context), "non-compliant");
    const outcome = await applyControl(request(current, control));
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("sshd -t failed");
    expect(await readFile(current.paths.sshdConfig, "utf8")).toBe(original);
  });

  test("disabling SSH password auth is refused without a confirmed secondary path", async () => {
    const current = await env();
    const context = {
      ...current.context,
      management: { ...current.context.management, secondaryPathConfirmed: false },
    };
    const control = withStatus(evaluate("SSH-002", current.inventory, context), "non-compliant");
    const outcome = await applyControl({ ...request(current, control), context });
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("secondary management path");
    expect(await readFile(current.paths.sshdConfig, "utf8")).toContain("PasswordAuthentication yes");
  });
});

describe("sysctl", () => {
  test("apply sets runtime value and persists a managed drop-in", async () => {
    const current = await env();
    const control = withStatus(evaluate("KRN-003", current.inventory, current.context), "non-compliant");
    const outcome = await applyControl(request(current, control));
    expect(current.runner.sysctl.get("kernel.randomize_va_space")).toBe("2");
    expect(await readFile(current.paths.sysctlManagedFile, "utf8")).toContain(
      "kernel.randomize_va_space = 2",
    );
    expect(outcome.verification?.passed).toBe(true);
  });
});

describe("services", () => {
  test("disable and stop a target service, then roll back", async () => {
    const current = await env();
    current.runner.services.set("telnet.socket", { enabled: true, active: true });
    const control = withStatus(evaluate("SVC-001", current.inventory, current.context), "non-compliant");
    const applied = await applyControl(request(current, control, "telnet.socket"));
    expect(applied.changed).toBe(true);
    expect(current.runner.services.get("telnet.socket")).toEqual({ enabled: false, active: false });

    const rolled = await rollbackControl(request(current, control, "telnet.socket"));
    expect(rolled.changed).toBe(true);
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
    const control = withStatus(evaluate("FW-001", inventory, current.context), "non-compliant");
    const outcome = await applyControl({ ...request(current, control), inventory });
    expect(outcome.changed).toBe(false);
  });

  test("ufw is enabled without closing administrative access", async () => {
    const current = await env();
    const inventory = structuredClone(current.inventory);
    if (inventory.securityControls.data?.firewall) {
      inventory.securityControls.data.firewall.detectedImplementations = ["ufw"];
    }
    const control = withStatus(evaluate("FW-001", inventory, current.context), "non-compliant");
    const outcome = await applyControl({ ...request(current, control), inventory });
    expect(current.runner.ufwStatusText).toContain("active");
    expect(outcome.verification?.passed).toBe(true);
  });
});

describe("filesystem", () => {
  test("FS-001 adds safe options to fstab after backup", async () => {
    const current = await env();
    const control = withStatus(evaluate("FS-001", current.inventory, current.context), "requires-review");
    const outcome = await applyControl(request(current, control));
    expect(outcome.changed).toBe(true);
    const fstab = await readFile(current.paths.fstab, "utf8");
    expect(fstab).toContain("nodev");
    expect(fstab).toContain("nosuid");
    expect(outcome.backupIds.length).toBe(1);
  });
});

describe("safety gates", () => {
  test("a control the assessment did not mark as actionable is refused", async () => {
    const current = await env();
    const control = evaluate("KRN-003", current.inventory, current.context); // status unknown
    const outcome = await applyControl(request(current, control));
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("refusing to apply");
  });

  test("apply without root is refused", async () => {
    const current = await env();
    const control = withStatus(evaluate("KRN-003", current.inventory, current.context), "non-compliant");
    const outcome = await applyControl({ ...request(current, control), hasRoot: false });
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("administrative privileges");
  });

  test("manual-only controls never apply", async () => {
    const current = await env();
    const control = withStatus(evaluate("NET-001", current.inventory, current.context), "requires-review");
    const outcome = await applyControl(request(current, control));
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("manual remediation required");
  });

  test("verify returns a persisted-shaped verification result", async () => {
    const current = await env();
    const control = withStatus(evaluate("SSH-005", current.inventory, current.context), "non-compliant");
    await applyControl(request(current, control));
    const outcome = await verifyControl(request(current, control));
    expect(outcome.verification?.verificationId.startsWith("ver-")).toBe(true);
  });
});
