/**
 * Execution tests over an in-memory FakeHost: preview, backup, apply, verify,
 * rollback and safety gates. No real host, no SSH.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { reconnectCheck } from "../src/hardening/agent";
import type { ControlEvaluationStatus, EvaluatedControl } from "../src/hardening/models";
import {
  applyControl,
  type ExecuteRequest,
  previewControl,
  rollbackControl,
  verifyControl,
} from "../src/hardening/remediation/run";
import { readLastRun } from "../src/hardening/store";
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

function request(current: ExecEnv, control: EvaluatedControl, targetUnit?: string): ExecuteRequest {
  const base: ExecuteRequest = {
    storeRoot: current.storeRoot,
    host: current.host,
    inventory: current.inventory,
    context: current.context,
    control,
    targetHost: current.host.label,
    hasRoot: true,
    sudo: true,
    now: () => "2025-04-01T00:00:00.000Z",
  };
  if (targetUnit !== undefined) base.target = targetUnit;
  return base;
}

describe("preview is read-only", () => {
  test("SSH preview changes nothing", async () => {
    const current = await env();
    const commands: string[] = [];
    const exec = current.host.exec.bind(current.host);
    current.host.exec = (command, args, options) => {
      commands.push(command);
      return exec(command, args, options);
    };
    const before = current.host.files.get("/etc/ssh/sshd_config");
    const control = withStatus(evaluate("SSH-005", current.inventory, current.context), "non-compliant");
    const outcome = await previewControl(request(current, control));
    expect(outcome.preview?.manual).toBe(false);
    expect(outcome.preview?.desiredState).toContain("MaxAuthTries 4");
    expect(current.host.files.get("/etc/ssh/sshd_config")).toBe(before);
    await verifyControl(request(current, control));
    expect(commands).not.toContain("mkdir");
  });
});

describe("SSH apply / verify / rollback", () => {
  test("apply preserves restrictive config permissions", async () => {
    const current = await env();
    await current.host.chmod("/etc/ssh/sshd_config", 0o600);
    const control = withStatus(evaluate("SSH-005", current.inventory, current.context), "non-compliant");
    await applyControl(request(current, control));
    expect((await current.host.stat("/etc/ssh/sshd_config"))?.mode).toBe(0o600);
  });

  test("tampered backup is rejected before restoring config", async () => {
    const current = await env();
    const control = withStatus(evaluate("SSH-005", current.inventory, current.context), "non-compliant");
    await applyControl(request(current, control));
    const entry = (await readLastRun(current.storeRoot))?.entries.at(-1);
    const file = `${entry?.backupDir}/${entry?.backupIds[0]}.json`;
    const backup = JSON.parse(current.host.files.get(file) ?? "{}");
    backup.content = "tampered fixture content";
    current.host.files.set(file, JSON.stringify(backup));
    const outcome = await rollbackControl(request(current, control));
    expect(outcome.message).toContain("integrity");
    expect(current.host.files.get("/etc/ssh/sshd_config")).toContain("MaxAuthTries 4");
  });

  test("failed fresh connection rolls back even if a listener could remain", async () => {
    const current = await env();
    const control = withStatus(evaluate("SSH-005", current.inventory, current.context), "non-compliant");
    const req = request(current, control);
    await applyControl(req);
    current.host.verifyConnection = async () => ({
      status: "timeout",
      stdout: "",
      stderr: "",
      exitCode: null,
      notRun: false,
      failureKind: "timeout",
    });
    const result = await reconnectCheck(current.host, req);
    expect(result).toContain("Automatic rollback attempted");
    expect(result).toContain("NOT CONFIRMED");
    expect(current.host.files.get("/etc/ssh/sshd_config")).toContain("MaxAuthTries 6");
    expect((await readLastRun(current.storeRoot))?.entries.at(-1)?.action).toBe("rollback");
  }, 10000);

  test("apply edits config, backs it up on the target, verifies and records the run", async () => {
    const current = await env();
    const control = withStatus(evaluate("SSH-005", current.inventory, current.context), "non-compliant");
    const outcome = await applyControl(request(current, control));

    expect(outcome.changed).toBe(true);
    expect(outcome.verification?.passed).toBe(true);
    expect(current.host.files.get("/etc/ssh/sshd_config")).toContain("MaxAuthTries 4");

    const run = await readLastRun(current.storeRoot);
    const entry = run?.entries.at(-1);
    expect(entry?.result).toBe("applied");
    expect(entry?.backupDir).toContain("/var/backups/server-hardener/");
    if (entry?.backupDir && outcome.backupIds[0]) {
      expect(current.host.files.has(`${entry.backupDir}/${outcome.backupIds[0]}.json`)).toBe(true);
    }
  });

  test("rollback restores the previous config from the target backup", async () => {
    const current = await env();
    const control = withStatus(evaluate("SSH-005", current.inventory, current.context), "non-compliant");
    await applyControl(request(current, control));
    const outcome = await rollbackControl(request(current, control));
    expect(outcome.changed).toBe(true);
    expect(current.host.files.get("/etc/ssh/sshd_config")).toContain("MaxAuthTries 6");
  });

  test("sshd -t failure restores the config and keeps no change", async () => {
    const current = await env();
    current.host.sshdSyntaxOk = false;
    const original = current.host.files.get("/etc/ssh/sshd_config");
    const control = withStatus(evaluate("SSH-004", current.inventory, current.context), "non-compliant");
    const outcome = await applyControl(request(current, control));
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("sshd -t failed");
    expect(current.host.files.get("/etc/ssh/sshd_config")).toBe(original);
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
  });
});

describe("SSH-007 removes unauthorized ports", () => {
  test("apply removes Port 22 and keeps the authorized port, then rollback restores it", async () => {
    const current = await env();
    const context = { ...current.context, management: { ...current.context.management, sshPort: 2222 } };
    const control = withStatus(evaluate("SSH-007", current.inventory, context), "non-compliant");
    const includePath = "/etc/ssh/sshd_config.d/90-puertos.conf";

    const applied = await applyControl({ ...request(current, control), context });
    expect(applied.changed).toBe(true);
    const after = current.host.files.get(includePath) ?? "";
    expect(after).toContain("Port 2222");
    expect(after).not.toMatch(/^Port 22$/m);

    const rolled = await rollbackControl({ ...request(current, control), context });
    expect(rolled.changed).toBe(true);
    expect(current.host.files.get(includePath)).toContain("Port 22");
  });
});

describe("sysctl", () => {
  test("apply sets runtime value and persists a managed drop-in", async () => {
    const current = await env();
    const control = withStatus(evaluate("KRN-003", current.inventory, current.context), "non-compliant");
    const outcome = await applyControl(request(current, control));
    expect(current.host.sysctl.get("kernel.randomize_va_space")).toBe("2");
    expect(current.host.files.get("/etc/sysctl.d/99-server-hardener.conf")).toContain(
      "kernel.randomize_va_space = 2",
    );
    expect(outcome.verification?.passed).toBe(true);
  });
});

describe("services", () => {
  test("disable + stop a target service and roll back", async () => {
    const current = await env();
    current.host.services.set("telnet.socket", { enabled: true, active: true });
    const control = withStatus(evaluate("SVC-001", current.inventory, current.context), "non-compliant");
    await applyControl(request(current, control, "telnet.socket"));
    expect(current.host.services.get("telnet.socket")).toEqual({ enabled: false, active: false });
    const rolled = await rollbackControl(request(current, control, "telnet.socket"));
    expect(rolled.changed).toBe(true);
    expect(current.host.services.get("telnet.socket")).toEqual({ enabled: true, active: true });
  });
});

describe("firewall safety", () => {
  test("firewalld activation is manual until zone-aware access is implemented", async () => {
    const current = await env();
    const inventory = structuredClone(current.inventory);
    if (inventory.securityControls.data?.firewall)
      inventory.securityControls.data.firewall.detectedImplementations = ["firewalld"];
    const control = withStatus(evaluate("FW-001", inventory, current.context), "non-compliant");
    const outcome = await applyControl({ ...request(current, control), inventory });
    expect(outcome.changed).toBe(false);
    expect(current.host.firewalldState).toBe("not running");
  });

  test("failed administrative allow rule prevents firewall activation", async () => {
    const current = await env();
    const inventory = structuredClone(current.inventory);
    if (inventory.securityControls.data?.firewall)
      inventory.securityControls.data.firewall.detectedImplementations = ["ufw"];
    const exec = current.host.exec.bind(current.host);
    current.host.exec = (command, args, options) =>
      command === "ufw" && args[0] === "allow"
        ? Promise.resolve({
            status: "error",
            stdout: "",
            stderr: "fixture failure",
            exitCode: 1,
            notRun: false,
          })
        : exec(command, args, options);
    const control = withStatus(evaluate("FW-001", inventory, current.context), "non-compliant");
    const outcome = await applyControl({ ...request(current, control), inventory });
    expect(outcome.changed).toBe(false);
    expect(current.host.ufwStatusText).toBe("Status: inactive");
  });

  test("nftables is never changed automatically", async () => {
    const current = await env();
    const inventory = structuredClone(current.inventory);
    if (inventory.securityControls.data?.firewall)
      inventory.securityControls.data.firewall.detectedImplementations = ["nftables"];
    const control = withStatus(evaluate("FW-001", inventory, current.context), "non-compliant");
    const outcome = await applyControl({ ...request(current, control), inventory });
    expect(outcome.changed).toBe(false);
  });

  test("ufw allows the configured administrative port, not 22 by default", async () => {
    const current = await env();
    const inventory = structuredClone(current.inventory);
    if (inventory.securityControls.data?.firewall) {
      inventory.securityControls.data.firewall.detectedImplementations = ["ufw"];
    }
    const context = { ...current.context, management: { ...current.context.management, sshPort: 2222 } };
    const control = withStatus(evaluate("FW-001", inventory, context), "non-compliant");
    const preview = await previewControl({ ...request(current, control), inventory, context });
    expect(preview.preview?.commands.join(" ")).toContain("ufw allow 2222/tcp");
  });

  test("ufw is enabled without closing administrative access", async () => {
    const current = await env();
    const inventory = structuredClone(current.inventory);
    if (inventory.securityControls.data?.firewall)
      inventory.securityControls.data.firewall.detectedImplementations = ["ufw"];
    const control = withStatus(evaluate("FW-001", inventory, current.context), "non-compliant");
    const outcome = await applyControl({ ...request(current, control), inventory });
    expect(current.host.ufwStatusText).toContain("active");
    expect(outcome.verification?.passed).toBe(true);
  });
});

describe("filesystem", () => {
  test("FS-001 adds safe options to fstab after a target backup", async () => {
    const current = await env();
    const control = withStatus(evaluate("FS-001", current.inventory, current.context), "requires-review");
    const outcome = await applyControl(request(current, control));
    expect(outcome.changed).toBe(true);
    expect(current.host.files.get("/etc/fstab")).toContain("nodev");
    expect(outcome.backupIds.length).toBe(1);
  });
});

describe("safety gates", () => {
  test("non-actionable control is refused", async () => {
    const current = await env();
    const control = evaluate("KRN-003", current.inventory, current.context); // unknown
    const outcome = await applyControl(request(current, control));
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("refusing to apply");
  });

  test("apply without root/sudo is refused", async () => {
    const current = await env();
    const control = withStatus(evaluate("KRN-003", current.inventory, current.context), "non-compliant");
    const outcome = await applyControl({ ...request(current, control), hasRoot: false, sudo: false });
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("administrative privileges");
  });

  test("connection failure is reported before any change", async () => {
    const current = await env();
    current.host.connectionOk = false;
    const control = withStatus(evaluate("KRN-003", current.inventory, current.context), "non-compliant");
    const outcome = await applyControl(request(current, control));
    expect(outcome.changed).toBe(false);
    expect(outcome.message).toContain("host key");
  });

  test("verify returns a verification result", async () => {
    const current = await env();
    const control = withStatus(evaluate("SSH-005", current.inventory, current.context), "non-compliant");
    await applyControl(request(current, control));
    const outcome = await verifyControl(request(current, control));
    expect(outcome.verification?.verificationId.startsWith("ver-")).toBe(true);
  });
});
