/**
 * Applicability engine tests: applicable / not-applicable / unknown /
 * unsupported / requires-context.
 */
import { describe, expect, test } from "bun:test";
import { decideApplicability } from "../src/hardening/planning/applicability";
import { emptyContext } from "../src/hardening/planning/context";
import { evaluateControl } from "../src/hardening/planning/evaluate";
import { clone, mustControl, sampleContext, sampleInventory } from "./planning-helpers";

describe("platform gating", () => {
  test("non-Linux platform is unsupported", async () => {
    const inventory = clone(await sampleInventory());
    if (inventory.operatingSystem.data) inventory.operatingSystem.data.family = "windows";
    const decision = decideApplicability(mustControl("SSH-001"), inventory, sampleContext());
    expect(decision.status).toBe("unsupported");
  });

  test("unknown platform family is unknown", async () => {
    const inventory = clone(await sampleInventory());
    if (inventory.operatingSystem.data) inventory.operatingSystem.data.family = "unknown";
    const decision = decideApplicability(mustControl("SSH-001"), inventory, sampleContext());
    expect(decision.status).toBe("unknown");
  });
});

describe("SSH applicability", () => {
  test("applicable when an SSH server is present", async () => {
    const decision = decideApplicability(mustControl("SSH-001"), await sampleInventory(), sampleContext());
    expect(decision.status).toBe("applicable");
  });

  test("not-applicable when no SSH server is detected", async () => {
    const inventory = clone(await sampleInventory());
    if (inventory.securityControls.data?.sshServer) {
      inventory.securityControls.data.sshServer.available = false;
    }
    const decision = decideApplicability(mustControl("SSH-001"), inventory, sampleContext());
    expect(decision.status).toBe("not-applicable");
  });

  test("unknown when the security-controls section is unavailable", async () => {
    const inventory = clone(await sampleInventory());
    inventory.securityControls = { status: "unavailable", data: null };
    const decision = decideApplicability(mustControl("SSH-001"), inventory, sampleContext());
    expect(decision.status).toBe("unknown");
  });
});

describe("missing evidence becomes unknown or requires-context", () => {
  test("SSH config not collected -> SSH-001 is not claimed compliant/non-compliant", async () => {
    const evaluated = evaluateControl(mustControl("SSH-001"), await sampleInventory(), sampleContext());
    expect(evaluated.status).toBe("unknown");
    expect(evaluated.currentState).toBeNull();
    expect(evaluated.evidence.some((e) => e.observed === null && e.note)).toBe(true);
  });

  test("no host firewall detected -> FW-002 requires context", async () => {
    const inventory = clone(await sampleInventory());
    if (inventory.securityControls.data?.firewall) {
      inventory.securityControls.data.firewall.detectedImplementations = [];
      inventory.securityControls.data.firewall.implementation.value = null;
    }
    const evaluated = evaluateControl(
      mustControl("FW-002"),
      inventory,
      emptyContext("srv-x", "2025-01-01T00:00:00.000Z"),
    );
    expect(evaluated.status).toBe("requires-context");
    expect(evaluated.missingContext).toContain("internetExposure");
  });

  test("ID-001 reports non-compliant when duplicate UID 0 exists", async () => {
    const inventory = clone(await sampleInventory());
    const users = inventory.users.data?.users;
    if (users) {
      users.push({
        name: "root2",
        uid: 0,
        gid: 0,
        primaryGroup: "root",
        supplementaryGroups: [],
        shell: "/bin/bash",
        home: "/root2",
        locked: { value: false, confidence: "observed", source: "/etc/shadow", collectedAt: "t" },
        accountType: { value: "system", confidence: "derived", source: "heuristic", collectedAt: "t" },
      });
    }
    const evaluated = evaluateControl(mustControl("ID-001"), inventory, sampleContext());
    expect(evaluated.status).toBe("non-compliant");
    expect(evaluated.currentState).toContain("2 accounts with UID 0");
  });
});
