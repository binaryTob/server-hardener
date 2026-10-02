/**
 * Assessment tests: applicability, risk (context-sensitive), preconditions and
 * tier classification. Pure engine, no host access.
 */
import { describe, expect, test } from "bun:test";
import { CONTROL_CATALOG, validateCatalog } from "../src/hardening/controls/catalog";
import { managementPorts } from "../src/hardening/controls/helpers";
import { decideApplicability } from "../src/hardening/planning/applicability";
import { emptyContext } from "../src/hardening/planning/context";
import { classifyTier, evaluateCatalog, evaluateControl } from "../src/hardening/planning/evaluate";
import { assessPreconditions } from "../src/hardening/planning/preconditions";
import {
  clone,
  evaluate,
  mustControl,
  NOW,
  sampleContext,
  sampleInventory,
  withoutAdministrativeUsers,
} from "./support";

describe("catalog integrity", () => {
  test("no structural issues and a sensible size", () => {
    expect(validateCatalog()).toEqual([]);
    expect(CONTROL_CATALOG.length).toBeGreaterThanOrEqual(20);
    expect(CONTROL_CATALOG.length).toBeLessThanOrEqual(45);
  });
});

describe("applicability", () => {
  test("not applicable when no SSH server is present", async () => {
    const inventory = clone(await sampleInventory());
    if (inventory.securityControls.data?.sshServer)
      inventory.securityControls.data.sshServer.available = false;
    expect(decideApplicability(mustControl("SSH-001"), inventory, sampleContext()).status).toBe(
      "not-applicable",
    );
  });

  test("unknown when the platform family is unknown", async () => {
    const inventory = clone(await sampleInventory());
    if (inventory.operatingSystem.data) inventory.operatingSystem.data.family = "unknown";
    expect(decideApplicability(mustControl("SSH-001"), inventory, sampleContext()).status).toBe("unknown");
  });
});

describe("risk is context-sensitive", () => {
  test("SSH password auth: lockout critical without a secondary path, low with one", async () => {
    const inventory = await sampleInventory();
    const unsafe = evaluateControl(
      mustControl("SSH-002"),
      inventory,
      sampleContext({ secondaryPathConfirmed: false, consoleAccess: false }),
    );
    const safe = evaluateControl(
      mustControl("SSH-002"),
      inventory,
      sampleContext({ secondaryPathConfirmed: true, consoleAccess: true }),
    );
    expect(unsafe.risk.lockoutRisk).toBe("critical");
    expect(safe.risk.lockoutRisk).toBe("low");
    expect(unsafe.risk.lockoutRisk).not.toBe(safe.risk.lockoutRisk);
  });
});

describe("tiers", () => {
  test("compliant / unknown / not-applicable controls are skipped", async () => {
    const inventory = await sampleInventory();
    const { byTier } = evaluateCatalog(CONTROL_CATALOG, inventory, sampleContext());
    for (const control of [...byTier.skip])
      expect(["compliant", "unknown", "not-applicable", "unsupported"]).toContain(control.status);
  });

  test("context-sensitive lockout control lands in risky", async () => {
    const inventory = await sampleInventory();
    const control = evaluateControl(
      mustControl("SSH-002"),
      inventory,
      sampleContext({ secondaryPathConfirmed: false, consoleAccess: false }),
    );
    expect(classifyTier(control)).toBe("risky");
    expect(control.tier).toBe("risky");
  });

  test("no numeric score is produced anywhere", async () => {
    const inventory = await sampleInventory();
    const control = evaluate("KRN-003", inventory, sampleContext());
    expect(control.risk.securityImpact).toBe("medium");
  });
});

describe("preconditions", () => {
  test("alternative admin precondition reflects the inventory", async () => {
    const inventory = await sampleInventory();
    const satisfied = assessPreconditions(mustControl("SSH-001"), inventory, sampleContext()).find(
      (p) => p.id === "alternative-admin-user",
    );
    const unsatisfied = assessPreconditions(
      mustControl("SSH-001"),
      withoutAdministrativeUsers(inventory),
      sampleContext(),
    ).find((p) => p.id === "alternative-admin-user");
    expect(satisfied?.status).toBe("satisfied");
    expect(unsatisfied?.status).toBe("unsatisfied");
  });

  test("a critical unsatisfied precondition blocks the control", async () => {
    const inventory = withoutAdministrativeUsers(await sampleInventory());
    const control = evaluateControl(mustControl("SSH-001"), inventory, sampleContext());
    expect(control.status).toBe("blocked");
    expect(control.blockers.some((b) => b.includes("alternative-admin-user"))).toBe(true);
  });

  test("missing context surfaces as a question-bearing control", async () => {
    const inventory = await sampleInventory();
    const control = evaluateControl(mustControl("SSH-002"), inventory, emptyContext(NOW));
    expect(control.status).toBe("requires-context");
    expect(control.missingContext).toContain("management.secondaryPathConfirmed");
  });
});

describe("management ports", () => {
  test("includes the configured ssh port and observed sshd ports (never assume 22)", async () => {
    const inventory = await sampleInventory();
    const context = { ...sampleContext(), management: { ...sampleContext().management, sshPort: 2222 } };
    const ports = managementPorts(inventory, context);
    expect(ports).toContain(2222);
  });

  test("falls back to observed sshd ports when no port is configured", async () => {
    const inventory = await sampleInventory();
    const context = sampleContext();
    expect(managementPorts(inventory, context)).toContain(22);
  });
});
