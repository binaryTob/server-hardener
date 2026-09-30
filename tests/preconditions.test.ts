/**
 * Precondition / dependency engine tests.
 *
 * Covers satisfied / unsatisfied / unknown and the rule that a critical
 * unsatisfied precondition turns a control into `blocked`.
 */
import { describe, expect, test } from "bun:test";
import { emptyContext } from "../src/hardening/planning/context";
import { evaluateControl } from "../src/hardening/planning/evaluate";
import { assessPreconditions } from "../src/hardening/planning/preconditions";
import {
  mustControl,
  sampleContext,
  sampleInventory,
  withoutAdministrativeUsers,
  withUnknownLockState,
} from "./planning-helpers";

describe("precondition statuses", () => {
  test("alternative admin user satisfied on a normal host", async () => {
    const inventory = await sampleInventory();
    const preconditions = assessPreconditions(mustControl("SSH-001"), inventory, sampleContext());
    const precondition = preconditions.find((p) => p.id === "alternative-admin-user");
    expect(precondition?.status).toBe("satisfied");
  });

  test("alternative admin user unsatisfied when no admin account exists", async () => {
    const inventory = withoutAdministrativeUsers(await sampleInventory());
    const preconditions = assessPreconditions(mustControl("SSH-001"), inventory, sampleContext());
    const precondition = preconditions.find((p) => p.id === "alternative-admin-user");
    expect(precondition?.status).toBe("unsatisfied");
  });

  test("alternative admin user unknown when lock state is unreadable", async () => {
    const inventory = withUnknownLockState(await sampleInventory());
    const preconditions = assessPreconditions(mustControl("SSH-001"), inventory, sampleContext());
    const precondition = preconditions.find((p) => p.id === "alternative-admin-user");
    expect(precondition?.status).toBe("unknown");
  });

  test("secondary management path reflects context", async () => {
    const inventory = await sampleInventory();
    const control = mustControl("SSH-001");
    const unknown = assessPreconditions(control, inventory, emptyContext("srv-x", "t")).find(
      (p) => p.id === "secondary-management-path",
    );
    const satisfied = assessPreconditions(
      control,
      inventory,
      sampleContext({ secondaryPathConfirmed: true }),
    ).find((p) => p.id === "secondary-management-path");
    const unsatisfied = assessPreconditions(
      control,
      inventory,
      sampleContext({ secondaryPathConfirmed: false }),
    ).find((p) => p.id === "secondary-management-path");
    expect(unknown?.status).toBe("unknown");
    expect(unknown?.missingContext).toContain("management.secondaryPathConfirmed");
    expect(satisfied?.status).toBe("satisfied");
    expect(unsatisfied?.status).toBe("unsatisfied");
  });
});

describe("blocked outcomes", () => {
  test("critical unsatisfied precondition -> blocked", async () => {
    const inventory = withoutAdministrativeUsers(await sampleInventory());
    const evaluated = evaluateControl(mustControl("SSH-001"), inventory, sampleContext());
    expect(evaluated.status).toBe("blocked");
    expect(evaluated.blockers.some((b) => b.includes("alternative-admin-user"))).toBe(true);
  });

  test("operator reports no secondary path -> blocked", async () => {
    const inventory = await sampleInventory();
    const evaluated = evaluateControl(
      mustControl("SSH-001"),
      inventory,
      sampleContext({ secondaryPathConfirmed: false }),
    );
    expect(evaluated.status).toBe("blocked");
    expect(evaluated.blockers.some((b) => b.includes("secondary-management-path"))).toBe(true);
  });

  test("critical unknown precondition without missing context -> blocked", async () => {
    const inventory = withUnknownLockState(await sampleInventory());
    const evaluated = evaluateControl(
      mustControl("SSH-001"),
      inventory,
      sampleContext({ secondaryPathConfirmed: true, consoleAccess: true }),
    );
    expect(evaluated.status).toBe("blocked");
    expect(evaluated.blockers.some((b) => b.startsWith("unresolved precondition"))).toBe(true);
  });

  test("all critical preconditions satisfied leaves the state-derived status", async () => {
    const inventory = await sampleInventory();
    const evaluated = evaluateControl(
      mustControl("SSH-001"),
      inventory,
      sampleContext({ secondaryPathConfirmed: true, consoleAccess: true }),
    );
    // State is not observable, preconditions are satisfied: unknown, not blocked.
    expect(evaluated.status).toBe("unknown");
    expect(evaluated.blockers).toHaveLength(0);
  });
});
