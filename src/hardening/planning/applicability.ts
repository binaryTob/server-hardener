/**
 * Applicability engine.
 *
 * Decides whether a control applies to this host before any state is read.
 * Platform gating happens here so individual controls never have to repeat it.
 * Pure: no commands, no host access.
 */

import { ref } from "../controls/helpers";
import type { ControlDefinition } from "../controls/types";
import type { ApplicabilityDecision, OperationalContext, ServerInventory } from "../models";

export function decideApplicability(
  control: ControlDefinition,
  inventory: ServerInventory,
  context: OperationalContext,
): ApplicabilityDecision {
  const family = inventory.operatingSystem.data?.family ?? "unknown";
  try {
    if (family === "unknown") {
      return {
        status: "unknown",
        rationale: `the operating system family could not be determined (control targets ${control.platform.join("/")})`,
        evidence: [ref("operatingSystem.data.family", null)],
        missingContext: [],
        confidence: "unknown",
      };
    }
    if (!control.platform.includes(family)) {
      return {
        status: "unsupported",
        rationale: `control targets ${control.platform.join("/")}; this host is ${family}`,
        evidence: [ref("operatingSystem.data.family", family)],
        missingContext: [],
        confidence: "observed",
      };
    }
    return control.applicability(inventory, context);
  } catch (err) {
    return {
      status: "unknown",
      rationale: `applicability evaluation failed: ${err instanceof Error ? err.message : String(err)}`,
      evidence: [],
      missingContext: [],
      confidence: "unknown",
    };
  }
}
