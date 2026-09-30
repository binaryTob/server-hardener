/**
 * Risk engine.
 *
 * Risk is assessed separately from applicability and from compliance. It starts
 * from the control's context-independent defaults and lets the control adjust
 * for the operational context. The same control therefore carries different
 * risk on different hosts — by design.
 *
 * No numeric score is produced. Levels are explicit.
 */

import type { ControlDefinition, ControlStateAssessment } from "../controls/types";
import type { OperationalContext, RiskAssessment, ServerInventory } from "../models";

export function assessRisk(
  control: ControlDefinition,
  state: ControlStateAssessment,
  inventory: ServerInventory,
  context: OperationalContext,
): RiskAssessment {
  const base: RiskAssessment = {
    ...control.baseRisk,
    rationale: `default risk profile for ${control.id}`,
  };
  let adjusted = base;
  if (control.adjustRisk) {
    try {
      const patch = control.adjustRisk(inventory, context, state);
      adjusted = {
        securityImpact: patch.securityImpact ?? base.securityImpact,
        availabilityRisk: patch.availabilityRisk ?? base.availabilityRisk,
        lockoutRisk: patch.lockoutRisk ?? base.lockoutRisk,
        operationalComplexity: patch.operationalComplexity ?? base.operationalComplexity,
        rationale: "risk adjusted from operational context",
      };
    } catch (err) {
      adjusted = {
        ...base,
        rationale: `risk adjustment failed, using defaults: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }
  return {
    ...adjusted,
    rationale: `${adjusted.rationale} (impact=${adjusted.securityImpact}, availability=${adjusted.availabilityRisk}, lockout=${adjusted.lockoutRisk}, complexity=${adjusted.operationalComplexity})`,
  };
}
