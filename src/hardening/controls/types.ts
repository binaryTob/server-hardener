/**
 * Control definition contract.
 *
 * A `ControlDefinition` is CODE, not data: applicability, state assessment,
 * risk adjustment and preconditions are pure functions over
 * (ServerInventory, OperationalContext). Nothing here executes commands or
 * touches the host — evaluation is fully evidence-based and deterministic.
 *
 * The serializable result of evaluating a definition is an `EvaluatedControl`.
 */
import type {
  ApplicabilityDecision,
  ControlCategory,
  ControlEvaluationStatus,
  EvidenceRef,
  OperationalContext,
  OSFamily,
  RiskAssessment,
  RiskLevel,
  ServerInventory,
} from "../models";

/** Result of assessing the control's current state from evidence. */
export interface ControlStateAssessment {
  /**
   * One of: compliant, non-compliant, unknown, requires-review,
   * requires-context, error. Applicability/blocked are decided by the engine.
   */
  status: Extract<
    ControlEvaluationStatus,
    "compliant" | "non-compliant" | "unknown" | "requires-review" | "requires-context" | "error"
  >;
  currentState: string | null;
  evidence: EvidenceRef[];
  missingContext: string[];
  rationale: string;
}

/** Default, context-independent risk profile of applying the control. */
export interface ControlRiskDefaults {
  securityImpact: RiskLevel;
  availabilityRisk: RiskLevel;
  lockoutRisk: RiskLevel;
  operationalComplexity: RiskLevel;
}

/** A single precondition's pure check result. */
export interface PreconditionCheck {
  status: "satisfied" | "unsatisfied" | "unknown";
  evidence: EvidenceRef[];
  missingContext: string[];
  reason: string | null;
}

/** A precondition declared by a control, evaluated by the engine. */
export interface PreconditionSpec {
  id: string;
  description: string;
  /** When true and not satisfied, the control is blocked (not just risky). */
  critical: boolean;
  check: (inventory: ServerInventory, context: OperationalContext) => PreconditionCheck;
}

export interface ControlDefinition {
  id: string;
  title: string;
  category: ControlCategory;
  /** OS families this control is designed for. */
  platform: OSFamily[];
  description: string;
  rationale: string;
  desiredState: string;
  requiresApproval: boolean;
  reversible: boolean;
  /** Other control ids that should be considered first. */
  dependencies: string[];
  tags: string[];
  references: string[];
  baseRisk: ControlRiskDefaults;
  applicability: (inventory: ServerInventory, context: OperationalContext) => ApplicabilityDecision;
  assess: (inventory: ServerInventory, context: OperationalContext) => ControlStateAssessment;
  /** Optional context-sensitive risk adjustment on top of `baseRisk`. */
  adjustRisk?: (
    inventory: ServerInventory,
    context: OperationalContext,
    state: ControlStateAssessment,
  ) => Partial<RiskAssessment>;
  preconditions?: (inventory: ServerInventory, context: OperationalContext) => PreconditionSpec[];
}
