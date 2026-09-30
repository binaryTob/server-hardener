/**
 * Operational ordering of controls.
 *
 * The order is operational, not severity-based: prerequisites first, then
 * low-risk foundational controls, then visibility, then identity, services and
 * network, and finally the disruptive/access-changing work.
 */
import type { PlanPhase } from "../models";

export const PHASE_ORDER: PlanPhase[] = [
  "prerequisites",
  "foundational",
  "logging-visibility",
  "identity",
  "services",
  "network",
  "access",
  "disruptive",
];

export function phaseIndex(phase: PlanPhase): number {
  const index = PHASE_ORDER.indexOf(phase);
  return index >= 0 ? index : PHASE_ORDER.length;
}
