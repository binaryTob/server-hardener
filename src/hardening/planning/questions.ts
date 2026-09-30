/**
 * Decision-changing question generation.
 *
 * A question is only produced when the engine actually needed missing context
 * to reach a decision, and it is always tied to the controls it unblocks.
 * No wizard, no generic "do you want security?" prompts.
 */
import type { PlanningQuestion, QuestionType } from "../models";
import { MANAGEMENT_METHOD_VALUES, SERVER_ROLE_VALUES } from "./context";

export interface QuestionDefinition {
  prompt: string;
  reason: string;
  type: QuestionType;
  options?: string[];
}

const QUESTION_DEFS: Record<string, QuestionDefinition> = {
  environment: {
    prompt: "Which environment is this server part of?",
    reason: "environment drives criticality and how aggressively controls should be proposed",
    type: "single-choice",
    options: ["production", "staging", "development", "testing", "unknown"],
  },
  criticality: {
    prompt: "How critical is this server to the service?",
    reason: "criticality informs review prioritisation (no numeric scoring is used)",
    type: "single-choice",
    options: ["low", "medium", "high", "critical", "unknown"],
  },
  internetExposure: {
    prompt: "Is this server directly reachable from the Internet?",
    reason: "Internet exposure changes the acceptable exposure of listeners and management services",
    type: "single-choice",
    options: ["direct", "indirect", "none", "unknown"],
  },
  roles: {
    prompt: "Which roles does this server actually fulfil?",
    reason:
      "the detected roles are only proposals; confirming or correcting them is required before service and filesystem decisions",
    type: "multi-choice",
    options: [...SERVER_ROLE_VALUES],
  },
  "management.methods": {
    prompt: "Which methods are used to administer this server?",
    reason: "the available management methods determine whether access-changing controls can be considered",
    type: "multi-choice",
    options: [...MANAGEMENT_METHOD_VALUES],
  },
  "management.secondaryPathConfirmed": {
    prompt: "Is a secondary management path (e.g. bastion, VPN, out-of-band) confirmed and tested?",
    reason: "without a confirmed secondary path, disabling direct administrative access can cause a lockout",
    type: "boolean",
  },
  "management.consoleAccess": {
    prompt: "Is console or out-of-band access available?",
    reason: "console access is the recovery path if remote administration is lost",
    type: "boolean",
  },
  "networks.administrative": {
    prompt: "Which networks are authorised to manage this server (CIDR list)?",
    reason: "management networks are required to judge whether administrative exposure is acceptable",
    type: "cidr-list",
  },
  "networks.service": {
    prompt: "Which networks require service access to this server (CIDR list)?",
    reason: "service networks describe legitimate traffic and inform exposure review",
    type: "cidr-list",
  },
  "reboot.allowed": {
    prompt: "May this server be rebooted as part of maintenance?",
    reason: "some controls require a reboot to take effect",
    type: "boolean",
  },
  "reboot.maintenanceWindowAvailable": {
    prompt: "Is a maintenance window available?",
    reason: "disruptive controls must be schedulable without causing an unplanned outage",
    type: "boolean",
  },
  highAvailability: {
    prompt: "Is this server part of a high-availability cluster?",
    reason: "HA membership can make some controls safe (peers absorb load) or dangerous (shared state)",
    type: "boolean",
  },
  operatorNotes: {
    prompt: "Any operational notes that affect hardening decisions?",
    reason: "captures exceptions such as an application requiring temporary script execution",
    type: "text",
  },
};

export function questionIdForPath(path: string): string {
  return `q-${path.replaceAll(".", "-")}`;
}

export function contextPathForQuestionId(id: string): string | null {
  const entry = Object.keys(QUESTION_DEFS).find((path) => questionIdForPath(path) === id);
  return entry ?? null;
}

export function questionDefinition(path: string): QuestionDefinition | undefined {
  return QUESTION_DEFS[path];
}

/** Map every missing-context path to the controls that need it. */
export function missingContextByPath(
  controls: { controlId: string; missingContext: string[] }[],
): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  for (const control of controls) {
    for (const path of control.missingContext) {
      const set = map.get(path) ?? new Set<string>();
      set.add(control.controlId);
      map.set(path, set);
    }
  }
  return map;
}

/** Build the ordered, deduplicated question list. Unknown paths are skipped. */
export function buildQuestions(pathToControls: Map<string, Set<string>>): PlanningQuestion[] {
  const entries = [...pathToControls.entries()].sort(([a], [b]) => a.localeCompare(b));
  const questions: PlanningQuestion[] = [];
  for (const [path, controls] of entries) {
    const def = QUESTION_DEFS[path];
    if (!def) continue;
    const question: PlanningQuestion = {
      id: questionIdForPath(path),
      prompt: def.prompt,
      reason: def.reason,
      affectedControls: [...controls].sort(),
      type: def.type,
      contextPath: path,
    };
    if (def.options) question.options = def.options;
    questions.push(question);
  }
  return questions;
}
