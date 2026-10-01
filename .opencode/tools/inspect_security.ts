/**
 * inspect_security — read-only hardening assessment of the target server.
 */
import { z } from "zod";
import { assess, formatAssessment, formatControlDetail } from "../../src/hardening/agent";
import { NoTargetError, ToolArgumentError } from "../../src/hardening/errors";
import { defaultStoreRoot } from "../../src/hardening/store";

const ACTIONS = ["assess", "explain"] as const;
const ALLOWED = ["action", "controlId", "target"] as const;

export default {
  description:
    "Read-only security assessment of the TARGET server. Groups hardening candidates by tier (SAFE / REVIEW / RISKY), " +
    "lists decision-critical questions and can explain a single control. Applies no changes and produces no numeric score.",
  args: {
    action: z.enum(ACTIONS).optional().describe("'assess' (default) or 'explain'."),
    controlId: z
      .string()
      .regex(/^[A-Z]{2,5}-\d{3}$/)
      .optional()
      .describe("Control to explain (required for 'explain')."),
    target: z.string().min(1).optional().describe("Override the session target (alias or user@host)."),
  },
  async execute(args: { action?: (typeof ACTIONS)[number]; controlId?: string; target?: string }) {
    for (const key of Object.keys(args)) {
      if (!(ALLOWED as readonly string[]).includes(key)) {
        throw new ToolArgumentError(`Unexpected argument "${key}".`);
      }
    }
    const storeRoot = defaultStoreRoot();
    let assessment: Awaited<ReturnType<typeof assess>>;
    try {
      assessment = await assess(args.target ? { storeRoot, target: args.target } : { storeRoot });
    } catch (err) {
      if (err instanceof NoTargetError) return err.message;
      throw err;
    }
    if (args.action === "explain") {
      if (!args.controlId) throw new ToolArgumentError("'explain' requires a controlId.");
      const control = assessment.controls.find((c) => c.controlId === args.controlId);
      if (!control) return `Control ${args.controlId} is not in the catalog.`;
      return formatControlDetail(control);
    }
    return formatAssessment(assessment);
  },
};
