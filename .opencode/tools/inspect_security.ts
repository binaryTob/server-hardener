/**
 * inspect_security — read-only hardening assessment of the local host.
 */
import { z } from "zod";
import { assess, formatAssessment, formatControlDetail } from "../../src/hardening/agent";
import { ToolArgumentError } from "../../src/hardening/errors";
import { defaultStoreRoot } from "../../src/hardening/store";

const ALLOWED = ["action", "controlId"] as const;

export default {
  description:
    "Read-only security assessment of the LOCAL host. Groups hardening candidates by tier (SAFE / REVIEW / RISKY), " +
    "lists decision-critical questions and can explain a single control. Applies no changes and produces no numeric score.",
  args: {
    action: z.enum(["assess", "explain"]).optional().describe("'assess' (default) or 'explain'."),
    controlId: z
      .string()
      .regex(/^[A-Z]{2,5}-\d{3}$/)
      .optional()
      .describe("Control to explain (required for 'explain')."),
  },
  async execute(args: { action?: "assess" | "explain"; controlId?: string }) {
    for (const key of Object.keys(args)) {
      if (!(ALLOWED as readonly string[]).includes(key)) {
        throw new ToolArgumentError(`Unexpected argument "${key}".`);
      }
    }
    const assessment = await assess({ storeRoot: defaultStoreRoot() });
    if (args.action === "explain") {
      if (!args.controlId) throw new ToolArgumentError("'explain' requires a controlId.");
      const control = assessment.controls.find((c) => c.controlId === args.controlId);
      if (!control) return `Control ${args.controlId} is not in the catalog.`;
      return formatControlDetail(control);
    }
    return formatAssessment(assessment);
  },
};
