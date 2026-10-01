/**
 * inspect_system — read-only summary of the target server (over SSH).
 */
import { z } from "zod";
import { type AgentDeps, assess, lastRunSummary } from "../../src/hardening/agent";
import { NoTargetError, ToolArgumentError } from "../../src/hardening/errors";
import { defaultStoreRoot } from "../../src/hardening/store";

const ACTIONS = ["inspect", "last-run"] as const;
const ALLOWED = ["action", "target"] as const;

export default {
  description:
    "Read-only inspection of the TARGET server (this workstation connects over SSH). Reports OS, detected " +
    "services, listening sockets, users, packages, firewall/logging state and collection gaps. Never modifies " +
    "anything. Uses the session target unless one is given; never assumes localhost.",
  args: {
    action: z.enum(ACTIONS).optional().describe("'inspect' (default) or 'last-run'."),
    target: z.string().min(1).optional().describe("Override the session target (alias or user@host)."),
  },
  async execute(args: { action?: (typeof ACTIONS)[number]; target?: string }) {
    for (const key of Object.keys(args)) {
      if (!(ALLOWED as readonly string[]).includes(key)) {
        throw new ToolArgumentError(`Unexpected argument "${key}".`);
      }
    }
    const storeRoot = defaultStoreRoot();
    if (args.action === "last-run") return lastRunSummary(storeRoot);
    const deps: AgentDeps = { storeRoot };
    try {
      const assessment = await assess(args.target ? { ...deps, target: args.target } : deps);
      return assessment.inventorySummary;
    } catch (err) {
      if (err instanceof NoTargetError) return err.message;
      throw err;
    }
  },
};
