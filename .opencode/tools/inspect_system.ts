/**
 * inspect_system — read-only summary of the local host.
 */
import { z } from "zod";
import { assess, formatSystemInspection, lastRunSummary } from "../../src/hardening/agent";
import { ToolArgumentError } from "../../src/hardening/errors";
import { defaultStoreRoot } from "../../src/hardening/store";

const ALLOWED = ["action"] as const;

export default {
  description:
    "Read-only inspection of the LOCAL host (the machine running OpenCode). Reports OS, detected services, " +
    "listening sockets, users, packages, firewall/logging state and collection gaps. Never modifies anything.",
  args: {
    action: z.enum(["inspect", "last-run"]).optional().describe("'inspect' (default) or 'last-run'."),
  },
  async execute(args: { action?: "inspect" | "last-run" }) {
    for (const key of Object.keys(args)) {
      if (!(ALLOWED as readonly string[]).includes(key)) {
        throw new ToolArgumentError(`Unexpected argument "${key}".`);
      }
    }
    if (args.action === "last-run") {
      return lastRunSummary(defaultStoreRoot());
    }
    const assessment = await assess({ storeRoot: defaultStoreRoot() });
    return formatSystemInspection(assessment.inventory);
  },
};
