/**
 * target — select and inspect the server-hardener target for this session.
 *
 * The agent runs on the operator workstation; the target is the Linux server it
 * administers over SSH. No target is ever assumed: without one, other tools ask.
 */
import { z } from "zod";
import { type AgentDeps, connectTarget, describeTargetInfo } from "../../src/hardening/agent";
import { NoTargetError, TargetValidationError, ToolArgumentError } from "../../src/hardening/errors";
import { clearSession, defaultStoreRoot, readSession } from "../../src/hardening/store";

const ACTIONS = ["connect", "info", "clear"] as const;
const ALLOWED = ["action", "target"] as const;

export default {
  description:
    "Select the target Linux server for this session (over SSH from this workstation). " +
    "Actions: 'connect' (validate + connect + remember), 'info' (show the active target), 'clear'. " +
    "Accepts an ssh alias, user@host or user@IP. Never assumes localhost.",
  args: {
    action: z.enum(ACTIONS).describe("connect | info | clear."),
    target: z
      .string()
      .min(1)
      .optional()
      .describe("Target: ssh alias, user@host or user@IP (required for 'connect')."),
  },
  async execute(args: { action: (typeof ACTIONS)[number]; target?: string }) {
    for (const key of Object.keys(args)) {
      if (!(ALLOWED as readonly string[]).includes(key)) {
        throw new ToolArgumentError(`Unexpected argument "${key}".`);
      }
    }
    const storeRoot = defaultStoreRoot();
    const deps: AgentDeps = { storeRoot };

    if (args.action === "connect") {
      if (!args.target) throw new ToolArgumentError("'connect' requires a target.");
      try {
        const result = await connectTarget(storeRoot, args.target, deps);
        return [result.connectionMessage, "", describeTargetInfo(result.info.target, result.info)].join("\n");
      } catch (err) {
        if (err instanceof TargetValidationError || err instanceof NoTargetError) return err.message;
        throw err;
      }
    }

    if (args.action === "clear") {
      await clearSession(storeRoot);
      return "Session target cleared.";
    }

    const session = await readSession(storeRoot);
    if (!session) return "No target selected. Use action 'connect' with a target (alias or user@host).";
    return describeTargetInfo(session.target, session);
  },
};
