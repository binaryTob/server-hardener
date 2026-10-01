/**
 * harden_logging — preview/apply/verify/rollback for logging/auditing controls.
 */
import { z } from "zod";
import { domainAction, type HardenDomain } from "../../src/hardening/agent";
import { ToolArgumentError } from "../../src/hardening/errors";
import { defaultStoreRoot } from "../../src/hardening/store";

const DOMAIN: HardenDomain = "logging";
const ACTIONS = ["inspect", "preview", "apply", "verify", "rollback"] as const;
const ALLOWED = ["action", "controlId", "target", "confirm"] as const;

export default {
  description:
    "Manage logging and auditing controls (LOG-*, AUD-*). Applies only predefined, backed-up, verified operations; apply/rollback require confirm:true and run locally.",
  args: {
    action: z.enum(ACTIONS).describe("inspect | preview | apply | verify | rollback."),
    controlId: z
      .string()
      .regex(/^[A-Z]{2,5}-\d{3}$/)
      .optional()
      .describe("Control id (required for preview/apply/verify/rollback)."),
    target: z
      .string()
      .regex(/^[a-zA-Z0-9_.@:-]+\.(service|socket|timer)$/)
      .optional()
      .describe("Optional service unit (service controls)."),
    confirm: z.boolean().optional().describe("Required true for apply/rollback."),
  },
  async execute(args: {
    action: (typeof ACTIONS)[number];
    controlId?: string;
    target?: string;
    confirm?: boolean;
  }) {
    for (const key of Object.keys(args)) {
      if (!(ALLOWED as readonly string[]).includes(key)) {
        throw new ToolArgumentError(`Unexpected argument "${key}".`);
      }
    }
    if ((args.action === "apply" || args.action === "rollback") && args.confirm !== true) {
      throw new ToolArgumentError(`'${args.action}' requires confirm:true after explicit operator approval.`);
    }
    return domainAction(DOMAIN, args.action, args.controlId, {
      storeRoot: defaultStoreRoot(),
      ...(args.target !== undefined ? { target: args.target } : {}),
    });
  },
};
