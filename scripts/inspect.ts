/**
 * CLI entry point: inspect the local host and print the hardening assessment.
 *
 *   bun run inspect
 *
 * Read-only. No changes are applied.
 */
import { assess, formatAssessment, formatSystemInspection } from "../src/hardening/agent";
import { defaultStoreRoot } from "../src/hardening/store";

const assessment = await assess({ storeRoot: defaultStoreRoot() });
console.log(formatSystemInspection(assessment.inventory));
console.log("");
console.log(formatAssessment(assessment));
