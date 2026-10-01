/**
 * CLI entry point: assess a target server (read-only) from the workstation.
 *
 *   bun run inspect admin@server.example
 *   bun run inspect db.example        # ssh alias
 *
 * If no target is given, the session target is used. Nothing is applied.
 */
import { assess, formatAssessment } from "../src/hardening/agent";
import { NoTargetError } from "../src/hardening/errors";
import { defaultStoreRoot } from "../src/hardening/store";

const target = process.argv[2];
try {
  const assessment = await assess(
    target ? { storeRoot: defaultStoreRoot(), target } : { storeRoot: defaultStoreRoot() },
  );
  console.log(assessment.inventorySummary);
  console.log("");
  console.log(formatAssessment(assessment));
} catch (err) {
  if (err instanceof NoTargetError) {
    console.error(err.message);
    process.exitCode = 1;
  } else {
    throw err;
  }
}
