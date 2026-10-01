/**
 * POSIX shell quoting for the REMOTE side of an ssh invocation.
 *
 * The local process never uses a shell: `ssh` is spawned with an argv array.
 * OpenSSH, however, hands the remote command to the target's login shell, so
 * every remote argument must be quoted. Arguments come exclusively from our own
 * fixed operations (never from the model), and are quoted here defensively.
 */
export function shellQuote(value: string): string {
  if (value === "") return "''";
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/** Build the single remote command string from a fixed argv. */
export function buildRemoteCommand(argv: string[]): string {
  return argv.map(shellQuote).join(" ");
}
