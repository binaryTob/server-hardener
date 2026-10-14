# Verification and operational boundaries

The offline suite exercises parsers, discovery, pure assessments, state, target
validation, command quoting and bounded remediation against an in-memory
`FakeHost`. It does not connect to an external server or apply host hardening.

Use Bun 1.4.3 or newer. The committed lockfile requires the v2 lockfile reader.

```bash
bun install --frozen-lockfile --ignore-scripts
bun run lint
bun run typecheck
bun test
bun run build
bun audit
```

Regression checks cover read-only preview/verify, restrictive configuration
modes, backup checksum rejection, context isolation across targets/ports,
conservative reconnect rollback and refusal to activate a firewall after a failed
administrative allow rule. Firewalld activation is manual until zone/interface
and administrative-port handling is implemented and validated.

Before operational use, validate the applicable controls on disposable Linux
VMs with console access. SSH includes/Match rules, socket activation, distro
service names, PAM, firewall zones and network paths need integration coverage.
Retained-session rollback is best effort, not out-of-band recovery. The local
operator, OpenCode session and source files are trusted; prompts and `confirm`
arguments are not a cryptographic approval mechanism.
