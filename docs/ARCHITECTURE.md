# Architecture — server-hardener (remote agent)

`server-hardener` is an **OpenCode agent on the operator's workstation**. It
administers **one target Linux server per session over SSH**. The target needs
nothing installed: no OpenCode, Bun, Node, repo, API keys, daemon or agent.

```
Operator workstation                 Target Linux server
  OpenCode                             sshd
  server-hardener       ── SSH ──▶     standard OS tools
  skills / tools
```

SSH is only the transport used by the tools. It is not fleet management, not
multi-server orchestration, and there is no deployment of the framework on the
target.

## 1. Product

```
git clone https://github.com/binaryTob/server-hardener.git
cd server-hardener
bun install --frozen-lockfile --ignore-scripts
opencode
> harden admin@server.example
```

The agent identifies the target, verifies SSH, runs read-only discovery, groups
hardening candidates by risk, asks the decision-critical questions, applies the
selected changes with remote file backups and verification, supports per-control
rollback and reports. Syntax failure restores SSH configuration immediately;
failed fresh SSH reconnection triggers a rollback attempt. Other verification
failures require operator review rather than a global automatic transaction.

## 2. Layers

```
src/hardening/
├── transport/
│   ├── target.ts     target parsing/validation (alias, user@host, ip)
│   ├── quote.ts      POSIX quoting for the remote command
│   ├── host.ts       Host interface + createHost + probe
│   ├── ssh.ts        SshHost (spawned ssh argv; BatchMode; sudo -n)
│   └── local.ts      LocalHost (tests / explicit localhost only)
├── exec.ts, fsio.ts, errors.ts
├── collectors/linux.ts, parsers/linux/*.ts, inventory.ts
├── models.ts, validation.ts
├── store.ts          workstation state: session + last-run + optional context
├── controls/         catalog (applicability/assess/risk/preconditions — pure)
├── planning/         context, applicability, risk, preconditions, evaluate,
│                     tiers, questions
├── remediation/      sysctl/ssh/firewall/services/logging/filesystem + run
└── agent.ts          target-aware high-level API + text rendering
.opencode/
├── agents/server-hardener.md
├── skills/           linux-discovery, linux-hardening, ssh/firewall/services/
│                     kernel/filesystem/logging-hardening, verification
└── tools/            target, inspect_system, inspect_security, harden_*
scripts/inspect.ts    CLI: read-only assessment of a target
```

## 3. Transport abstraction

`Host` implements `CommandRunner` + `FileReader` plus privileged/file-write
operations. Two implementations:

- **SshHost** (default): spawns `ssh` with an **argv array** (never a shell),
  `BatchMode=yes`, `ConnectTimeout`, `NumberOfPasswordPrompts=0`; the remote
  command is quoted. Privileged operations use `sudo -n` (never a password).
  Honours `~/.ssh/config`, agent, `IdentityFile`, `ProxyJump`, `known_hosts`.
- **LocalHost**: only used when the target is explicitly `localhost` (tests or
  opt-in). It is never selected implicitly.

The model cannot supply a command: tools call fixed operations whose argvs are
built in code; `assertSafeCommand` rejects anything but bare command names.

## 4. Target selection

`target` accepts an ssh alias, `user@host` or `user@ip`. Parsing rejects
option-shaped targets (`-oProxyCommand=…`) and shell metacharacters. The active
target is remembered in `.server-hardener/session.json`; tools use it unless a
`target` is given. **If there is no target, tools ask — they never fall back to
localhost.**

## 5. Discovery and evaluation

Read-only collectors/parsers run unchanged against either Host. Controls are
pure code; the engine decides applicability, compliance, risk, preconditions and
the operator tier (`safe`/`review`/`risky`). No numeric score.

## 6. Remediation

Preview → apply → verify → rollback, per control:
- **Backups live on the target** at `/var/backups/server-hardener/<run-id>/`
  (content + SHA-256 + owner/group/mode, mode 0600). Config content passes through
  workstation memory while reading, editing and creating/restoring backups.
  Restore checks content integrity before writing; config edits preserve mode.
- sysctl, SSH, firewall (UFW activation; firewalld/nftables manual), services (known-insecure only),
  logging/audit, filesystem fstab. Everything else is `manual remediation
  required`.
- **SSH/firewall reconnection check:** after an access-affecting change the tool
  opens a NEW ssh connection from the workstation; if it fails it attempts a
  rollback over the retained session and checks a fresh connection again. A
  listening port is not accepted as proof of operator access. There is no remote
  recovery timer; use a verified secondary management path. UFW activation needs
  successful administrative allow rules first; firewalld zone-aware activation
  is not implemented. Firewall rollback restores activation, not all rules.

## 7. Privileges

Root SSH or an admin user with passwordless `sudo -n`. Availability is probed;
if neither works, privileged controls are refused with a clear message. No
password is ever captured or stored.

## 8. Local state (workstation)

```
.server-hardener/
├── session.json           active target for the session
├── last-run.json          applied/skipped/failed/rolled-back + verification
└── optional-context.json  operator-supplied operational context
```

Context is used only for the selected session target. Connecting to a different
target/explicit port clears old approvals and management details. Explicit SSH
ports are part of rollback host identity. Alias resolution changes are outside
this string-based identity; reconfirm context if an alias is repointed.

## 9. Tests

`tests/`: parsers, discovery, assessment, store (session/last-run/context),
and a security suite covering target validation, safe ssh argv, host-key/auth/
timeout classification, and the rule that no tool assumes localhost. Execution
tests run against an in-memory `FakeHost` (preview/backup/apply/verify/rollback)
without real SSH.

## 10. Deliberately out of scope

Fleet management, remote agents, daemon, API server, queue/scheduler, DB,
web UI, orchestrator, Ansible/Terraform, remote deployment of the framework.
Windows. Scoring, pentesting, compliance dashboards, complex plan/state engines.
