---
name: ssh-hardening
description: SSH hardening over a remote connection. Use before changing any SSH directive on the target.
---
# SSH hardening (remote, lockout-sensitive)

Tool: `harden_ssh`. You are connected OVER SSH: a bad change can lock you out.

Before a lockout-capable change:
1. Identify the remote user and how they authenticate (when observable).
2. Confirm an alternative administrative account and privilege escalation.
3. Confirm a secondary management path and/or console access.
   The engine refuses `PasswordAuthentication no` without a confirmed secondary
   path — respect it.

Mechanics (by the tool): remote backup, `sshd -t`, reload (never restart),
verify effective config (`sshd -T`) and that sshd stays active. If `sshd -t`
fails the backup is restored.

Crucially: after applying, the tool opens a NEW SSH connection from the
workstation. Only a successful reconnect means success; otherwise it attempts a
rollback. Never store or ask for credentials.
