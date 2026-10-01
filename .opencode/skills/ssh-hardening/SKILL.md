---
name: ssh-hardening
description: SSH hardening rules (root login, password auth, MaxAuthTries, X11, empty passwords). Use before changing any SSH directive.
---
# SSH hardening

Tool: `harden_ssh` (`inspect|preview|apply|verify|rollback`).

Safety, in order:
1. **Lockout check.** Before disabling password authentication, confirm a
   working alternative: a secondary management path and/or console access. The
   engine refuses `PasswordAuthentication no` when no secondary path is
   confirmed — respect that.
2. **Alternative admin.** Disabling root login requires a named administrative
   account and a working escalation path (sudo). If unknown, do not proceed.
3. Always preview, show the exact directive change and the lockout warning, and
   get explicit confirmation.

Mechanics (handled by the tool): back up `sshd_config`, edit one directive,
`sshd -t`, reload (never restart), verify effective config (`sshd -T`) and that
the service stays active; restore the backup automatically if `sshd -t` fails.

Never store or ask for credentials.
