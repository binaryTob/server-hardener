---
name: verification
description: How to verify hardening changes. Use after every applied control and when deciding success or rollback.
---
# Verification

Never consider a change successful just because a command exited 0. Each
remediation verifies the resulting state:

- **sysctl**: read the runtime value back (`sysctl -n`) equals the target.
- **SSH**: `sshd -t` succeeds, the effective directive (`sshd -T`) matches, and
  the service is still active.
- **service**: `systemctl is-enabled` / `is-active` reflect the intended state.
- **firewall**: `ufw status` active / `firewall-cmd --state` running.
- **filesystem**: the fstab entry contains the required options (and warn that a
  remount is pending).
- **logging**: the service is active and enabled.

On failure: offer rollback. If automatic rollback is unsafe, say
`manual rollback required`. Record outcomes in `.server-hardener/last-run.json`.
