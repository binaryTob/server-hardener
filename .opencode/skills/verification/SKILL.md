---
name: verification
description: How to verify hardening changes on the target. Use after every applied control and when deciding success or rollback.
---
# Verification (remote)

Never trust exit codes. Each remediation verifies the target's resulting state:

- sysctl: read the runtime value back (`sysctl -n`) equals the target.
- SSH: `sshd -t` ok, effective directive (`sshd -T`) matches, service active,
  AND a NEW ssh connection from the workstation succeeds.
- service: `systemctl is-enabled` / `is-active`.
- firewall: `ufw status` active / `firewall-cmd --state` running, and a new
  connection still works.
- filesystem: the fstab entry has the required options (remount pending).
- logging: service active and enabled.

On failure: offer rollback. If automatic rollback is unsafe, say
`manual rollback required`. Outcomes are recorded in
`.server-hardener/last-run.json` on the workstation; backups stay on the target.
