---
name: firewall-hardening
description: Firewall hardening on the target. Use before enabling or changing the host firewall.
---
# Firewall hardening (remote)

Tool: `harden_firewall` (FW-*).

Rules:
- Work with the firewall already present (ufw, firewalld). Never replace one
  with another, and never auto-generate nftables rules (preview only).
- **Never close the operator's access.** The agent knows it is connected from
  the workstation: determine the SSH port, ensure it is allowed, and only then
  consider the policy change. Never default-deny first.
- After enabling, the tool verifies a NEW SSH connection from the workstation;
  if it fails, rollback is attempted.
- Verify resulting state (`ufw status` / `firewall-cmd --state`), not exit code.
