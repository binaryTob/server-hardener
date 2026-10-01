---
name: firewall-hardening
description: Firewall hardening rules. Use before enabling or changing the host firewall.
---
# Firewall hardening

Tool: `harden_firewall` (FW-*).

Rules:
- Work with the firewall **already present** (ufw, firewalld). **Never replace
  one firewall with another.**
- **Never close the administrative path.** Before enabling a firewall, identify
  the administrative (SSH) port from observed listeners and ensure it is
  allowed. If the port cannot be determined, warn and stop.
- nftables: automatic ruleset generation is **not** supported — preview only,
  apply manually.
- Show the proposed commands and warnings, then require explicit confirmation.
- Verify the resulting state (`ufw status` / `firewall-cmd --state`), not just
  exit code.
