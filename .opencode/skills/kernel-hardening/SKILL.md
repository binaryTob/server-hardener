---
name: kernel-hardening
description: Kernel sysctl hardening rules (ASLR, ptrace, kernel pointers, source routing, ICMP redirects). Use before changing sysctl values.
---
# Kernel / sysctl hardening

Tool: `harden_sysctl` (KRN-*).

Rules:
- Persist values in the managed drop-in
  `/etc/sysctl.d/99-server-hardener.conf` (a clearly marked managed block) and
  apply them at runtime with `sysctl -w` (never `sysctl --system`).
- Detect conflicting settings in other sysctl files before writing and surface
  them as warnings.
- Verify the runtime value afterwards (`sysctl -n`), not just the write.
- Rollback restores the previous managed file (or removes the block) and the
  previous runtime values.
- If a value is not currently observable, it is `unknown`; do not assume.
