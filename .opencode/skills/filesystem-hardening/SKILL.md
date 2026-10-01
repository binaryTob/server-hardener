---
name: filesystem-hardening
description: Filesystem/mount hardening rules (nodev, nosuid, noexec, separate mounts). Use before editing mount options.
---
# Filesystem hardening

Tool: `harden_filesystem` (FS-*).

Rules:
- Only edit `/etc/fstab` entries that already exist; back the file up first.
- Adding `nodev,nosuid` to `/tmp`, `/var/tmp` is generally safe.
- **`noexec` is context-dependent** (workloads may execute scripts there). Do
  not treat it as a defect; ask before applying.
- Never remount automatically. State clearly that a remount or reboot is needed
  for the change to take effect.
- Never apply destructive mount changes automatically.
