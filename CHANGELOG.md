# Changelog

## Unreleased

- **Disk usage inside VMs**, from the QEMU guest agent (`get-fsinfo`, readable by PVEAuditor on PVE 9): each
  real filesystem in the VM's drawer, and a new early warning, *VM disk filling up* (90 % / 97 %).
- **Several standalone Proxmox hosts** as one lab: `add-host.sh` on the extra host creates its read-only
  token and prints one `homelab-pulse-hosts add …` line for the Pulse container. Each host's UI check uses
  its own CA; a silent host shows as an offline node; duplicate VMIDs across hosts raise a warning.

## 1.1.0 — 2026-10-13

- **Alerts** to a generic webhook (e.g. Home Assistant) and/or ntfy: service down, node offline, Proxmox
  unreachable, guest stopped unexpectedly, backup failed, early warnings. Recovery messages, grouping
  (one message per incident), quiet hours with a morning summary, mutes, optional reminders. Restart-safe.
- **Early warnings** with an Attention strip: storage forecast from Proxmox RRD history, certificate
  expiry, SSD wear/SMART, guests without a recent backup, node memory, container disks.
- **History that lasts:** Day/Week/Month/Year graphs from Proxmox RRD; uptime per check (24 h / 7 d / 30 d);
  activity feed, alert state and settings kept in SQLite (`/var/lib/homelab-pulse/pulse.db`).
- **Settings page** (`/settings`) behind an admin password (PBKDF2, signed 30-day session, rate-limited,
  CSRF header). Installer generates and prints the password; `homelab-pulse-passwd` resets it.

## 1.0.0 — 2026-10-12

First public release.

- Discovers nodes, guests, IPs (LXC interfaces, QEMU guest agent, static/cloud-init config) and
  services (port scan + HTTP/TLS/DNS/banner fingerprinting) by itself; new guests appear within a minute.
- Multi-node clusters: one hub per node on the map, per-node host panels and backups, shared storage.
- Health checks are planned from discovery; tags (`pulse-*`) and `overrides.json` steer it.
- One-command installer for Proxmox hosts (LXC + read-only PVEAuditor token), upgrade in place.
- Demo mode simulates a two-node cluster through the same code paths.
