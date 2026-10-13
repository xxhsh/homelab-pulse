# Homelab Pulse

A live, animated map of your Proxmox homelab on one page, and it **figures out the lab by itself**. It
also **watches the lab for you**: it sends a push notification when something breaks or is about to.
Install it and it finds every node, VM and container, their IP addresses, and the services they run
(web apps, DNS, MQTT, databases…), then keeps checking that those services answer. Guests you create
later show up within a minute. You don't edit a config file.

![Desktop](docs/screenshots/desktop.png)

Every guest is a node on the map. Its outer ring fills with CPU (it glows when busy and turns amber
above 88 %), a thin second ring shows memory, small dots under its name show its services, and
particles stream along the links in proportion to real network traffic (indigo = in, white = out).
Around the map are panels for each Proxmox node (CPU history, RAM, storage, SMART health), the health
checks grouped by guest, last night's backups per guest, and a 24-hour activity feed. Tap any node
for details and 30-minute sparklines.

<p align="center"><img src="docs/screenshots/phone.png" width="280" alt="Phone layout"></p>

## Install

On a Proxmox VE host (9.x recommended; 8.x works with the caveat below), as root:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/3g15h1/homelab-pulse/main/install.sh)"
```

The installer:

1. creates an unprivileged Debian 13 container (1 core, 512 MB, 4 GB, next free ID, DHCP, tagged `homelab-pulse`),
2. creates a Proxmox user `pulse@pve` with the built-in read-only role **PVEAuditor** and an API token
   `pulse@pve!ct<vmid>` for this container,
3. installs Pulse as a systemd service and prints its address and the **admin password** for the settings page.

Options: `--vmid`, `--storage`, `--bridge`, `--ip 192.168.1.60/24 --gw 192.168.1.1`, `--ref <tag>`,
`--dry-run` (prints every change and makes none). `install.sh --help` lists them all.

**Upgrade:** run the same command again. It finds the container by its tag, keeps the token, the CA
and your settings, and keeps the previous version in `/opt/homelab-pulse.prev`.

Add it to a phone's home screen (Share → Add to Home Screen) and it opens like an app. `?embed` hides
the header and footer, for embedding in another dashboard such as a Home Assistant webpage card.

## How discovery works

```
every 5 s    node + guest stats from /cluster/resources and each node's status
every 60 s   guest IPs, disk usage inside VMs (guest agent), SMART, backups (vzdump task logs), task log
every 5 min  discovery: scan each running guest, identify what answers, update the checks
             (a guest that was just created or started is scanned 45 s later)
every 15 s   run the health checks, 8 at a time; a check turns red after 2 failures in a row
```

- **IP addresses** come from the Proxmox API: a container's live interfaces, the QEMU guest agent for
  VMs, or a static `ip=` / cloud-init address in the guest's config.
- **Scanning:** Pulse tries a TCP connection to about 30 common ports (22, 53, 80, 443, 1883, 3000,
  5432, 8000, 8080, 8123, 8443, 9000, 11434, 32400…) on each running guest's address, and ports 80/443 on
  the router. It scans **only the addresses Proxmox reports for your guests**, never the rest of your
  network.
- **Fingerprinting:** each open port gets one harmless look: an HTTP `GET /` (following at most one
  redirect to the same host), a TLS handshake (certificate name and expiry), a DNS query (and whether it
  blocks ads), or the greeting line of protocols like SSH. Pulse never logs in and never sends a form.
- **Recognising software:** the page title, `Server` header, certificate and port are matched against a
  list of common homelab software (Home Assistant, AdGuard Home, Pi-hole, Paperless-ngx, Nextcloud,
  Jellyfin, Plex, Immich, Grafana, Uptime Kuma, Portainer, Nginx Proxy Manager, Vaultwarden, Gitea,
  Frigate, Node-RED, Ollama, TrueNAS, Proxmox Backup Server and more). The best match becomes the guest's
  role and icon. Unknown web apps are labelled with their page title.
- Every recognised service gets a health check, except SSH. SSH is listed on the guest, but checking it
  every 15 s would fill sshd's log, so it isn't checked unless you add the check in `overrides.json`.
  Ports like Redis, PostgreSQL, MQTT and FTP are only connected to and never sent an HTTP request.
- A service has to be missing from **two scans in a row** before it is dropped, so a guest that reboots
  during a scan doesn't lose its checks. Checks for a stopped guest are paused (grey), not red.
- **Clusters:** every node gets its own hub on the map and its own panel. Guests move with migrations.
- **Disks inside VMs:** Proxmox only knows how full a *container* is. For VMs, Pulse asks the QEMU guest
  agent (`get-fsinfo`) and shows each real filesystem in the VM's drawer (read-only roots, bind mounts and
  tiny boot partitions are left out). Needs the agent running in the VM; VMs without it just show their
  allocated size.

## Several standalone hosts

A cluster needs nothing extra: one Pulse sees every node. For Proxmox hosts that **aren't** clustered
(a second box, a laptop node), Pulse can watch them too and show them all as one lab:

1. On the **other** host, as root:
   ```bash
   bash -c "$(curl -fsSL https://raw.githubusercontent.com/3g15h1/homelab-pulse/main/add-host.sh)"
   ```
   It creates the same read-only `pulse@pve` user (PVEAuditor) and a token there, and prints one line.
2. Paste that line into the Pulse container's shell (`pct enter <id>` on the host Pulse runs on):
   `homelab-pulse-hosts add <name> <bundle>`. Pulse restarts and the host appears within a minute.

The line contains that host's read-only token, so treat it like a password. `homelab-pulse-hosts list`
shows the extra hosts, `homelab-pulse-hosts remove <name>` drops one (then `add-host.sh --remove` on that
host deletes its token). Each host's UI check is verified against its own CA.

- A host that stops answering shows as an offline node (and raises *Node offline*); the others carry on.
- **VMIDs must be unique across hosts**, as they would be in a cluster. If two hosts use the same ID, the
  first host's guest is shown and an *Attention* warning names the clash.

## Alerts

Open **⚙ → Alerts & settings** (`/settings`) and sign in with the admin password the installer printed.
Pick where alerts go, press **Save & send test**, and you're done.

- **Webhook:** Pulse POSTs JSON `{title, message, severity, state, items, url, ts}` to any URL, with optional
  extra headers. In Home Assistant, a *Webhook* trigger plus a `notify.mobile_app_…` action puts it on your
  phone through the companion app.
- **ntfy:** push to an [ntfy](https://ntfy.sh) topic (ntfy.sh or your own server, optional access token).
  Critical alerts arrive with high priority, and tapping one opens the dashboard.

What raises an alert (each can be switched off):

| Alert | When |
|---|---|
| Service down | a health check has failed for 3 minutes (adjustable) |
| Node offline | a Proxmox node drops out |
| Pulse can't reach Proxmox | the API has failed for 2 minutes |
| Guest stopped unexpectedly | a VM/container stopped and no stop/shutdown task explains it |
| Backup failed | the latest vzdump job on a node didn't finish OK |
| Early warning | see below |

How it behaves:
- **Recovery:** you get a "back after 12 min" message when a problem clears.
- **Grouping:** anything within 60 s becomes one message, so a host reboot is "12 services down on pve1", not 12 pings.
- **Quiet hours:** non-critical alerts are held and sent as one summary in the morning.
- **Mutes:** silence a check, a guest or a whole node for maintenance, for a while or until it recovers.
- **Reminders:** optional, while something stays broken.
- **Restarts:** alert state survives restarts and upgrades, so nothing is sent twice.

## Early warnings

Problems that aren't outages yet. They show in an **Attention** strip on the dashboard and can alert too:

| Warning | Default |
|---|---|
| Storage filling up | full within 30 days at the current rate (critical: 7), or above 85 % (critical: 95 %) |
| Certificate expiring | any TLS check within 21 days (critical: 7) |
| SSD wear / SMART | 80 % worn (critical: 90 %); SMART not passing |
| Guest without a recent backup | no successful backup in 48 h (guests in a backup job) |
| Node memory high | above 90 % for 15 minutes |
| Container disk filling up | above 90 % (critical: 97 %) |
| VM disk filling up | any filesystem inside a VM above 90 % (critical: 97 %), via the guest agent |

The storage forecast uses **Proxmox's own history** (its RRD database), so it works from the first minute.
It only warns about a steady trend, not a one-off copy.

## History

- **Graphs:** each guest's and node's drawer has **Live · Day · Week · Month · Year**. Live is the last
  30 minutes; the longer ranges come straight from Proxmox, which keeps a year of data.
- **Uptime:** every health check shows uptime for 24 h, 7 d and 30 d.
- **Survives restarts:** check results (90 days), the activity feed (30 days), alert state and settings are
  kept in a small SQLite file, `/var/lib/homelab-pulse/pulse.db`.

## Settings page and admin password

Viewing the dashboard stays open as before. Changing anything on `/settings` needs the admin password.
- **Storage:** the password is stored hashed (PBKDF2), and a sign-in lasts 30 days.
- **Secrets:** the ntfy token and webhook headers are never shown back in full.
- **Attempts:** sign-ins are limited to 5 a minute.
- **Forgotten password:** in the Pulse container, run `homelab-pulse-passwd` (or `homelab-pulse-passwd --generate`).
- **Upgrading from 1.0:** the installer creates a password and prints it.
- **Seeing it again:** `install.sh --show-password`.

## Fine-tuning

Discovery needs no help, but you can steer it.

**Proxmox tags on a guest** (Datacenter → guest → Summary → Tags):

| Tag | Effect |
|---|---|
| `pulse-ignore` | Hide the guest completely |
| `pulse-noscan` | Show the guest but don't scan it |
| `pulse-role-shared-ai` | Role text ("shared ai"; dashes become spaces) |
| `pulse-icon-brain` | Icon (home, shield, doc, film, photo, chart, database, terminal, code, lock, flow, radio, sync, disk, cube, globe, camera, brain, chat, key, flask, spark, pulse, box) |
| `pulse-ip-192-168-1-50` | Address to use (dots as dashes) |

**`/etc/homelab-pulse/overrides.json`** in the container, for anything tags can't say. All keys are
optional. See `overrides.example.json`:

```json
{
  "internet": {"host": "1.1.1.1", "port": 443},
  "router": {"name": "Router", "ip": "192.168.1.1"},
  "scan": {"ports_add": [8384], "ports_remove": [21]},
  "guests": {"103": {"role": "Home Assistant", "icon": "home", "ip": "192.168.1.13"}},
  "checks": [{"id": "public-cert", "name": "Public HTTPS", "kind": "tls", "host": "192.168.1.11",
              "port": 443, "sni": "home.example.org", "target": 101}],
  "hide_checks": ["101:22"]
}
```

`internet: false` turns the Internet check off. `checks` adds a check (kinds `tcp`, `http`, `tls`, `dns`).
One whose `target` and port match a discovered check replaces it. Use that for a fully verified TLS check
with the right server name. `hide_checks` removes checks by id (`<vmid>:<port>`). The file is re-read
every minute. A mistake in it shows on the dashboard and doesn't stop discovery.

Precedence: guest tags, then `overrides.json`, then discovery, then a guess from the guest's name.

## Configuration

`/etc/homelab-pulse/env` (see `env.example`): `PULSE_PVE` (`live` or `demo`), `PULSE_PVE_HOST`,
`PULSE_PVE_PORT`, `PULSE_PVE_TOKEN_FILE`, `PULSE_PVE_CA`, `PULSE_PVE_TLS_NAME` (rarely needed),
`PULSE_PVE_HOSTS_DIR` (extra standalone hosts, default `/etc/homelab-pulse/hosts.d`), `PULSE_OVERRIDES`, `PULSE_DB`, `PULSE_ADMIN_PASSWORD_FILE`, `PULSE_PUBLIC_URL` (the link used in
notifications), `PULSE_PORT`, `PULSE_BIND`, `PULSE_LOG`. Restart after editing:
`systemctl restart homelab-pulse`.

Routes: `/` UI, `/settings`, `/api/state` JSON snapshot, `/api/stream` Server-Sent Events,
`/api/history/<vmid|node>`, `/api/rrd/<vmid|node>?range=day|week|month|year`, `/api/uptime`,
`/healthz` (503 when Proxmox, the checks or discovery are failing). The settings API (`/api/settings`, `/api/mutes`,
`/api/test-notify`, …) needs a signed-in session and the `X-Pulse-Request: 1` header.

## Try it without Proxmox

```bash
git clone https://github.com/3g15h1/homelab-pulse && cd homelab-pulse
PULSE_PORT=8765 python3 pulse/server.py     # demo mode: a simulated two-node cluster (settings password: demo)
```

Python 3.11+ standard library only. There's nothing to `pip install`.

## Manual install (any Debian/Ubuntu box)

1. On a Proxmox node:
   `pveum user add pulse@pve && pveum acl modify / --users pulse@pve --roles PVEAuditor && pveum user token add pulse@pve dash --privsep 0`
2. On the box: copy `pulse/` to `/opt/homelab-pulse/pulse`, `homelab-pulse.service` to `/etc/systemd/system/`,
   and create a `pulse` system user.
3. Put `pulse@pve!dash=<secret>` in `/etc/homelab-pulse/pve-token` (mode 640, group pulse), copy the node's
   `/etc/pve/pve-root-ca.pem` to `/etc/homelab-pulse/pve-ca.pem`, and write `/etc/homelab-pulse/env` from
   `env.example` with `PULSE_PVE=live` and `PULSE_PVE_HOST=<node IP>`.
4. `systemctl daemon-reload && systemctl enable --now homelab-pulse`

## Security and privacy

- **Read-only.** The token has the PVEAuditor role. Pulse can see the lab but can't change anything.
  Revoke it on its own with `pveum user token remove pulse@pve ct<vmid>`.
- **It port-scans your guests**, as described above, and only the addresses Proxmox reports for them. Tag
  a guest `pulse-noscan` to opt it out.
- **No login on the dashboard.** Anyone who can reach it sees guest names, addresses, services and backup
  state. Keep it on your LAN or a VPN such as Tailscale. Don't expose it to the internet.
- Nothing leaves your network except the Internet check (a TCP connect to 1.1.1.1:443, which you can turn off)
  and the alerts you configure.
- Text taken from scanned services (page titles, headers) is shortened and always shown escaped.

**Proxmox VE 8:** reading a VM's addresses and disk usage through the guest agent needs `VM.Monitor`, which
the read-only role doesn't have on PVE 8 (PVE 9's PVEAuditor includes `VM.GuestAgent.Audit`, which is enough).
Containers are unaffected. Give VMs a static IP or a `pulse-ip-…` tag.

## Uninstall

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/3g15h1/homelab-pulse/main/uninstall.sh)"
```

This destroys the container and its API token (`pulse@pve!ct<vmid>`). The `pulse@pve` user goes too,
unless another Pulse install still uses it.

## Development

```bash
python3 -m unittest discover -s tests -t .
```

`pulse/alerts.py` is the alert state machine, `pulse/early.py` the early warnings, `pulse/notify.py` delivery,
`pulse/store.py` the SQLite history, `pulse/discover.py` the discovery pipeline, `pulse/catalog.py` the list of recognised software and
scanned ports, `pulse/collect.py` the polling and the snapshot, `pulse/demo.py` the simulated cluster.
New software to recognise is usually a single line in `catalog.RULES`.

## License

MIT
