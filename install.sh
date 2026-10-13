#!/usr/bin/env bash
# Homelab Pulse installer. Run as root on a Proxmox VE host:
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/3g15h1/homelab-pulse/main/install.sh)"
#
# Creates an unprivileged Debian LXC, a read-only Proxmox user (pulse@pve, role PVEAuditor) with an
# API token, and installs Pulse as a systemd service. Run it again to upgrade: the container is
# found by its "homelab-pulse" tag, and its token, CA and settings are kept.
set -euo pipefail

REPO="3g15h1/homelab-pulse"
REF="main"
VMID="" STORAGE="" BRIDGE="vmbr0" IP="dhcp" GW="" SRC="" ROTATE=0 DRY=0 SHOW_PW=0
APP=/opt/homelab-pulse
ETC=/etc/homelab-pulse
TAG=homelab-pulse
PVE_USER=pulse@pve

usage() {
  cat <<EOF
Usage: install.sh [options]

  --vmid N          container ID (default: next free; with an existing container: upgrade it)
  --storage NAME    storage for the container disk (default: first storage that holds containers)
  --bridge NAME     network bridge (default: vmbr0)
  --ip CIDR|dhcp    container address, e.g. 192.168.1.60/24 (default: dhcp)
  --gw IP           gateway, needed with a static --ip
  --ref REF         git branch or tag to install (default: main)
  --src DIR         install from a local checkout instead of downloading
  --rotate-token    create a new API token even if the container already has one
  --show-password   print the existing admin password for the settings page
  --dry-run         print every change instead of making it
  -h, --help        this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --vmid) VMID=$2; shift 2 ;;
    --storage) STORAGE=$2; shift 2 ;;
    --bridge) BRIDGE=$2; shift 2 ;;
    --ip) IP=$2; shift 2 ;;
    --gw) GW=$2; shift 2 ;;
    --ref) REF=$2; shift 2 ;;
    --src) SRC=$2; shift 2 ;;
    --rotate-token) ROTATE=1; shift ;;
    --show-password) SHOW_PW=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
# Every change goes through run(): printed in --dry-run, executed otherwise.
run() {
  if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi
}
# Same for a shell snippet executed inside the container.
in_ct() {
  if [ "$DRY" = 1 ]; then printf '+ pct exec %s -- sh -c %q\n' "$VMID" "$1"; else pct exec "$VMID" -- sh -c "$1"; fi
}

# ------------------------------------------------------------------ preflight
[ "$(id -u)" = 0 ] || [ "${PULSE_ASSUME_ROOT:-}" = 1 ] || die "run as root on the Proxmox host"
for c in pveversion pct pveum pvesh pveam pvesm; do
  command -v "$c" >/dev/null || die "'$c' not found: this must run on a Proxmox VE host"
done
PVE_VER=$(pveversion | sed -n 's|^pve-manager/\([0-9]*\)\..*|\1|p')
[ -n "$PVE_VER" ] && [ "$PVE_VER" -ge 8 ] || die "Proxmox VE 8 or newer is required"
if [ "$PVE_VER" -lt 9 ]; then
  say "Note: on Proxmox VE 8 a read-only token can't ask the QEMU guest agent for VM addresses."
  say "      Containers are fine; give VMs a static IP or a pulse-ip-a-b-c-d tag."
fi
if [ "$IP" != dhcp ] && [ -z "$GW" ]; then die "--ip needs --gw"; fi

json_get() {  # json_get <python expression on d> : reads JSON on stdin
  python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"
}
HOST_IP=$(pvesh get /cluster/status --output-format json |
  json_get 'next((e.get("ip") or "") for e in d if e.get("type") == "node" and e.get("local"))')
[ -n "$HOST_IP" ] || die "could not work out this node's IP from /cluster/status"

# ------------------------------------------------------------------ source
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
if [ -z "$SRC" ] && [ -f "$(dirname "$0")/pulse/server.py" ]; then SRC=$(cd "$(dirname "$0")" && pwd); fi
if [ -z "$SRC" ]; then
  say "Downloading $REPO@$REF"
  curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$REF" | tar -xz -C "$WORK"
  SRC=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -n1)
fi
[ -f "$SRC/pulse/server.py" ] || die "no Pulse source found in $SRC"

# ------------------------------------------------------------------ new or upgrade?
has_tag() { pct config "$1" 2>/dev/null | grep -qE "^tags:.*\b$TAG\b"; }
UPGRADE=0
if [ -n "$VMID" ] && pct config "$VMID" >/dev/null 2>&1; then
  UPGRADE=1
  has_tag "$VMID" || run pct set "$VMID" --tags "$( (pct config "$VMID" | sed -n 's/^tags: //p'; echo $TAG) | paste -sd';')"
elif [ -z "$VMID" ]; then
  for id in $(pct list | awk 'NR>1 {print $1}'); do
    if has_tag "$id"; then VMID=$id; UPGRADE=1; break; fi
  done
fi

if [ "$UPGRADE" = 1 ]; then
  say "Upgrading Homelab Pulse in CT $VMID"
else
  VMID=${VMID:-$(pvesh get /cluster/nextid)}
  STORAGE=${STORAGE:-$(pvesm status --content rootdir | awk 'NR>1 && $3=="active" {print $1; exit}')}
  [ -n "$STORAGE" ] || die "no active storage for containers; pass --storage"
  TEMPLATE=$(pveam list "$(pvesm status --content vztmpl | awk 'NR>1 && $3=="active" {print $1; exit}')" 2>/dev/null |
    awk '/debian-13-standard_.*_amd64/ {print $1}' | sort -V | tail -n1)
  if [ -z "$TEMPLATE" ]; then
    TSTORE=$(pvesm status --content vztmpl | awk 'NR>1 && $3=="active" {print $1; exit}')
    run pveam update >/dev/null
    TNAME=$(pveam available --section system | awk '/debian-13-standard_.*_amd64/ {print $2}' | sort -V | tail -n1)
    [ -n "$TNAME" ] || die "no Debian 13 template available from pveam"
    run pveam download "$TSTORE" "$TNAME"
    TEMPLATE="$TSTORE:vztmpl/$TNAME"
  fi
  NET="name=eth0,bridge=$BRIDGE,ip=$IP"
  [ "$IP" = dhcp ] || NET="$NET,gw=$GW"
  say "Creating CT $VMID from $TEMPLATE"
  run pct create "$VMID" "$TEMPLATE" --hostname pulse --cores 1 --memory 512 --swap 256 \
    --rootfs "$STORAGE:4" --net0 "$NET" --unprivileged 1 --features nesting=1 --onboot 1 \
    --tags "$TAG" --description "Homelab Pulse: https://github.com/$REPO"
  run pct start "$VMID"
  in_ct 'i=0; until ip -4 route | grep -q default && getent hosts deb.debian.org >/dev/null; do i=$((i+1)); [ $i -gt 60 ] && exit 1; sleep 1; done'
  in_ct 'command -v python3 >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3; }'
fi

if [ "$DRY" = 0 ] && [ "$(pct status "$VMID" | awk '{print $2}')" != running ]; then run pct start "$VMID"; fi

# ------------------------------------------------------------------ read-only Proxmox user + token
pveum user list --output-format json | json_get 'any(u["userid"] == "'$PVE_USER'" for u in d)' | grep -q True ||
  run pveum user add "$PVE_USER" --comment "Homelab Pulse (read-only dashboard)"
run pveum acl modify / --users "$PVE_USER" --roles PVEAuditor

in_ct "id pulse >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin pulse; install -d -m 750 -o root -g pulse $ETC"

TOKEN_ID="ct$VMID"   # one token per container, so a second install never touches another's token
HAVE_TOKEN=0
if [ "$UPGRADE" = 1 ] && pct exec "$VMID" -- test -s "$ETC/pve-token"; then HAVE_TOKEN=1; fi
if [ "$HAVE_TOKEN" = 0 ] || [ "$ROTATE" = 1 ]; then
  say "Creating API token $PVE_USER!$TOKEN_ID (read-only)"
  if [ "$DRY" = 0 ] && pveum user token list "$PVE_USER" --output-format json 2>/dev/null |
       json_get 'any(t["tokenid"] == "'$TOKEN_ID'" for t in d)' | grep -q True; then
    run pveum user token remove "$PVE_USER" "$TOKEN_ID"
  fi
  if [ "$DRY" = 1 ]; then
    printf '+ pveum user token add %s %s --privsep 0 --output-format json  (value pushed to CT %s:%s)\n' \
      "$PVE_USER" "$TOKEN_ID" "$VMID" "$ETC/pve-token"
  else
    umask 077
    pveum user token add "$PVE_USER" "$TOKEN_ID" --privsep 0 --output-format json |
      json_get '"'$PVE_USER'!'$TOKEN_ID'=" + d["value"]' > "$WORK/token"
    pct push "$VMID" "$WORK/token" "$ETC/pve-token" --perms 640 --group pulse
    rm -f "$WORK/token"
  fi
fi
run pct push "$VMID" /etc/pve/pve-root-ca.pem "$ETC/pve-ca.pem" --perms 644

# Admin password for the settings page: made once, kept on upgrades, printed only when new.
ADMIN_PW="" NEW_PW=0
if [ "$UPGRADE" = 1 ] && pct exec "$VMID" -- test -s "$ETC/admin-password"; then
  if [ "$SHOW_PW" = 1 ]; then ADMIN_PW=$(pct exec "$VMID" -- cat "$ETC/admin-password"); fi
else
  ADMIN_PW=$(python3 -c 'import secrets; print(secrets.token_urlsafe(15))')
  NEW_PW=1
  (umask 077; printf '%s\n' "$ADMIN_PW" > "$WORK/admin")
  run pct push "$VMID" "$WORK/admin" "$ETC/admin-password" --perms 640 --group pulse
fi

# ------------------------------------------------------------------ app
tar -C "$SRC" -czf "$WORK/app.tgz" pulse README.md LICENSE update.sh
if [ "$UPGRADE" = 1 ]; then
  in_ct "rm -rf $APP.prev && if [ -d $APP ]; then cp -a $APP $APP.prev; fi"
fi
run pct push "$VMID" "$WORK/app.tgz" /tmp/homelab-pulse.tgz
in_ct "rm -rf $APP.new && mkdir -p $APP.new && tar -xzf /tmp/homelab-pulse.tgz -C $APP.new && rm /tmp/homelab-pulse.tgz && rm -rf $APP && mv $APP.new $APP && chown -R root:root $APP && chmod -R a+rX $APP"
run pct push "$VMID" "$SRC/homelab-pulse.service" /etc/systemd/system/homelab-pulse.service
run pct push "$VMID" "$SRC/homelab-pulse-passwd" /usr/local/bin/homelab-pulse-passwd --perms 755
run pct push "$VMID" "$SRC/homelab-pulse-hosts" /usr/local/bin/homelab-pulse-hosts --perms 755
run pct push "$VMID" "$SRC/overrides.example.json" "$ETC/overrides.example.json" --perms 644

if [ "$UPGRADE" = 0 ] || ! pct exec "$VMID" -- test -s "$ETC/env"; then
  sed -e "s|^PULSE_PVE=.*|PULSE_PVE=live|" -e "s|^PULSE_PVE_HOST=.*|PULSE_PVE_HOST=$HOST_IP|" "$SRC/env.example" > "$WORK/env"
  [ "$DRY" = 1 ] && printf '+ env file with PULSE_PVE=live PULSE_PVE_HOST=%s\n' "$HOST_IP"
  run pct push "$VMID" "$WORK/env" "$ETC/env" --perms 640 --group pulse
elif ! pct exec "$VMID" -- grep -q PULSE_PVE_HOST "$ETC/env"; then
  in_ct "echo PULSE_PVE_HOST=$HOST_IP >> $ETC/env"   # older installs assumed the host's address
fi

in_ct "systemctl daemon-reload && systemctl enable -q homelab-pulse && systemctl restart homelab-pulse"

if [ "$DRY" = 1 ]; then
  if [ "$SHOW_PW" = 1 ] && [ "$NEW_PW" = 0 ] && [ -n "$ADMIN_PW" ]; then say "Admin password: $ADMIN_PW"; fi
  say "Dry run: nothing was changed."; exit 0
fi

# ------------------------------------------------------------------ verify + report
PORT=$(pct exec "$VMID" -- sh -c ". $ETC/env; echo \${PULSE_PORT:-80}")
ok=0
for _ in $(seq 1 20); do
  if pct exec "$VMID" -- python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$PORT/', timeout=2)" 2>/dev/null; then ok=1; break; fi
  sleep 1
done
CT_IP=$(pct exec "$VMID" -- sh -c "ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1")
[ "$ok" = 1 ] || die "the service didn't answer; see: pct exec $VMID -- journalctl -u homelab-pulse -n 50"
URL="http://$CT_IP$( [ "$PORT" = 80 ] || echo ":$PORT")"
cat <<EOF

  Homelab Pulse is running in CT $VMID:  $URL

  It discovers your nodes, guests and their services by itself (first full scan within a minute).
  Fine-tune with Proxmox tags on a guest:  pulse-ignore  pulse-noscan  pulse-role-<text>  pulse-icon-<name>
  or with $ETC/overrides.json (example next to it).

  Alerts & settings:  $URL/settings
$(if [ -n "$ADMIN_PW" ]; then printf '  Admin password:     %s%s' "$ADMIN_PW" "$([ "$NEW_PW" = 1 ] && echo '   (new; keep it somewhere safe)')";
  else printf '  Admin password:     unchanged (show it with --show-password; reset with homelab-pulse-passwd)'; fi)

  Upgrade:    run this installer again
  Uninstall:  bash uninstall.sh   (from the repo; or: pct destroy $VMID && pveum user token remove $PVE_USER $TOKEN_ID)
EOF
