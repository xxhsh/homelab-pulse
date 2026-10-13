#!/usr/bin/env bash
# Let a Pulse running on another Proxmox host watch THIS host too (for standalone hosts that aren't
# in the same cluster; cluster members need nothing, Pulse sees them already). Run as root here:
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/3g15h1/homelab-pulse/main/add-host.sh)"
#
# Creates the read-only user pulse@pve (role PVEAuditor) and an API token on this host, then prints
# one command to paste into the Pulse container's shell. That line contains the token: treat it
# like a password. Remove again with --remove.
set -euo pipefail

PVE_USER=pulse@pve
TOKEN_ID=remote LABEL="" DRY=0 REMOVE=0 ROTATE=0

usage() {
  cat <<USAGE
Usage: add-host.sh [options]

  --label NAME      name for this host in Pulse (default: this node's name)
  --token-id ID     API token name on this host (default: remote)
  --rotate-token    replace an existing token of that name
  --remove          delete the token (and pulse@pve once no token is left)
  --dry-run         print every change instead of making it
  -h, --help        this help
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --label) LABEL=$2; shift 2 ;;
    --token-id) TOKEN_ID=$2; shift 2 ;;
    --rotate-token) ROTATE=1; shift ;;
    --remove) REMOVE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
run() { if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi; }
json_get() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

[ "$(id -u)" = 0 ] || [ "${PULSE_ASSUME_ROOT:-}" = 1 ] || die "run as root on the Proxmox host"
for c in pveversion pveum pvesh; do
  command -v "$c" >/dev/null || die "'$c' not found: this must run on a Proxmox VE host"
done
[[ "$TOKEN_ID" =~ ^[A-Za-z][A-Za-z0-9._-]*$ ]] || die "--token-id: letters, digits, . _ - only"

has_token() {
  pveum user token list "$PVE_USER" --output-format json 2>/dev/null |
    json_get 'any(t.get("tokenid") == "'"$TOKEN_ID"'" for t in d)' | grep -q True
}

if [ "$REMOVE" = 1 ]; then
  if has_token; then run pveum user token remove "$PVE_USER" "$TOKEN_ID"; fi
  left=$(pveum user token list "$PVE_USER" --output-format json 2>/dev/null | json_get 'len(d)' 2>/dev/null || echo 0)
  if [ "$DRY" = 1 ] && has_token; then left=$((left - 1)); fi
  if [ "$left" -le 0 ]; then run pveum user delete "$PVE_USER" || true
  else say "Kept $PVE_USER: $left other token(s) still use it."; fi
  say "Done. In the Pulse container: homelab-pulse-hosts remove <label>"
  exit 0
fi

STATUS=$(pvesh get /cluster/status --output-format json)
NODE=$(echo "$STATUS" | json_get 'next((e.get("name") or "") for e in d if e.get("type") == "node" and e.get("local"))')
HOST_IP=$(echo "$STATUS" | json_get 'next((e.get("ip") or "") for e in d if e.get("type") == "node" and e.get("local"))')
[ -n "$HOST_IP" ] || die "could not work out this node's IP from /cluster/status"
LABEL=${LABEL:-$(echo "$NODE" | tr 'A-Z' 'a-z')}
[[ "$LABEL" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] && [ "$LABEL" != primary ] ||
  die "--label: lowercase letters, digits and dashes (and not 'primary')"

say "Read-only access for Pulse on $NODE ($HOST_IP)"
pveum user list --output-format json | json_get 'any(u["userid"] == "'$PVE_USER'" for u in d)' | grep -q True ||
  run pveum user add "$PVE_USER" --comment "Homelab Pulse (read-only dashboard)"
run pveum acl modify / --users "$PVE_USER" --roles PVEAuditor
if has_token; then
  [ "$ROTATE" = 1 ] || die "token $PVE_USER!$TOKEN_ID exists already: use --rotate-token to replace it, or --token-id NAME"
  run pveum user token remove "$PVE_USER" "$TOKEN_ID"
fi

if [ "$DRY" = 1 ]; then
  printf '+ pveum user token add %s %s --privsep 0 --output-format json  (value goes into the bundle)\n' "$PVE_USER" "$TOKEN_ID"
  say "Dry run: nothing changed. Without --dry-run this prints: homelab-pulse-hosts add $LABEL <bundle>"
  exit 0
fi
SECRET=$(pveum user token add "$PVE_USER" "$TOKEN_ID" --privsep 0 --output-format json | json_get 'd["value"]')
BUNDLE=$(HOST="$HOST_IP" TOKEN="$PVE_USER!$TOKEN_ID=$SECRET" python3 -c '
import base64, json, os
ca = open(os.environ.get("PULSE_PVE_CA_SRC", "/etc/pve/pve-root-ca.pem")).read()
print(base64.b64encode(json.dumps({"host": os.environ["HOST"], "port": 8006, "token": os.environ["TOKEN"],
                                   "ca": ca}).encode()).decode())')

cat <<DONE

Done. In the Pulse container (on its own host: pct enter <its CT id>), paste this one line:

homelab-pulse-hosts add $LABEL $BUNDLE

It contains this host's read-only API token: don't share it. Pulse restarts and shows $NODE within a minute.
Undo: homelab-pulse-hosts remove $LABEL (in the container), then here: add-host.sh --remove
DONE
