#!/usr/bin/env python3
"""Manage the extra Proxmox hosts this Pulse watches (standalone hosts that aren't in its cluster).

Run as root inside the Pulse container:
    homelab-pulse-hosts add LABEL BUNDLE   # BUNDLE is printed by add-host.sh on the other host ("-": stdin)
    homelab-pulse-hosts list
    homelab-pulse-hosts remove LABEL
Each host is one /etc/homelab-pulse/hosts.d/LABEL.env file plus its token and CA next to it. The
service is restarted afterwards unless --no-restart is given.
"""
import argparse
import base64
import binascii
import json
import os
import re
import subprocess
import sys
from pathlib import Path

LABEL = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
TOKEN = re.compile(r"[\w.-]+@[\w.-]+![\w.-]+=[0-9a-fA-F-]{8,}")
HOSTNAME = re.compile(r"[A-Za-z0-9.:-]{1,253}")


class HostError(ValueError):
    pass


def decode_bundle(text):
    """add-host.sh output -> {host, port, token, ca}. Validated, since it ends up in config files."""
    try:
        b = json.loads(base64.b64decode(text.strip(), validate=True))
    except (binascii.Error, ValueError):
        raise HostError("that isn't a bundle from add-host.sh (copy the whole line it printed)") from None
    if not isinstance(b, dict):
        raise HostError("that isn't a bundle from add-host.sh")
    host, port, token, ca = b.get("host"), b.get("port", 8006), b.get("token"), b.get("ca")
    if not isinstance(host, str) or not HOSTNAME.fullmatch(host):
        raise HostError("the bundle has no valid host address")
    if not isinstance(port, int) or not 0 < port < 65536:
        raise HostError("the bundle has no valid port")
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise HostError("the bundle has no valid API token")
    if not isinstance(ca, str) or "BEGIN CERTIFICATE" not in ca:
        raise HostError("the bundle has no CA certificate")
    return {"host": host, "port": port, "token": token, "ca": ca}


def add(d, label, bundle, owner=None):
    """Write LABEL.env, LABEL.token (640) and LABEL-ca.pem into `d`. owner: (uid, gid) for the token."""
    if not LABEL.fullmatch(label) or label == "primary":
        raise HostError("the label must be lowercase letters, digits and dashes (and not 'primary')")
    b = decode_bundle(bundle)
    d = Path(d)
    d.mkdir(parents=True, exist_ok=True)
    token, ca = d / f"{label}.token", d / f"{label}-ca.pem"
    fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w") as f:
        f.write(b["token"] + "\n")
    os.chmod(token, 0o640)
    if owner:
        os.chown(token, 0, owner[1])
    ca.write_text(b["ca"] if b["ca"].endswith("\n") else b["ca"] + "\n")
    os.chmod(ca, 0o644)
    env = d / f"{label}.env"
    env.write_text(f"# {label}: added by homelab-pulse-hosts\nPULSE_PVE_HOST={b['host']}\nPULSE_PVE_PORT={b['port']}\n"
                   f"PULSE_PVE_TOKEN_FILE={token}\nPULSE_PVE_CA={ca}\n")
    os.chmod(env, 0o644)
    return b


def remove(d, label):
    if not LABEL.fullmatch(label):
        raise HostError("no such host")
    gone = [p for p in (Path(d) / f"{label}.env", Path(d) / f"{label}.token", Path(d) / f"{label}-ca.pem")
            if p.exists()]
    if not gone:
        raise HostError(f"no host called {label}")
    for p in gone:
        p.unlink()


def listing(d):
    out = []
    for f in sorted(Path(d).glob("*.env")):
        host = next((line.split("=", 1)[1].strip() for line in f.read_text().splitlines()
                     if line.startswith("PULSE_PVE_HOST=")), "?")
        out.append((f.stem, host))
    return out


def _pulse_gid():
    import grp
    try:
        return grp.getgrnam("pulse").gr_gid
    except KeyError:
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default=os.environ.get("PULSE_PVE_HOSTS_DIR", "/etc/homelab-pulse/hosts.d"))
    ap.add_argument("--no-restart", action="store_true", help="don't restart the service afterwards")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a_add = sub.add_parser("add", help="add or replace a host")
    a_add.add_argument("label")
    a_add.add_argument("bundle", help="the bundle add-host.sh printed, or - to read it from stdin")
    a_rm = sub.add_parser("remove", help="stop watching a host")
    a_rm.add_argument("label")
    sub.add_parser("list", help="show the extra hosts")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "list":
            rows = listing(a.dir) if Path(a.dir).is_dir() else []
            print("\n".join(f"{label}\t{host}" for label, host in rows) or "No extra hosts.")
            return 0
        if a.cmd == "add":
            gid = _pulse_gid() if os.geteuid() == 0 else None
            b = add(a.dir, a.label, sys.stdin.read() if a.bundle == "-" else a.bundle,
                    owner=(0, gid) if gid is not None else None)
            print(f"Added {a.label} ({b['host']}).")
        else:
            remove(a.dir, a.label)
            print(f"Removed {a.label}.")
    except HostError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    if not a.no_restart and os.geteuid() == 0:
        subprocess.run(["systemctl", "restart", "homelab-pulse"], check=False)
        print("Restarted homelab-pulse.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
