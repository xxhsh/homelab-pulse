"""Discovery: find what runs in each guest without being told.

inventory (guest IPs from the Proxmox API) -> scan (TCP connect on a short port list) ->
fingerprint (one benign request per open port) -> classify (role + icon) -> plan_checks (the set of
health checks the collector runs). Only IPs the Proxmox API reports are ever scanned.

Pure functions take and return plain data; only Net touches the network, and tests swap it out.
"""
import html
import ipaddress
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import catalog
import probes
from sources import SourceError

AGENT_RETRY_S = 600          # a VM without the guest agent is asked again after 10 min
MISSES_TO_DROP = 2           # a service must be missing from 2 scans in a row before it's "gone"
MAX_TEXT = 80                # strings taken from scanned services are capped
GENERIC_TITLE = re.compile(r"(?i)^\s*(log ?in|sign ?in|login page|welcome|home|index( of .*)?|dashboard|untitled|"
                           r"redirect(ing)?.*|loading.*|404.*|403.*|401.*|error.*)\s*$")
SKIP_IFACE = re.compile(r"^(lo|docker|br-|veth|virbr|cni|flannel|cali|tailscale|wg|zt|tun)")


# ---------------------------------------------------------------- inventory

def extract_ips(ifaces):
    """Usable IPv4 addresses from LXC `/interfaces` or guest-agent `network-get-interfaces` output."""
    out = []
    for iface in ifaces or ():
        if SKIP_IFACE.match(iface.get("name", "")):
            continue
        cands = [a.get("ip-address") for a in iface.get("ip-addresses", ())
                 if a.get("ip-address-type") in ("ipv4", "inet")]
        if iface.get("inet"):
            cands.append(iface["inet"].split("/")[0])
        for c in cands:
            try:
                ip = ipaddress.IPv4Address(c)
            except (ValueError, TypeError):
                continue
            if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified) and str(ip) not in out:
                out.append(str(ip))
    return out


def _net_values(config, key):
    vals = []
    for k in sorted(config):
        if re.fullmatch(r"(net|ipconfig)\d+", k):
            m = re.search(rf"(?:^|,){key}=([0-9.]+)", str(config[k]))
            if m:
                vals.append(m.group(1))
    return vals


def static_ips(config):
    return _net_values(config, "ip")


def config_gateway(config):
    gws = _net_values(config, "gw")
    return gws[0] if gws else None


def pick_primary(ips, node_ip):
    """The address shown on the map and scanned: same /24 as the node when there is one."""
    if not ips:
        return None
    if node_ip:
        prefix = node_ip.rsplit(".", 1)[0] + "."
        for ip in ips:
            if ip.startswith(prefix):
                return ip
    return ips[0]


def guest_ips(pve, g, tags, agent_cache, now):
    """g: {node, type, vmid, running}. Explicit IP (tag/override) first, then live interfaces
    (LXC) or the QEMU guest agent, then static ip= from the config."""
    ips = [tags["ip"]] if tags.get("ip") else []
    live = []
    if g["running"]:
        try:
            if g["type"] == "lxc":
                live = extract_ips(pve.lxc_interfaces(g["node"], g["vmid"]))
            elif agent_cache.get(g["vmid"], 0) <= now:
                data = pve.agent_interfaces(g["node"], g["vmid"])
                live = extract_ips(data.get("result", data) if isinstance(data, dict) else data)
        except (SourceError, OSError, ValueError):
            if g["type"] == "qemu":
                agent_cache[g["vmid"]] = now + AGENT_RETRY_S   # no agent: don't ask on every poll
    if not live:
        try:
            live = static_ips(pve.guest_config(g["node"], g["type"], g["vmid"]))
        except (SourceError, OSError, ValueError):
            live = []
    return ips + [ip for ip in live if ip not in ips]


# ---------------------------------------------------------------- fingerprinting

@dataclass
class Finding:
    port: int
    kind: str                 # http | tls | dns | tcp  (the probe kind its check uses)
    product: str
    icon: str = "box"
    rank: int = 999           # lower = more specific (catalog rule index)
    scheme: str | None = None
    title: str | None = None
    server: str | None = None
    cert_cn: str | None = None
    cert_days: int | None = None
    banner: str | None = None

    def view(self):
        return {"port": self.port, "kind": self.kind, "product": self.product, "scheme": self.scheme}


def _clean(s):
    s = re.sub(r"\s+", " ", html.unescape(s or "")).strip()
    return s[:MAX_TEXT] or None


class Net:
    """The real network. connect() is the scan; fingerprint() is one benign look at an open port."""

    def __init__(self, timeout=1.5, fp_timeout=3.0, no_http=catalog.NO_HTTP):
        self.timeout, self.fp_timeout, self.no_http = timeout, fp_timeout, no_http

    def connect(self, ip, port):
        try:
            with socket.create_connection((ip, port), self.timeout):
                return True
        except OSError:
            return False

    def fingerprint(self, ip, port, dns_port=None):
        if port == 53:
            r = probes.probe_dns(ip, "doubleclick.net", timeout=self.fp_timeout, port=dns_port or 53)
            if r.ok:
                f = self._finding(port, "dns", "", None)
                if r.detail == "blocking ads":    # AdGuard Home / Pi-hole: their web UIs rarely say so
                    f.product, f.icon = "DNS + ad blocking", "shield"
                return f
        if port in self.no_http:
            return self._try_plain(ip, port) or self._finding(port, "tcp", "", None)
        if port in catalog.TLS_FIRST:
            return self._try_tls(ip, port) or self._try_plain(ip, port) or self._finding(port, "tcp", "", None)
        return self._try_plain(ip, port) or self._try_tls(ip, port) or self._finding(port, "tcp", "", None)

    # -- one connection each --

    def _try_plain(self, ip, port):
        try:
            with socket.create_connection((ip, port), self.fp_timeout) as s:
                s.settimeout(0.6)
                try:
                    first = s.recv(256)          # server-first protocols (SSH, FTP, SMTP…) greet us
                except (TimeoutError, socket.timeout):
                    first = b""
                if first:
                    banner = _clean(first.split(b"\n")[0].decode("latin-1"))
                    return self._finding(port, "tcp", f"banner: {banner}", None, banner=banner)
                if port in self.no_http:
                    return self._finding(port, "tcp", "", None)
                s.settimeout(self.fp_timeout)
                resp = self._http(s, ip, port, "/")
        except OSError:
            return None
        if resp is None:
            return None
        if resp["status"] == 400 and "https" in resp["body"].lower():
            return None                          # "plain HTTP sent to an HTTPS port": let TLS try
        resp = self._follow(ip, port, resp, None)
        return self._http_finding(port, "http", resp, None)

    def _try_tls(self, ip, port):
        ctx = probes.insecure_context()
        try:
            with socket.create_connection((ip, port), self.fp_timeout) as raw, \
                    ctx.wrap_socket(raw, server_hostname=None) as s:
                try:
                    cert = probes.cert_info(s.getpeercert(binary_form=True))
                except ValueError:
                    cert = {"cn": None, "not_after": None}
                resp = self._http(s, ip, port, "/")
        except (OSError, ssl.SSLError):
            return None
        days = int((cert["not_after"] - time.time()) // 86400) if cert["not_after"] else None
        if resp is None:
            return self._finding(port, "tls", f"cert: {cert['cn'] or ''}", "https", cert_cn=cert["cn"], cert_days=days)
        resp = self._follow(ip, port, resp, ctx)
        return self._http_finding(port, "tls", resp, "https", cert_cn=cert["cn"], cert_days=days)

    def _follow(self, ip, port, resp, ctx):
        """Follow one same-host redirect (apps love redirecting / to their login page)."""
        loc = resp["location"] or ""
        if resp["status"] not in (301, 302, 303, 307, 308) or not loc.startswith("/") or loc.startswith("//"):
            return resp
        try:
            with socket.create_connection((ip, port), self.fp_timeout) as raw:
                s = ctx.wrap_socket(raw, server_hostname=None) if ctx else raw
                nxt = self._http(s, ip, port, loc[:200])
        except (OSError, ssl.SSLError):
            return resp
        if nxt is None:
            return resp
        nxt["server"] = nxt["server"] or resp["server"]
        return nxt

    def _http(self, s, ip, port, path):
        """Minimal HTTP/1.0 GET on an open socket; None if the answer isn't HTTP."""
        s.sendall(f"GET {path} HTTP/1.0\r\nHost: {ip}:{port}\r\nUser-Agent: homelab-pulse\r\n"
                  f"Accept: text/html\r\nConnection: close\r\n\r\n".encode())
        buf, deadline = b"", time.monotonic() + self.fp_timeout
        while len(buf) < 65536 and time.monotonic() < deadline:
            try:
                chunk = s.recv(8192)
            except (TimeoutError, socket.timeout, ssl.SSLError):
                break
            if not chunk:
                break
            buf += chunk
        if not buf.startswith(b"HTTP/"):
            return None
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            return None
        hdrs = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            hdrs[k.strip().lower()] = v.strip()
        text = body.decode("utf-8", "replace")
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        return {"status": status, "server": _clean(hdrs.get("server")), "location": hdrs.get("location"),
                "title": _clean(m.group(1)) if m else None, "body": re.sub(r"<[^>]+>", " ", text[:4000])}

    def _http_finding(self, port, kind, resp, scheme, **extra):
        blob = (f"title: {resp['title'] or ''} server: {resp['server'] or ''} location: {resp['location'] or ''} "
                f"body: {resp['body'][:2000]} cert: {extra.get('cert_cn') or ''}")
        return self._finding(port, kind, blob, scheme or "http", web=True, title=resp["title"], server=resp["server"],
                             **extra)

    @staticmethod
    def _finding(port, kind, blob, scheme, web=False, **extra):
        hit = catalog.identify(blob.lower(), port)
        if hit:
            product, icon, rank = hit
        elif extra.get("title") and not GENERIC_TITLE.match(extra["title"]):
            product, icon, rank = extra["title"][:40], "globe", 100 + len(catalog.RULES)
        elif web:
            product, icon, rank = "Web app", "globe", 200 + len(catalog.RULES)
        elif kind == "tls":
            product, icon, rank = "TLS service", "lock", 200 + len(catalog.RULES)
        else:
            product, icon, rank = "TCP service", "box", 300 + len(catalog.RULES)
        return Finding(port=port, kind=kind, product=product, icon=icon, rank=rank, scheme=scheme, **extra)


def scan(net, ip, ports, workers=4):
    """Open ports on one IP, at most `workers` connects at a time."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        flags = list(pool.map(lambda p: net.connect(ip, p), ports))
    return [p for p, ok in zip(ports, flags) if ok]


# ---------------------------------------------------------------- service lifecycle

class Discoverer:
    """Remembers what each target runs. A target is {key, ip, name, running, scan, ports}; key is
    a VMID or "router". Targets that are stopped, unscannable or address-less keep what they had."""

    def __init__(self, net, guests_in_parallel=4, per_guest=4):
        self.net, self.parallel, self.per_guest = net, guests_in_parallel, per_guest
        self.known = {}       # key -> {port: Finding}
        self.misses = {}      # (key, port) -> consecutive misses
        self.first_run = True

    def services(self, key):
        return sorted(self.known.get(key, {}).values(), key=lambda f: f.port)

    def forget(self, keep):
        for key in [k for k in list(self.known) if k not in keep]:
            self.known.pop(key, None)
            self.misses = {k: v for k, v in self.misses.items() if k[0] != key}

    def _look(self, t, ports):
        open_ = scan(self.net, t["ip"], tuple(t.get("ports") or ports), self.per_guest)
        found = {}
        for p in open_:
            try:
                found[p] = self.net.fingerprint(t["ip"], p)
            except Exception:  # noqa: BLE001 - an odd service mustn't stop discovery
                found[p] = Finding(port=p, kind="tcp", product="TCP service")
        return t, found

    def run(self, targets, ports):
        """Scan targets, update memory, return activity events."""
        events, todo = [], []
        for t in targets:
            if not t.get("scan", True):
                self.known[t["key"]] = {}
            elif t.get("running") and t.get("ip"):
                todo.append(t)
        with ThreadPoolExecutor(max_workers=self.parallel) as pool:
            results = list(pool.map(lambda t: self._look(t, ports), todo))
        now = time.time()
        for t, found in results:
            # build a new map and swap it in: other threads may be reading the old one
            key, have = t["key"], dict(self.known.get(t["key"], {}))
            for p, f in found.items():
                self.misses.pop((key, p), None)
                if p not in have and not self.first_run:
                    events.append({"ts": now, "kind": "discovery", "level": "info",
                                   "text": f"Found {f.product} on {t['name']}"})
                have[p] = f
            for p in [p for p in have if p not in found]:
                n = self.misses[(key, p)] = self.misses.get((key, p), 0) + 1
                if n >= MISSES_TO_DROP:
                    events.append({"ts": now, "kind": "discovery", "level": "warn",
                                   "text": f"{have[p].product} on {t['name']} is gone"})
                    del have[p]
                    del self.misses[(key, p)]
            self.known[key] = have
        self.first_run = False
        return events


# ---------------------------------------------------------------- classification + checks

def classify(findings, name, ostype, kind):
    """(role, icon) for a guest: the most specific recognised service, else a guess from its name."""
    named = [f for f in findings if f.rank < len(catalog.RULES) and f.product not in catalog.GENERIC]
    if named:
        best = min(named, key=lambda f: f.rank)
        return best.product, best.icon
    return catalog.guess_from_name(name, ostype, kind)


def check_for(key, ip, f, guest_name):
    spec = {"id": f"{key}:{f.port}", "name": f.product}
    if f.kind == "dns":
        spec.update(kind="dns", server=ip, qname="doubleclick.net")
    elif f.kind == "tls":
        spec.update(kind="tls", host=ip, port=f.port, verify=False)
    elif f.kind == "http":
        spec.update(kind="http", url=f"{f.scheme or 'http'}://{ip}:{f.port}/")
    else:
        spec.update(kind="tcp", host=ip, port=f.port)
    spec.update(target=key, port=f.port, product=f.product, guest=guest_name, source="discovered")
    return spec


def _check_port(c):
    if "port" in c:
        return c["port"]
    m = re.match(r"\w+://[^/:]+(?::(\d+))?", c.get("url", ""))
    if m:
        return int(m.group(1)) if m.group(1) else (443 if c["url"].startswith("https") else 80)
    return 53 if c.get("kind") == "dns" else None


def plan_checks(services, guests, router, nodes, ov, ca_path):
    """The full check set: builtin (internet, router, each node's Proxmox UI) + discovered +
    override checks (replacing a discovered one on the same target and port) - hide_checks."""
    checks = []
    if ov.get("internet") is not False:
        inet = ov.get("internet") or {}
        checks.append({"id": "internet", "name": "Internet", "kind": "tcp", "host": inet.get("host", "1.1.1.1"),
                       "port": inet.get("port", 443), "target": "internet", "source": "builtin"})
    if router and router.get("ip"):
        for f in services.get("router", ()):
            checks.append(dict(check_for("router", router["ip"], f, router.get("name") or "Router"),
                               name=router.get("name") or "Router"))
    for n in nodes:
        if n.get("ip"):
            c = {"id": f"node:{n['name']}", "name": "Proxmox UI" if len(nodes) == 1 else f"Proxmox UI ({n['name']})",
                 "kind": "tls", "host": n["ip"], "port": 8006, "sni": n["name"], "target": n["name"],
                 "source": "builtin"}
            ca = ca_path(n["name"]) if callable(ca_path) else ca_path   # one CA per standalone host
            c.update(cafile=ca) if ca else c.update(verify=False)
            checks.append(c)
    for g in guests:
        if g.get("ip"):
            checks += [check_for(g["vmid"], g["ip"], f, g["name"]) for f in services.get(g["vmid"], ())
                       if f.product not in catalog.QUIET]
    for o in ov.get("checks", ()):
        o = dict(o, source="override")
        tgt = o.get("target")
        tgt = int(tgt) if isinstance(tgt, str) and tgt.isdigit() else tgt
        o["target"] = tgt
        checks = [c for c in checks if c["id"] != o["id"]
                  and not (c["source"] == "discovered" and c["target"] == tgt and c.get("port") == _check_port(o))]
        checks.append(o)
    hidden = set(ov.get("hide_checks", ()))
    return [c for c in checks if c["id"] not in hidden]
