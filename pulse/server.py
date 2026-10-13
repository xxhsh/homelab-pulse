#!/usr/bin/env python3
"""Homelab Pulse: a live, self-discovering map of a Proxmox homelab. Python stdlib only.

Routes (open):     /  (UI, ?embed hides header/footer)  /settings  /api/state  /api/stream (SSE)
                   /api/history/<vmid|node>  /api/rrd/<vmid|node>?range=  /api/uptime  /api/session  /healthz
Routes (admin):    /api/login /api/logout /api/settings /api/test-notify /api/deliveries /api/mutes
                   /api/password /api/alerts/<key>/clear  (writes also need the X-Pulse-Request header)
Config comes from the environment (see env.example) and the optional overrides file.
"""
import json
import logging
import os
import re
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import alerts
import auth
import collect
import demo
import discover
import notify
import probes
import settings as settings_mod
import sources
import store as store_mod

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".svg": "image/svg+xml",
                 ".webmanifest": "application/manifest+json", ".js": "text/javascript"}
log = logging.getLogger("pulse")
MAX_BODY = 64 * 1024
HEALTH_SOURCES = ("pve", "probes", "discovery")
COOKIE = "pulse_session"
MUTE_TARGET = re.compile(r"(check|guest|node|warn|backup|source):[\w.:/-]{1,120}")


def _read_secret(path):
    try:
        return Path(path).read_text().strip() or None
    except OSError:
        return None


def _guess_url(port):
    """http://<this container's LAN address>/ for links in notifications (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
            sk.connect(("1.1.1.1", 80))
            ip = sk.getsockname()[0]
    except OSError:
        ip = "localhost"
    return f"http://{ip}{'' if port == 80 else f':{port}'}/"


def read_env_file(path):
    """KEY=VALUE lines, as systemd's EnvironmentFile reads them (comments and blanks skipped)."""
    out = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def extra_hosts(dirpath):
    """Additional standalone Proxmox hosts: one <label>.env file each in `dirpath`, with the same
    PULSE_PVE_HOST / _PORT / _TOKEN_FILE / _CA / _TLS_NAME keys as the main env file.
    -> [(label, settings)] sorted by label; a file without a host or token is reported and skipped."""
    out = []
    try:
        files = sorted(Path(dirpath).glob("*.env"))
    except OSError:
        return out
    for f in files:
        try:
            e = read_env_file(f)
        except OSError as err:
            log.error("extra host %s: %s", f.name, err)
            continue
        token = _read_secret(e.get("PULSE_PVE_TOKEN_FILE", ""))
        if not e.get("PULSE_PVE_HOST") or not token:
            log.error("extra host %s: needs PULSE_PVE_HOST and a readable PULSE_PVE_TOKEN_FILE; skipped", f.name)
            continue
        out.append((f.stem, {"host": e["PULSE_PVE_HOST"], "port": int(e.get("PULSE_PVE_PORT", 8006)), "token": token,
                             "ca": e.get("PULSE_PVE_CA") or None, "tls_name": e.get("PULSE_PVE_TLS_NAME") or None}))
    return out


def build_collector(env=os.environ):
    pve_mode = env.get("PULSE_PVE", "demo")
    ca = env.get("PULSE_PVE_CA", "/etc/homelab-pulse/pve-ca.pem")
    ov = env.get("PULSE_OVERRIDES", "/etc/homelab-pulse/overrides.json")
    public_url = env.get("PULSE_PUBLIC_URL") or _guess_url(int(env.get("PULSE_PORT", 80)))
    if pve_mode != "live":
        st = store_mod.Store(":memory:")
        st.put("admin", auth.hash_password("demo", iterations=1000))
        net = demo.DemoNet()
        c = collect.Collector(demo.DemoPve(), "demo", net, probe_fn=net.probe, overrides_path=ov, ca_path=ca,
                              store=st, notifier=notify.Notifier(st, public_url))
        c.demo, c.admin_ready = True, True
        return c
    host = env.get("PULSE_PVE_HOST")
    if not host:
        sys.exit("PULSE_PVE=live needs PULSE_PVE_HOST (the IP of a Proxmox node)")
    token = _read_secret(env.get("PULSE_PVE_TOKEN_FILE", "/etc/homelab-pulse/pve-token"))
    if not token:
        sys.exit("PULSE_PVE=live but the token file is missing or empty")
    db = env.get("PULSE_DB") or str(Path(env.get("STATE_DIRECTORY", "/var/lib/homelab-pulse").split(":")[0]) / "pulse.db")
    st = store_mod.Store(db)
    pve = sources.PveClient(host, int(env.get("PULSE_PVE_PORT", 8006)), token, ca, env.get("PULSE_PVE_TLS_NAME") or None)
    extra = extra_hosts(env.get("PULSE_PVE_HOSTS_DIR", "/etc/homelab-pulse/hosts.d"))
    if extra:
        log.info("watching %d Proxmox hosts: %s", 1 + len(extra), ", ".join([host] + [h["host"] for _, h in extra]))
        pve = sources.MultiPve([("primary", pve)] + [
            (label, sources.PveClient(h["host"], h["port"], h["token"], h["ca"], h["tls_name"])) for label, h in extra])
    c = collect.Collector(pve, "live", discover.Net(), probe_fn=probes.run, overrides_path=ov, ca_path=ca,
                          store=st, notifier=notify.Notifier(st, public_url))
    c.demo = False
    c.admin_ready = auth.ensure_admin(st, env.get("PULSE_ADMIN_PASSWORD_FILE", "/etc/homelab-pulse/admin-password"))
    return c


def make_handler(collector):
    st = collector.store
    sessions = auth.Sessions(st, collector.clock)
    limiter = auth.RateLimiter(clock=collector.clock)
    demo_mode = getattr(collector, "demo", False)

    class Handler(BaseHTTPRequestHandler):
        server_version = "pulse"
        sys_version = ""

        def log_message(self, fmt, *args):
            log.debug("%s " + fmt, self.client_address[0], *args)

        def _send(self, code, body, ctype="application/json", cache="no-store", cookie=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, separators=(",", ":")).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        # -- auth helpers --

        def _cookie_value(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == COOKIE:
                    return v
            return None

        def _signed_in(self):
            return sessions.valid(self._cookie_value())

        def _cookie(self, value, max_age):
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
            return f"{COOKIE}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}"

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise _HttpError(413, "request too large")
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise _HttpError(400, "invalid JSON") from None

        def _guard(self, need_session=True):
            """Every write needs the X-Pulse-Request header (blocks cross-site forms) and, except
            for login, a valid session."""
            if self.headers.get("X-Pulse-Request") != "1":
                raise _HttpError(403, "missing X-Pulse-Request header")
            if need_session and not self._signed_in():
                raise _HttpError(401, "sign in first")

        def _need_session(self):
            if not self._signed_in():
                raise _HttpError(401, "sign in first")

        def _dispatch(self, fn):
            try:
                fn()
            except _HttpError as e:
                self._send(e.code, {"error": e.message, **e.extra})

        def do_POST(self):
            self._dispatch(self._post)

        def do_PUT(self):
            self._dispatch(self._put)

        def do_DELETE(self):
            self._dispatch(self._delete)

        # -- admin API --

        def _post(self):
            path = urllib.parse.unquote(self.path.split("?", 1)[0])
            if path == "/api/login":
                self._guard(need_session=False)
                ip = self.client_address[0]
                if limiter.blocked(ip):
                    raise _HttpError(429, "too many attempts; wait a minute")
                pw = str(self._body().get("password", ""))
                if not st.get("admin"):
                    raise _HttpError(503, "no admin password set; run homelab-pulse-passwd in the container")
                if not auth.verify_password(pw, st.get("admin")):
                    limiter.fail(ip)
                    log.warning("failed settings sign-in from %s", ip)
                    raise _HttpError(401, "wrong password")
                return self._send(200, {"ok": True}, cookie=self._cookie(sessions.issue(), auth.SESSION_MAX_AGE))
            self._guard()
            if path == "/api/logout":
                return self._send(200, {"ok": True}, cookie=self._cookie("", 0))
            if path == "/api/test-notify":
                channel = self._body().get("channel")
                if channel not in ("webhook", "ntfy"):
                    raise _HttpError(400, "channel must be webhook or ntfy")
                n = alerts.Notification("Test from Homelab Pulse", "If you can read this, alerts will reach you.",
                                        "info", "test", [], collector.clock())
                results = collector.notifier.send_now(n, collector.settings_loader()["notify"], channel=channel)
                return self._send(200, {"results": results})
            if path == "/api/mutes":
                b = self._body()
                target = str(b.get("target", ""))
                if not MUTE_TARGET.fullmatch(target):
                    raise _HttpError(400, "invalid mute target")
                minutes = b.get("minutes")
                if minutes is not None and (not isinstance(minutes, int) or not 1 <= minutes <= 60 * 24 * 30):
                    raise _HttpError(400, "minutes must be 1 to 43200")
                st.add_mute(target, collector.clock() + minutes * 60 if minutes else None, bool(b.get("until_recovered")))
                return self._send(200, {"ok": True})
            if path == "/api/password":
                b = self._body()
                if not auth.verify_password(str(b.get("current", "")), st.get("admin")):
                    raise _HttpError(403, "the current password is wrong")
                try:
                    auth.change_password(st, sessions, str(b.get("new", "")))
                except ValueError as e:
                    raise _HttpError(400, str(e)) from None
                return self._send(200, {"ok": True}, cookie=self._cookie("", 0))
            m = re.fullmatch(r"/api/alerts/(.{1,200})/clear", path)
            if m:
                collector.clear_alert(m.group(1))
                return self._send(200, {"ok": True})
            raise _HttpError(404, "not found")

        def _put(self):
            if self.path.split("?", 1)[0] != "/api/settings":
                raise _HttpError(404, "not found")
            self._guard()
            current = settings_mod.load(st)
            try:
                doc = settings_mod.validate(settings_mod.merge_masked(self._body(), current))
            except settings_mod.SettingsError as e:
                raise _HttpError(400, e.message, path=e.path) from None
            st.put("config", doc)
            self._send(200, {"settings": settings_mod.mask(doc)})

        def _delete(self):
            path = urllib.parse.unquote(self.path.split("?", 1)[0])
            if not path.startswith("/api/mutes/"):
                raise _HttpError(404, "not found")
            self._guard()
            st.remove_mute(path[len("/api/mutes/"):])
            self._send(200, {"ok": True})

        def _get_admin(self, path):
            self._need_session()
            if path == "/api/settings":
                return self._send(200, {"settings": settings_mod.mask(settings_mod.load(st)), "demo": demo_mode})
            if path == "/api/deliveries":
                return self._send(200, {"deliveries": st.deliveries()})
            return self._send(200, {"mutes": st.list_mutes(collector.clock())})

        def do_GET(self):
            self._dispatch(self._get)

        def _get(self):
            path, _, query = self.path.partition("?")
            if path in ("/api/settings", "/api/deliveries", "/api/mutes"):
                return self._get_admin(path)
            if path == "/api/session":
                return self._send(200, {"signed_in": self._signed_in(), "admin_set": bool(st.get("admin")),
                                        "demo": demo_mode})
            if path == "/api/uptime":
                return self._send(200, collector.uptime())
            if path.startswith("/api/rrd/"):
                key = urllib.parse.unquote(path[len("/api/rrd/"):])
                rng = urllib.parse.parse_qs(query).get("range", ["day"])[0]
                series = collector.rrd_series(int(key) if key.isdigit() else key, rng) if "/" not in key else None
                return self._send(200, series) if series else self._send(404, {"error": "unknown"})
            if path == "/settings":
                path = "/settings.html"
            if path == "/":
                path = "/index.html"
            if path == "/api/state":
                return self._send(200, collector.snapshot())
            if path == "/api/stream":
                return self._stream()
            if path == "/healthz":
                src = collector.snapshot()["sources"]
                ok = all(src[k]["ok"] is not False for k in HEALTH_SOURCES if k in src)
                return self._send(200 if ok else 503, {"ok": ok, "sources": src})
            if path.startswith("/api/history/"):
                key = path[len("/api/history/"):]
                hist = collector.history_for(int(key) if key.isdigit() else key) if "/" not in key else None
                return self._send(200, hist) if hist else self._send(404, {"error": "unknown"})
            f = (STATIC / path.lstrip("/")).resolve()
            if f.parent == STATIC and f.is_file() and f.suffix in CONTENT_TYPES:
                return self._send(200, f.read_bytes(), CONTENT_TYPES[f.suffix], "no-cache")
            return self._send(404, {"error": "not found"})

        def _stream(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            seen = -1
            try:
                while True:
                    with collector.cond:
                        collector.cond.wait_for(lambda: collector.version != seen, timeout=15)
                        changed = collector.version != seen
                    if changed:
                        snap = collector.snapshot()
                        seen = snap["version"]
                        self.wfile.write(b"data: " + json.dumps(snap, separators=(",", ":")).encode() + b"\n\n")
                    else:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass

    return Handler


class _HttpError(Exception):
    def __init__(self, code, message, **extra):
        super().__init__(message)
        self.code, self.message, self.extra = code, message, extra


def serve(collector, host="0.0.0.0", port=80):
    server = ThreadingHTTPServer((host, port), make_handler(collector))
    server.daemon_threads = True
    return server


def main():
    logging.basicConfig(level=os.environ.get("PULSE_LOG", "INFO"), format="%(levelname)s %(message)s")
    collector = build_collector()
    if not collector.admin_ready:
        log.warning("no admin password: settings are locked until homelab-pulse-passwd is run")
    collector.notifier.start()
    collector.start()
    port = int(os.environ.get("PULSE_PORT", 80))
    server = serve(collector, os.environ.get("PULSE_BIND", "0.0.0.0"), port)
    log.info("homelab-pulse on :%d (proxmox=%s)", port, collector.sources["pve"]["mode"])
    server.serve_forever()


if __name__ == "__main__":
    main()
