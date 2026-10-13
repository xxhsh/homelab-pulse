"""Early warnings: problems that aren't outages yet. Pure functions over a collector snapshot.

Each warning is a condition {key: "warn:<rule>:<subject>", kind: "warning", severity, title, target}
for the alert engine. Storage forecasts use Proxmox's own RRD history (hourly averages), so they
work from the first minute instead of after weeks of Pulse running.
"""
import re

D = 86400
FORECAST_DAYS = 14
MIN_POINTS = 48
MIN_R2 = 0.5
_CERT = re.compile(r"cert (-?\d+) days left")


def forecast_days(points, total, now):
    """Days until `total` is reached, from a least-squares line over the last 14 days of
    (time, used) points. None when there isn't a clear upward trend."""
    pts = [(t, u) for t, u in points if u is not None and t >= now - FORECAST_DAYS * D]
    if len(pts) < MIN_POINTS or not total:
        return None
    n = len(pts)
    mt = sum(t for t, _ in pts) / n
    mu = sum(u for _, u in pts) / n
    sxx = sum((t - mt) ** 2 for t, _ in pts)
    sxy = sum((t - mt) * (u - mu) for t, u in pts)
    syy = sum((u - mu) ** 2 for _, u in pts)
    if sxx == 0 or syy == 0:
        return None
    slope = sxy / sxx
    r2 = sxy * sxy / (sxx * syy)
    if slope <= 0 or r2 < MIN_R2:
        return None
    return max(0.0, (total - pts[-1][1]) / slope / D)


def _cond(rule, subject, severity, title, target, node=None):
    return {"key": f"warn:{rule}:{subject}", "kind": "warning", "severity": severity, "title": title,
            "target": target, "node": node}


def _storage(cfg, sid, label, used, total, points, now, subject, target):
    if not total:
        return None
    pct = used / total * 100
    days = forecast_days(points or [], total, now)
    sev = None
    if pct > cfg["crit_pct"] or (days is not None and days < cfg["crit_days"]):
        sev = "critical"
    elif pct > cfg["warn_pct"] or (days is not None and days < cfg["warn_days"]):
        sev = "warning"
    if not sev:
        return None
    trend = days is not None and days < (cfg["crit_days"] if sev == "critical" else cfg["warn_days"])
    title = f"{label} full in ~{round(days)} days" if trend else f"{label} {round(pct)} % full"
    return _cond("storage_full", subject, sev, title, target, target)


def evaluate(snapshot, storage_hist, cfg, state, now):
    """-> list of conditions. `state` is a dict the caller keeps between calls (memory timers)."""
    out = []
    nodes = [n for n in snapshot.get("nodes", []) if n.get("online")]
    multi = len(snapshot.get("nodes", [])) > 1

    c = cfg["storage_full"]
    if c["enabled"]:
        for n in nodes:
            for s in n.get("storage", []):
                label = f"{s['id']} on {n['name']}" if multi else s["id"]
                w = _storage(c, s["id"], label, s["used"], s["total"], storage_hist.get((n["name"], s["id"])), now,
                             f"{n['name']}/{s['id']}", n["name"])
                if w:
                    out.append(w)
        for s in snapshot.get("shared_storage", []):
            w = _storage(c, s["id"], s["id"], s["used"], s["total"], storage_hist.get(("*", s["id"])), now,
                         s["id"], None)
            if w:
                out.append(w)

    c = cfg["cert_expiry"]
    if c["enabled"]:
        for p in snapshot.get("probes", []):
            m = _CERT.search(p.get("detail") or "") if p.get("kind") == "tls" else None
            if not m:
                continue
            days = int(m.group(1))
            if days > c["warn_days"]:
                continue
            name = f"{p['name']} ({p['guest']})" if p.get("guest") else p["name"]
            title = f"Certificate for {name} has expired" if days < 0 else f"Certificate for {name} expires in {days} days"
            out.append(_cond("cert_expiry", p["id"], "critical" if days <= c["crit_days"] else "warning", title,
                             p.get("target")))

    for n in nodes:
        for d in n.get("disks", []):
            dev = (d.get("dev") or "").rsplit("/", 1)[-1]
            subject = f"{n['name']}/{dev}"
            wear = d.get("wear_used")
            c = cfg["ssd_wear"]
            if c["enabled"] and wear is not None and wear >= c["warn_pct"]:
                out.append(_cond("ssd_wear", subject, "critical" if wear >= c["crit_pct"] else "warning",
                                 f"{d.get('model') or dev} on {n['name']} is {wear} % worn", n["name"], n["name"]))
            health = (d.get("health") or "").upper()
            if cfg["smart"]["enabled"] and health and health not in ("PASSED", "OK", "UNKNOWN"):
                out.append(_cond("smart", subject, "critical",
                                 f"{d.get('model') or dev} on {n['name']}: SMART says {d['health']}", n["name"],
                                 n["name"]))

    c = cfg["backup_stale"]
    if c["enabled"] and snapshot.get("backups"):
        for g in snapshot["backups"].get("guests", []):
            if g.get("error"):
                out.append(_cond("backup_stale", g["vmid"], "warning",
                                 f"{g['name']}: last backup failed ({g['error'][:60]})", g["vmid"]))
            elif g.get("ts") and now - g["ts"] > c["hours"] * 3600:
                age = now - g["ts"]
                age_txt = f"{round(age / D)} days" if age >= 2 * D else f"{round(age / 3600)} hours"
                out.append(_cond("backup_stale", g["vmid"], "warning", f"{g['name']} has no backup for {age_txt}",
                                 g["vmid"]))

    c = cfg["node_memory"]
    since = state.setdefault("mem_since", {})
    for n in nodes:
        over = c["enabled"] and n.get("maxmem") and n["mem"] / n["maxmem"] * 100 > c["pct"]
        if not over:
            since.pop(n["name"], None)
            continue
        first = since.setdefault(n["name"], now)
        if now - first >= c["minutes"] * 60:
            out.append(_cond("node_memory", n["name"], "warning",
                             f"{n['name']} memory {round(n['mem'] / n['maxmem'] * 100)} % used", n["name"],
                             n["name"]))

    c = cfg["ct_disk"]
    if c["enabled"]:
        for g in snapshot.get("guests", []):
            if g.get("type") != "lxc" or not g.get("running") or not g.get("maxdisk"):
                continue
            pct = g["disk"] / g["maxdisk"] * 100
            if pct > c["warn_pct"]:
                out.append(_cond("ct_disk", g["vmid"], "critical" if pct > c["crit_pct"] else "warning",
                                 f"{g['name']} disk {round(pct)} % full", g["vmid"]))

    c = cfg["vm_disk"]
    if c["enabled"]:
        for g in snapshot.get("guests", []):
            if g.get("type") != "qemu" or not g.get("running"):
                continue
            fss = g.get("fs") or []
            for f in fss:
                if not f.get("total"):
                    continue
                pct = f["used"] / f["total"] * 100
                if pct > c["warn_pct"]:
                    where = "disk" if len(fss) == 1 or f["mount"] in ("/", "C:\\") else f["mount"]
                    out.append(_cond("vm_disk", f"{g['vmid']}:{f['mount']}",
                                     "critical" if pct > c["crit_pct"] else "warning",
                                     f"{g['name']} {where} {round(pct)} % full", g["vmid"]))
    return out
