"""Alert, notification and warning settings: defaults, validation and masking of secrets.

Stored as one JSON document in the store (key "config") and edited on the settings page. Secrets
(the ntfy token and webhook header values) only ever leave the server masked as "••••" + last 4.
"""
import copy
import re

MASK = "••••"

DEFAULTS = {
    "notify": {
        "webhook": {"enabled": False, "url": "", "headers": {}, "insecure": False},
        "ntfy": {"enabled": False, "server": "https://ntfy.sh", "topic": "", "token": "", "insecure": False},
    },
    "alerts": {
        "down_after_s": 180, "send_recovery": True, "repeat_every_s": 0, "group_window_s": 60,
        "kinds": {"service_down": True, "node_offline": True, "api_down": True, "guest_stopped": True,
                  "backup_failed": True, "warning": True},
        "quiet": {"enabled": False, "start": "23:00", "end": "07:00", "critical_too": False},
    },
    "warnings": {
        "storage_full": {"enabled": True, "warn_days": 30, "crit_days": 7, "warn_pct": 85, "crit_pct": 95},
        "cert_expiry": {"enabled": True, "warn_days": 21, "crit_days": 7},
        "ssd_wear": {"enabled": True, "warn_pct": 80, "crit_pct": 90},
        "smart": {"enabled": True},
        "backup_stale": {"enabled": True, "hours": 48},
        "node_memory": {"enabled": True, "pct": 90, "minutes": 15},
        "ct_disk": {"enabled": True, "warn_pct": 90, "crit_pct": 97},
        "vm_disk": {"enabled": True, "warn_pct": 90, "crit_pct": 97},
    },
}


class SettingsError(ValueError):
    def __init__(self, path, message):
        super().__init__(f"{path}: {message}")
        self.path, self.message = path, message


def _int(lo, hi):
    return ("int", lo, hi)


URL = ("url",)
TIME = ("time",)
HEADERS = ("headers",)
TOPIC = ("str", r"[A-Za-z0-9_-]{0,64}")
SECRET = ("str", r"[^\r\n]{0,512}")
BOOL = ("bool",)
PCT = _int(1, 100)
DAYS = _int(0, 3650)

SCHEMA = {
    "notify": {
        "webhook": {"enabled": BOOL, "url": URL, "headers": HEADERS, "insecure": BOOL},
        "ntfy": {"enabled": BOOL, "server": URL, "topic": TOPIC, "token": SECRET, "insecure": BOOL},
    },
    "alerts": {
        "down_after_s": _int(0, 86400), "send_recovery": BOOL, "repeat_every_s": _int(0, 7 * 86400),
        "group_window_s": _int(0, 3600),
        "kinds": {k: BOOL for k in DEFAULTS["alerts"]["kinds"]},
        "quiet": {"enabled": BOOL, "start": TIME, "end": TIME, "critical_too": BOOL},
    },
    "warnings": {
        "storage_full": {"enabled": BOOL, "warn_days": DAYS, "crit_days": DAYS, "warn_pct": PCT, "crit_pct": PCT},
        "cert_expiry": {"enabled": BOOL, "warn_days": DAYS, "crit_days": DAYS},
        "ssd_wear": {"enabled": BOOL, "warn_pct": PCT, "crit_pct": PCT},
        "smart": {"enabled": BOOL},
        "backup_stale": {"enabled": BOOL, "hours": _int(1, 24 * 365)},
        "node_memory": {"enabled": BOOL, "pct": PCT, "minutes": _int(1, 1440)},
        "ct_disk": {"enabled": BOOL, "warn_pct": PCT, "crit_pct": PCT},
        "vm_disk": {"enabled": BOOL, "warn_pct": PCT, "crit_pct": PCT},
    },
}


def _check(spec, value, path):
    kind = spec[0]
    if kind == "bool":
        if not isinstance(value, bool):
            raise SettingsError(path, "must be true or false")
    elif kind == "int":
        if not isinstance(value, int) or isinstance(value, bool) or not spec[1] <= value <= spec[2]:
            raise SettingsError(path, f"must be a whole number from {spec[1]} to {spec[2]}")
    elif kind == "str":
        if not isinstance(value, str) or not re.fullmatch(spec[1], value):
            raise SettingsError(path, "has invalid characters or is too long")
    elif kind == "url":
        if not isinstance(value, str) or (value and not re.fullmatch(r"https?://[^\s]{1,500}", value)):
            raise SettingsError(path, "must start with http:// or https://")
    elif kind == "time":
        if not isinstance(value, str) or not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", value):
            raise SettingsError(path, "must be a time like 23:00")
    elif kind == "headers":
        if not isinstance(value, dict) or len(value) > 20:
            raise SettingsError(path, "must be a list of header names and values")
        for k, v in value.items():
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", k) or not isinstance(v, str) or re.search(r"[\r\n]", v):
                raise SettingsError(f"{path}.{k}", "invalid header")


def _walk(schema, value, defaults, path):
    if not isinstance(value, dict):
        raise SettingsError(path or "settings", "must be an object")
    out = {}
    for k in value:
        if k not in schema:
            raise SettingsError(f"{path}.{k}" if path else k, "unknown setting")
    for k, spec in schema.items():
        p = f"{path}.{k}" if path else k
        v = value.get(k, copy.deepcopy(defaults[k]))
        if isinstance(spec, dict):
            out[k] = _walk(spec, v, defaults[k], p)
        else:
            _check(spec, v, p)
            out[k] = v
    return out


def validate(doc):
    """Validated copy of `doc` merged onto the defaults. Raises SettingsError(path, message)."""
    d = _walk(SCHEMA, doc, DEFAULTS, "")
    for name in ("webhook",):
        if d["notify"][name]["enabled"] and not d["notify"][name]["url"]:
            raise SettingsError(f"notify.{name}.url", "is needed when the webhook is on")
    n = d["notify"]["ntfy"]
    if n["enabled"] and (not n["topic"] or not n["server"]):
        raise SettingsError("notify.ntfy.topic", "is needed when ntfy is on")
    return d


def _mask(v):
    return MASK + v[-4:] if v else ""


def mask(doc):
    d = copy.deepcopy(doc)
    d["notify"]["ntfy"]["token"] = _mask(d["notify"]["ntfy"]["token"])
    d["notify"]["webhook"]["headers"] = {k: _mask(v) for k, v in d["notify"]["webhook"]["headers"].items()}
    return d


def merge_masked(new, old):
    """A settings document from the browser carries masked secrets; put the real ones back."""
    d = copy.deepcopy(new)
    try:
        if str(d["notify"]["ntfy"]["token"]).startswith(MASK):
            d["notify"]["ntfy"]["token"] = old["notify"]["ntfy"]["token"]
        hdrs = d["notify"]["webhook"]["headers"]
        if isinstance(hdrs, dict):
            for k, v in hdrs.items():
                if str(v).startswith(MASK):
                    hdrs[k] = old["notify"]["webhook"]["headers"].get(k, "")
    except (KeyError, TypeError):
        pass                        # validate() reports the shape problem
    return d


def load(store):
    try:
        return validate(store.get("config", {}))
    except SettingsError:
        return copy.deepcopy(DEFAULTS)
