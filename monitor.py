#!/usr/bin/env python3
"""
GuardTowarr - Health monitor for the *arr / Plex / Jellyfin media stack.
Serves an HTML dashboard with live status, diagnostics, and alerts.

Copyright (C) 2026 tonytrawl

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.
"""

import json
import os
import sys
import time
import base64
import hashlib
import hmac
import copy
import re
import tempfile
import shutil
import socket
import http.client
import ipaddress
import threading
import concurrent.futures
import http.server
import socketserver
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta

# ----------------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# Data directory. Defaults to the working directory (Windows/exe behaviour).
# In Docker, set GUARDTOWARR_CONFIG_DIR=/config so settings persist on a volume.
DATA_DIR = os.environ.get("GUARDTOWARR_CONFIG_DIR", "").strip() or "."
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except Exception:
    DATA_DIR = "."

CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
DISMISS_FILE = os.path.join(DATA_DIR, "dismissed.json")
PORT = int(os.environ.get("GUARDTOWARR_PORT", "9595"))  # 9595: avoids Readarr's 8787 and other *arr defaults
POLL_INTERVAL = 30  # seconds (default)

# Bump this when you cut a new GitHub release (must match the release tag, e.g. v1.0.0).
CURRENT_VERSION = "v2.0.0"
GITHUB_REPO = "tonytrawl/GuardTowarr"
RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{GITHUB_REPO}/releases/latest"

# NOTE: The list of services this app knows about lives in the SERVICE_REGISTRY
# further down (just after the per-service check functions, since each entry
# points at its check function). Things that used to be maintained by hand in
# several different places -- which credential fields a service needs, its
# default address, its troubleshooting links, the short blurb shown during
# setup -- are now all read straight out of that one registry. Add a service
# there once and it shows up everywhere automatically.

# Default file extensions the blocked-file scan flags inside torrents. These are
# executable/script types that have no business in a media download, so finding
# one usually means a fake or malware release. Users can edit this list.
_DEFAULT_BLOCKED_EXTS = ["exe", "scr", "bat", "cmd", "com", "msi",
                         "vbs", "js", "jar", "lnk", "pif", "reg", "hta", "ps1"]

DEFAULT_CONFIG = {
    "poll_interval": 30,
    "setup_complete": False,   # becomes True after first-run onboarding
    "port": 9595,
    "theme": "auto",  # auto | light | dark
    # Optional second, restricted port meant to be reverse-proxied for remote
    # access. It serves a locked-down view (no credentials, no internal IPs, no
    # admin actions) and requires a shared token. OFF by default.
    "public": {
        "enabled": False,       # serve the restricted public port at all
        "port": 9596,
        "token": "",            # shared secret required to use the public port
        "allow_requests": False,  # let token-holders search AND add/request media
        "allow_actions": False  # let token-holders run remediation fixes (incl. destructive)
    },
    "default_profiles": {"movie": None, "series": None},  # remembered quality profile per kind
    "notifications": {
        "enabled": False,
        "ntfy_server": "https://ntfy.sh",
        "topic": "",
        "severity": "error",          # "error" = errors only, "warning" = warnings+errors
        "notify_recovery": True,      # notify when a service recovers
        "ignore_services": [],        # list of service names to never notify about
        "quiet_enabled": False,       # suppress + batch alerts during quiet hours
        "quiet_start": "23:00",
        "quiet_end": "07:00",
        "torrent_done": False,        # beta: notify when a torrent finishes downloading
        "discord_enabled": False,     # send alerts to a Discord channel webhook
        "discord_webhook": "",        # Discord webhook URL
        "ntfy_enabled": True,         # send alerts via ntfy (when a topic is set)
        "pushover_enabled": False,    # send alerts via Pushover
        "pushover_token": "",         # Pushover application API token
        "pushover_user": "",          # Pushover user (or group) key
        "telegram_enabled": False,    # send alerts via a Telegram bot
        "telegram_token": "",         # Telegram bot token (from @BotFather)
        "telegram_chat": "",          # Telegram chat id to send to
        # When a service the others depend on goes down (Prowlarr -> indexers,
        # a download client -> the *arr download-client check), suppress the
        # downstream apps' duplicate alerts and let the root cause alert alone.
        "dependency_aware": True
    },
    "ui": {
        "sound_enabled": False,       # chime/flash on new error
        "sound_url": "",              # custom sound (URL); blank = built-in beep
        "update_check": True          # daily GitHub release check + dismissible notice
    },
    "beta": {
        "torrents": True,             # show the active-torrents view button (on by default)
        "lite_stats": False,          # skip heavy stats fetches; serve only cheap local data
        "remediation": True,          # diagnose & fix: queue insights + one-click fixes on issues
        "malware_scan": False,        # scan arr torrents for blocked file types
        "malware_autoremove": False,  # auto remove+blocklist+re-search a match (vs flag for a click)
        "malware_extensions": list(_DEFAULT_BLOCKED_EXTS)
    },
    # The per-service defaults (one entry each for radarr, sonarr, plex, etc.)
    # get filled in from the SERVICE_REGISTRY once it's defined further down.
    # We start it empty here and populate it at the bottom of this section so we
    # don't have to keep this list and the registry in sync by hand.
    "services": {}
}

# Live, thread-safe config shared by poller + web handler.
CONFIG_LOCK = threading.RLock()
CONFIG = {}

# shared state, written by poller, read by webserver
STATE_LOCK = threading.Lock()
STATE = {"last_poll": None, "services": {}}


def atomic_json(path, value):
    """Replace a complete, flushed file; never truncate the last good copy."""
    fd, tmp = tempfile.mkstemp(prefix=".guardtowarr-", dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def service_app(name, svc):
    return svc.get("app") or name


def active_instances(cfg, apps=None, stype=None):
    return [(n, s) for n, s in cfg.get("services", {}).items()
            if isinstance(s, dict) and not s.get("disabled", True) and s.get("enabled", True)
            and (apps is None or service_app(n, s) in apps)
            and (stype is None or s.get("type") == stype)]


def queue_instances(cfg):
    return [(n, _QUEUE_ARR[service_app(n, s)]) for n, s in active_instances(cfg, _QUEUE_ARR)]


def _merge_defaults(cfg):
    """Ensure new keys exist on configs created by older versions. Also tolerant
    of a config that's missing, empty, or not a dict (e.g. a hand-edited or
    half-written file from a mounted Docker volume) -- in that case we start from
    an empty dict and fill in every default, rather than crashing."""
    if not isinstance(cfg, dict):
        cfg = {}
    # Coerce services to a dict up front so every later check (including the
    # setup_complete inference below) is safe even if the file had services:null.
    if not isinstance(cfg.get("services"), dict):
        cfg["services"] = {}
    cfg = copy.deepcopy(cfg)
    cfg["services"] = {n: s for n, s in cfg["services"].items()
                       if isinstance(n, str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", n)
                       and isinstance(s, dict)}
    for name, svc in cfg["services"].items():
        app = svc.get("app", name)
        if not isinstance(app, str):
            app = name
        svc["app"] = app
        template = DEFAULT_CONFIG["services"].get(app, {})
        for key, value in template.items():
            if key in svc and not isinstance(svc[key], type(value)):
                svc[key] = copy.deepcopy(value)
    cfg.setdefault("poll_interval", 30)
    # "setup_complete" was added in a later version. If it's missing, this config
    # was written by an older build. Don't drag those users back through first-run
    # setup -- if any service already has credentials filled in, they were clearly
    # set up before the flag existed, so treat them as done. Only a config with no
    # credentials anywhere (a genuinely fresh install) starts setup.
    if "setup_complete" not in cfg:
        already_configured = any(
            any(str(svc.get(f, "")).strip() for f in ("api_key", "token", "username", "password"))
            for svc in cfg.get("services", {}).values()
        )
        cfg["setup_complete"] = already_configured
    cfg.setdefault("port", PORT)
    cfg.setdefault("theme", "auto")
    cfg.setdefault("default_profiles", {"movie": None, "series": None})
    notif = cfg.setdefault("notifications", {})
    if not isinstance(notif, dict): notif = {}; cfg["notifications"] = notif
    notif.setdefault("enabled", False)
    notif.setdefault("ntfy_server", "https://ntfy.sh")
    notif.setdefault("topic", "")
    notif.setdefault("severity", "error")
    notif.setdefault("notify_recovery", True)
    notif.setdefault("ignore_services", [])
    notif.setdefault("quiet_enabled", False)
    notif.setdefault("quiet_start", "23:00")
    notif.setdefault("quiet_end", "07:00")
    notif.setdefault("torrent_done", False)
    notif.setdefault("discord_enabled", False)
    notif.setdefault("discord_webhook", "")
    notif.setdefault("ntfy_enabled", True)
    notif.setdefault("pushover_enabled", False)
    notif.setdefault("pushover_token", "")
    notif.setdefault("pushover_user", "")
    notif.setdefault("telegram_enabled", False)
    notif.setdefault("telegram_token", "")
    notif.setdefault("telegram_chat", "")
    notif.setdefault("dependency_aware", True)
    ui = cfg.setdefault("ui", {})
    if not isinstance(ui, dict): ui = {}; cfg["ui"] = ui
    ui.setdefault("sound_enabled", False)
    ui.setdefault("sound_url", "")
    ui.setdefault("update_check", True)
    beta = cfg.setdefault("beta", {})
    if not isinstance(beta, dict): beta = {}; cfg["beta"] = beta
    beta.setdefault("torrents", True)
    beta.setdefault("lite_stats", False)
    beta.setdefault("remediation", True)
    beta.setdefault("malware_scan", False)
    beta.setdefault("malware_autoremove", False)
    beta.setdefault("malware_extensions", list(_DEFAULT_BLOCKED_EXTS))
    if not isinstance(beta.get("malware_extensions"), list):
        beta["malware_extensions"] = list(_DEFAULT_BLOCKED_EXTS)
    pub = cfg.setdefault("public", {})
    if not isinstance(pub, dict): pub = {}; cfg["public"] = pub
    pub.setdefault("enabled", False)
    pub.setdefault("port", 9596)
    pub.setdefault("token", "")
    pub.setdefault("allow_requests", False)
    pub.setdefault("allow_actions", False)
    # Make sure the services block exists, then backfill any service that ships
    # in the defaults but isn't in this (possibly older) config yet. Without this,
    # a service added in a new version -- e.g. Readarr/Lidarr -- would never show
    # up for people upgrading from a build that predated it. Newly backfilled
    # services arrive disabled (off), so they don't suddenly appear on an existing
    # user's dashboard; they're there waiting to be switched on in Settings.
    svcs = cfg.setdefault("services", {})
    # guard against a config where "services" was explicitly set to null or a
    # non-dict value (e.g. hand-edited); treat that as empty so we can backfill.
    if not isinstance(svcs, dict):
        svcs = {}
        cfg["services"] = svcs
    # Migration: Overseerr and Jellyseerr used to be two separate services; they're
    # now one "seerr" service. Carry an existing user's configured one over to
    # "seerr", then drop the old entries so they don't linger as duplicate cards.
    if "seerr" not in svcs:
        legacy = None
        for old in ("overseerr", "jellyseerr"):
            s = svcs.get(old)
            if isinstance(s, dict) and (str(s.get("api_key", "")).strip() or not s.get("disabled", True)):
                legacy = s
                break
        if legacy is not None:
            svcs["seerr"] = {
                "enabled": legacy.get("enabled", True),
                "disabled": legacy.get("disabled", False),
                "hidden": legacy.get("hidden", False),
                "url": legacy.get("url", "http://localhost:5055"),
                "type": "seerr",
                "api_key": legacy.get("api_key", ""),
            }
    svcs.pop("overseerr", None)
    svcs.pop("jellyseerr", None)
    for name, default_svc in DEFAULT_CONFIG["services"].items():
        if name not in svcs:
            svcs[name] = dict(default_svc)   # copy so configs don't share the default object
    for name, svc in svcs.items():
        template = DEFAULT_CONFIG["services"].get(svc.get("app", name), {})
        for key, value in template.items():
            svc.setdefault(key, copy.deepcopy(value))
        svc.setdefault("app", name)
        svc.setdefault("label", name)
        svc.setdefault("enabled", True)
        svc.setdefault("disabled", False)
        svc.setdefault("hidden", False)
    for key, fallback, low, high in (("poll_interval", 30, 5, 3600), ("port", 9595, 1, 65535)):
        try:
            cfg[key] = max(low, min(high, int(cfg.get(key, fallback))))
        except (TypeError, ValueError, OverflowError):
            cfg[key] = fallback
    if not isinstance(cfg.get("default_profiles"), dict):
        cfg["default_profiles"] = {}
    for section in ("notifications", "ui", "beta", "public"):
        for key, default in DEFAULT_CONFIG[section].items():
            if not isinstance(cfg[section].get(key), type(default)):
                cfg[section][key] = copy.deepcopy(default)
    cfg["schema_version"] = 2
    return cfg


def load_config():
    if not os.path.exists(CONFIG_FILE):
        atomic_json(CONFIG_FILE, DEFAULT_CONFIG)
        print(f"[*] Created {CONFIG_FILE}.")
    # Read and merge. If the file is empty, corrupt, or not valid JSON (which can
    # happen with a hand-edited or half-written mounted config), don't crash --
    # fall back to defaults via _merge_defaults, which tolerates a non-dict input.
    try:
        with open(CONFIG_FILE, encoding="utf-8-sig") as f:
            raw = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print(f"[!] {CONFIG_FILE} was empty or invalid JSON; starting from defaults.")
        shutil.copy2(CONFIG_FILE, CONFIG_FILE + ".corrupt-" + str(time.time_ns()))
        raw = {}
    except Exception as e:
        print(f"[!] Couldn't read {CONFIG_FILE} ({e}); starting from defaults.")
        raise RuntimeError("Configuration cannot be read; leaving the original file untouched") from e
    if not isinstance(raw, dict) or not isinstance(raw.get("services", {}), dict) or any(
            not isinstance(s, dict) for s in (raw.get("services", {}) if isinstance(raw, dict)
                                             and isinstance(raw.get("services", {}), dict) else {}).values()):
        shutil.copy2(CONFIG_FILE, CONFIG_FILE + ".recovered-" + str(time.time_ns()))
    return _merge_defaults(raw)


def save_config(cfg):
    with CONFIG_LOCK:
        atomic_json(CONFIG_FILE, cfg)


def get_config():
    with CONFIG_LOCK:
        return json.loads(json.dumps(CONFIG))  # deep copy for safe reads


def missing_credentials(svc):
    """Return list of required fields that are blank for an enabled service."""
    req = REQUIRED_FIELDS.get(svc.get("type"), [])
    return [f for f in req if not str(svc.get(f, "")).strip()]


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward service credentials or request bodies to another origin."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        def origin(url):
            p = urllib.parse.urlsplit(url)
            return p.scheme.lower(), p.hostname, p.port or (443 if p.scheme == "https" else 80)
        if origin(req.full_url) != origin(newurl):
            raise urllib.error.HTTPError(req.full_url, code, "Cross-origin redirect blocked", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_urlopen(req, timeout=10):
    if urllib.parse.urlsplit(req.full_url).scheme not in ("http", "https"):
        raise ValueError("Only HTTP(S) requests are supported.")
    return urllib.request.build_opener(SameOriginRedirect()).open(req, timeout=timeout)


def http_get(url, headers=None, timeout=10, auth_cookie=None):
    req = urllib.request.Request(url, headers=headers or {})
    if auth_cookie:
        req.add_header("Cookie", auth_cookie)
    with safe_urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def _issue(level, source, message, fix=""):
    return {"level": level, "source": source, "message": message, "fix": fix}


# Grace period before we ALERT on a stalled download. Stalls are often transient
# (the torrent just needs time to find peers), so a freshly-stalled torrent still
# shows on the dashboard but stays "provisional" -- no notification -- until it's
# been continuously stalled this long. Genuine failures (missing files, errors)
# alert immediately. Two separate stores so the qBittorrent checker and the *arr
# queue scan can each prune cleanly.
_STALL_GRACE_SECONDS = 180   # 3 minutes
_QBIT_STALL_SINCE = {}       # qBit torrent hash -> first time seen stalled
_ARR_STALL_SINCE = {}        # *arr downloadId    -> first time seen stalled


def _stall_held(store, key, is_stalled, now=None):
    """Has `key` been continuously stalled for at least the grace period? Records
    the first-seen-stalled time in `store`, and clears it once no longer stalled.
    With no key we can't track it, so don't suppress."""
    now = now or time.time()
    if not key:
        return is_stalled
    if not is_stalled:
        store.pop(key, None)
        return False
    first = store.setdefault(key, now)
    return (now - first) >= _STALL_GRACE_SECONDS


# ----------------------------------------------------------------------------
# SERVICE CHECKS
# ----------------------------------------------------------------------------
def check_arr(name, cfg):
    """Radarr / Sonarr use API v3; Prowlarr uses API v1. Same status + health endpoints."""
    base = cfg["url"].rstrip("/")
    key = cfg.get("api_key", "")
    if not key:
        return svc_result(name, "warning", "No API key configured", [])
    headers = {"X-Api-Key": key}
    # Radarr and Sonarr are on API v3. The newer/older siblings -- Prowlarr,
    # Readarr, Lidarr -- all live under /api/v1. Everything else here is identical.
    api = _arr_api_ver(service_app(name, cfg))
    try:
        # ping system status first
        status, body = http_get(f"{base}/api/{api}/system/status", headers)
        if status != 200:
            return svc_result(name, "error", f"System status returned HTTP {status}", [])
        # pull the health endpoint (this is where *arr reports its own problems)
        status, body = http_get(f"{base}/api/{api}/health", headers)
        issues = json.loads(body) if body.strip() else []
        errs = []
        for h in issues:
            src = h.get("source", "")
            msg = h.get("message", "")
            entry = {
                "level": h.get("type", "warning"),     # "warning" | "error"
                "source": src,
                "message": msg,
                "fix": h.get("wikiUrl", ""),
            }
            # "Update available" warnings: the user fixes these by updating the app
            # itself, not by reading docs -- so link to the *arr dashboard and tell
            # them where the update lives, instead of a wiki page.
            if "update" in src.lower():
                entry["fix"] = base
                entry["fix_label"] = f"Open {name.title()} to update ↗"
                if "system" not in msg.lower():
                    entry["message"] = f"{msg}. Update from System → Updates in {name.title()}"
            errs.append(entry)
        if any(e["level"] == "error" for e in errs):
            return svc_result(name, "error", f"{len(errs)} health issue(s)", errs)
        if errs:
            return svc_result(name, "warning", f"{len(errs)} health warning(s)", errs)
        return svc_result(name, "ok", "Healthy", [])
    except urllib.error.HTTPError as e:
        return svc_result(name, "error", f"HTTP {e.code}: {e.reason}", [])
    except Exception as e:
        return svc_result(name, "error", f"Unreachable: {e}", [])


def check_plex(name, cfg):
    base = cfg["url"].rstrip("/")
    token = cfg.get("token", "")
    if not token:
        return svc_result(name, "warning", "No Plex token configured", [])
    try:
        status, body = http_get(f"{base}/identity?X-Plex-Token={urllib.parse.quote(token)}",
                                headers={"Accept": "application/json"})
        if status != 200:
            return svc_result(name, "error", f"Plex returned HTTP {status}",
                [_issue("error", "Connection",
                        f"Plex returned HTTP {status} (token may be invalid or expired).",
                        DOC_LINKS["plex_http"])])
        # check libraries are reachable
        status, body = http_get(f"{base}/library/sections?X-Plex-Token={urllib.parse.quote(token)}",
                                headers={"Accept": "application/json"})
        if status != 200:
            return svc_result(name, "warning", "Online but libraries unreachable",
                [_issue("warning", "Libraries",
                        "Server is up but its libraries aren't responding.",
                        DOC_LINKS["plex_libraries"])])
        try:
            data = json.loads(body)
            n = len(data.get("MediaContainer", {}).get("Directory", []))
        except Exception:
            n = "?"
        return svc_result(name, "ok", f"Online ({n} libraries)", [])
    except Exception as e:
        return svc_result(name, "error", f"Unreachable: {e}",
            [_issue("error", "Unreachable",
                    "Couldn't reach the Plex server. Check the address, that Plex is running, and remote access.",
                    DOC_LINKS["plex_unreachable"])])


def check_qbit(name, cfg):
    base = cfg["url"].rstrip("/")
    try:
        # login to get session cookie
        data = urllib.parse.urlencode({
            "username": cfg.get("username", ""),
            "password": cfg.get("password", "")
        }).encode()
        req = urllib.request.Request(f"{base}/api/v2/auth/login", data=data,
                                     headers={"Referer": base})
        with safe_urlopen(req, timeout=10) as r:
            cookie = r.headers.get("Set-Cookie", "")
            login_body = r.read().decode().strip()
        if login_body != "Ok." and not cookie:
            return svc_result(name, "error", "Login failed (check username/password)",
                [_issue("error", "Authentication",
                        "Couldn't log in to the qBittorrent Web UI. Check the username and password.",
                        DOC_LINKS["qbit_login"])])
        cookie = cookie.split(";")[0] if cookie else None
        # get transfer info + torrent list for stalled/errored states
        status, body = http_get(f"{base}/api/v2/torrents/info", auth_cookie=cookie)
        torrents = json.loads(body) if body.strip() else []
        errs = []
        bad_states = {"error", "missingFiles", "stalledDL", "unknown"}
        seen_hashes = set()
        for t in torrents:
            st = t.get("state", "")
            h = t.get("hash", "")
            if h:
                seen_hashes.add((name, h))
            is_stalled = (st == "stalledDL")
            held = _stall_held(_QBIT_STALL_SINCE, (name, h), is_stalled)
            if st in bad_states:
                iss = _issue(
                    "error" if st in ("error", "missingFiles") else "warning",
                    t.get("name", "")[:80],
                    f"Torrent state: {st}",
                    DOC_LINKS["qbit_torrent"])
                iss["hash"] = h   # lets the recheck/reannounce actions target it
                iss["state"] = st  # used to correlate with the *arr queue + classify cause
                # a freshly-stalled torrent shows on the dashboard right away, but
                # stays provisional (no alert) until it's outlasted the grace window
                if is_stalled and not held:
                    iss["provisional"] = True
                errs.append(iss)
        # prune stall timers for torrents that are no longer present
        for k in list(_QBIT_STALL_SINCE):
            if isinstance(k, tuple) and k[0] == name and k not in seen_hashes:
                _QBIT_STALL_SINCE.pop(k, None)
        if any(e["level"] == "error" for e in errs):
            return svc_result(name, "error", f"{len(errs)} torrent error(s)", errs)
        if errs:
            return svc_result(name, "warning", f"{len(errs)} stalled torrent(s)", errs)
        return svc_result(name, "ok", f"Online ({len(torrents)} torrents)", [])
    except Exception as e:
        return svc_result(name, "error", f"Unreachable: {e}",
            [_issue("error", "Unreachable",
                    "Couldn't reach qBittorrent. Check the address and that the Web UI is enabled.",
                    DOC_LINKS["qbit_unreachable"])])


def check_ombi(name, cfg):
    base = cfg["url"].rstrip("/")
    key = cfg.get("api_key", "")
    if not key:
        return svc_result(name, "warning", "No API key configured", [])
    headers = {"ApiKey": key, "Accept": "application/json"}
    try:
        status, body = http_get(f"{base}/api/v1/Status", headers)
        if status != 200:
            return svc_result(name, "error", f"Ombi returned HTTP {status}",
                [_issue("error", "Connection",
                        f"Ombi returned HTTP {status} (the API key may be wrong).",
                        DOC_LINKS["ombi_http"])])
        # check for failed/pending requests as a soft signal
        try:
            status, body = http_get(f"{base}/api/v1/Request/movie/total", headers)
        except Exception:
            pass
        return svc_result(name, "ok", "Online", [])
    except Exception as e:
        return svc_result(name, "error", f"Unreachable: {e}",
            [_issue("error", "Unreachable",
                    "Couldn't reach Ombi. Check the address and that the service is running.",
                    DOC_LINKS["ombi_unreachable"])])


def check_seerr(name, cfg):
    """Overseerr and Jellyseerr share the same API (Jellyseerr is a fork of
    Overseerr), so one checker covers both. Auth is an X-Api-Key header and the
    health endpoint is /api/v1/status, which returns the running version."""
    base = cfg["url"].rstrip("/")
    key = cfg.get("api_key", "")
    if not key:
        return svc_result(name, "warning", "No API key configured", [])
    headers = {"X-Api-Key": key, "Accept": "application/json"}
    try:
        status, body = http_get(f"{base}/api/v1/status", headers)
        if status != 200:
            return svc_result(name, "error", f"Returned HTTP {status}",
                [_issue("error", "Connection",
                        f"{name.title()} returned HTTP {status} (the API key may be wrong).",
                        DOC_LINKS.get("seerr_http", ""))])
        return svc_result(name, "ok", "Online", [])
    except Exception as e:
        return svc_result(name, "error", f"Unreachable: {e}",
            [_issue("error", "Unreachable",
                    f"Couldn't reach {name.title()}. Check the address and that the service is running.",
                    DOC_LINKS.get("seerr_unreachable", ""))])


def check_jellyfin(name, cfg):
    """Jellyfin health check. Auth is an API key via the X-Emby-Token header;
    /System/Info returns 200 with a valid key. (Live now-playing is read
    separately from /Sessions in the stats code.) Jellyfin support is beta and
    limited to monitoring + live stats."""
    base = cfg["url"].rstrip("/")
    key = cfg.get("api_key", "")
    if not key:
        return svc_result(name, "warning", "No API key configured", [])
    headers = {"X-Emby-Token": key, "Accept": "application/json"}
    try:
        status, body = http_get(f"{base}/System/Info", headers)
        if status != 200:
            return svc_result(name, "error", f"Returned HTTP {status}",
                [_issue("error", "Connection",
                        f"Jellyfin returned HTTP {status} (the API key may be wrong).",
                        DOC_LINKS.get("jellyfin_http", ""))])
        return svc_result(name, "ok", "Online", [])
    except Exception as e:
        return svc_result(name, "error", f"Unreachable: {e}",
            [_issue("error", "Unreachable",
                    "Couldn't reach Jellyfin. Check the address and that the service is running.",
                    DOC_LINKS.get("jellyfin_unreachable", ""))])


def _tunarr_doc_link(check):
    """Point each Tunarr health check at the most relevant docs page."""
    c = check.lower()
    if "transcode" in c or "hardware" in c or "accel" in c:
        return "https://tunarr.com/configure/ffmpeg/transcode_config/"
    if "ffmpeg" in c:
        return "https://tunarr.com/configure/ffmpeg/"
    return DOC_LINKS.get("tunarr_http", "https://tunarr.com/")


def check_tunarr(name, cfg):
    """Tunarr health (live TV channels; successor to dizqueTV). No auth by default.
    /api/system/health returns a map of check -> {type, context}; we surface every
    check that isn't 'healthy', the same way we read the *arr health endpoint."""
    base = cfg["url"].rstrip("/")
    # Tunarr health 'type' values: 'healthy' is fine; anything clearly-bad is an
    # error; everything else non-healthy (e.g. 'warning') is a warning.
    healthy = ("healthy", "ok", "passed", "success", "")
    bad = ("error", "critical", "unhealthy", "failed", "fail")
    try:
        status, body = http_get(f"{base}/api/system/health", headers={"Accept": "application/json"})
        if status != 200:
            return svc_result(name, "error", f"Tunarr returned HTTP {status}",
                [_issue("error", "Connection", f"Tunarr returned HTTP {status}.",
                        DOC_LINKS.get("tunarr_http", ""))])
        data = json.loads(body) if body.strip() else {}
        errs = []
        if isinstance(data, dict):
            for check, val in data.items():
                if not isinstance(val, dict):
                    continue
                t = (val.get("type") or "").lower()
                if t in healthy:
                    continue
                level = "error" if t in bad else "warning"
                msg = (val.get("context") or f"{check}: {t}")[:300]
                errs.append(_issue(level, check, msg, _tunarr_doc_link(check)))
        if any(e["level"] == "error" for e in errs):
            return svc_result(name, "error", f"{len(errs)} health issue(s)", errs)
        if errs:
            return svc_result(name, "warning", f"{len(errs)} health warning(s)", errs)
        return svc_result(name, "ok", "Healthy", [])
    except Exception as e:
        return svc_result(name, "error", f"Unreachable: {e}",
            [_issue("error", "Unreachable",
                    "Couldn't reach Tunarr. Check the address and that the service is running.",
                    DOC_LINKS.get("tunarr_unreachable", ""))])


def check_sabnzbd(name, cfg):
    try:
        queue = sab_data(cfg, "queue", start=0, limit=1000)
        issues = []
        if queue.get("paused") or queue.get("status", "").lower() == "paused":
            issues.append(_issue("warning", "Queue", "SABnzbd downloading is paused."))
        for row in queue.get("slots", []):
            if row.get("status", "").lower() in ("failed", "missing", "error"):
                issues.append(_issue("error", row.get("filename", "Download"),
                                     "SABnzbd queue item: " + row.get("status", "")))
        try:
            history = sab_data(cfg, "history", start=0, limit=100, failed_only=1)
            for row in history.get("slots", []):
                if row.get("status", "").lower() == "failed" and float(row.get("completed", 0) or 0) >= time.time()-86400:
                    issues.append(_issue("error", row.get("name", "Download"), row.get("fail_message") or "Download failed."))
        except Exception:
            issues.append(_issue("warning", "History", "Queue is reachable, but failed-download history could not be read."))
        for issue in issues:
            issue["fix"] = "https://sabnzbd.org/wiki/"
        level = "error" if any(i["level"] == "error" for i in issues) else "warning" if issues else "ok"
        return svc_result(name, level, f"{len(issues)} issue(s)" if issues else f"Online ({queue.get('noofslots', len(queue.get('slots', [])))} queued)", issues)
    except Exception as e:
        return svc_result(name, "error", f"SABnzbd unavailable: {e}", [])


def sab_data(svc, mode, **params):
    query = urllib.parse.urlencode(dict(mode=mode, output="json", apikey=svc.get("api_key", ""), **params))
    _, body = http_get(svc["url"].rstrip("/") + "/api?" + query)
    data = json.loads(body)
    if data.get("error"):
        raise ValueError("SABnzbd rejected the request; check its API key and access settings.")
    if not isinstance(data.get(mode), dict):
        raise ValueError("Unexpected SABnzbd response")
    return data[mode]


def check_cleanuparr(name, cfg):
    """Read Cleanuparr's own health reports; never trigger its cleanup jobs."""
    try:
        headers = {"X-Api-Key": cfg.get("api_key", "")}
        base = cfg["url"].rstrip("/")
        try:
            _, body = http_get(base + "/health/detailed", headers)
        except urllib.error.HTTPError as e:
            if e.code != 503:
                raise
            body = e.read().decode("utf-8")
        health = json.loads(body)
        if not isinstance(health, dict) or "status" not in health:
            raise ValueError("Unsupported health response")
        issues = []
        for source, item in health.get("entries", {}).items():
            if str(item.get("status", "")).lower() != "healthy":
                level = "warning" if item.get("status", "").lower() == "degraded" else "error"
                issues.append(_issue(level, source, item.get("description") or "Health check failed",
                                     "https://cleanuparr.github.io/docs/"))
        if not issues and str(health["status"]).lower() != "healthy":
            issues.append(_issue("error", "Health", "Cleanuparr reports an unhealthy state."))
        try:
            _, body = http_get(base + "/api/manualevents?isResolved=false&page=1&pageSize=100", headers)
            events = json.loads(body)
            for event in events.get("items", []):
                if event.get("isResolved"):
                    continue
                severity = str(event.get("severity", "warning")).lower()
                issue = _issue("error" if severity in ("error", "critical") else "warning",
                               event.get("itemTitle") or "Action required",
                               event.get("message") or "Cleanuparr needs attention.", base)
                issue["external_id"] = event.get("id")
                issues.append(issue)
            if events.get("totalCount", 0) > len(events.get("items", [])):
                issues.append(_issue("warning", "Action required", "More unresolved events are available in Cleanuparr.", base))
        except Exception:
            issues.append(_issue("warning", "Events", "Health is available, but action-required events could not be loaded."))
        level = "error" if any(i["level"] == "error" for i in issues) else "warning" if issues else "ok"
        return svc_result(name, level, f"{len(issues)} health issue(s)" if issues else "Healthy", issues)
    except urllib.error.HTTPError as e:
        return svc_result(name, "error", "API key rejected" if e.code in (401, 403) else f"HTTP {e.code}", [])
    except Exception as e:
        return svc_result(name, "error", f"Cleanuparr health unavailable: {e}", [])


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.socket_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def docker_containers(svc):
    """Only GET /containers/json. No container control or arbitrary API proxy."""
    endpoint = svc.get("url", "")
    if endpoint.startswith("unix://"):
        if not hasattr(socket, "AF_UNIX"):
            raise ValueError("Use an HTTP socket proxy on this platform.")
        conn = UnixHTTPConnection(endpoint[len("unix://"):])
        try:
            conn.request("GET", "/containers/json?all=1")
            response = conn.getresponse()
            if response.status != 200:
                raise ValueError(f"Docker returned HTTP {response.status}")
            return json.loads(response.read(4 * 1024 * 1024))
        finally:
            conn.close()
    if urllib.parse.urlsplit(endpoint).scheme not in ("http", "https"):
        raise ValueError("Use unix:///var/run/docker.sock or an HTTP(S) Docker socket proxy.")
    _, body = http_get(endpoint.rstrip("/") + "/containers/json?all=1")
    data = json.loads(body)
    if not isinstance(data, list):
        raise ValueError("Docker returned an unexpected response.")
    return data


def check_docker(name, cfg):
    try:
        containers = docker_containers(cfg)
        selected = {v.strip() for v in cfg.get("containers", "").split(",") if v.strip()}
        seen, issues, rows = set(), [], []
        for item in containers:
            names = [n.lstrip("/") for n in item.get("Names", [])]
            label = names[0] if names else item.get("Id", "")[:12]
            if selected and not selected.intersection(names):
                continue
            seen.update(names)
            state, status = item.get("State", "unknown"), item.get("Status", "")
            rows.append({"name": label, "state": state, "status": status})
            if state != "running" or "(unhealthy)" in status:
                issues.append(_issue("error", label, f"Container {state}: {status}",
                                     "https://docs.docker.com/engine/containers/run/"))
        for missing in selected - seen:
            issues.append(_issue("error", missing, "Configured container is missing."))
        result = svc_result(name, "error" if issues else "ok",
                            f"{len(issues)} container issue(s)" if issues else f"{len(rows)} containers running", issues)
        result["containers"] = rows
        return result
    except Exception as e:
        return svc_result(name, "error", f"Docker unavailable: {e}", [])


def check_nzbget(name, cfg):
    """NZBGet (Usenet downloader, beta). Talks JSON-RPC at /jsonrpc with HTTP basic
    auth (username/password). We call the 'status' method; a valid response means
    it's up. A 401 means bad credentials; a paused queue is surfaced as a warning."""
    base = cfg["url"].rstrip("/")
    user = cfg.get("username", "")
    pw = cfg.get("password", "")
    try:
        payload = json.dumps({"method": "status", "params": [], "id": 1}).encode()
        req = urllib.request.Request(f"{base}/jsonrpc", data=payload,
                                     headers={"Content-Type": "application/json"})
        if user or pw:
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            req.add_header("Authorization", f"Basic {token}")
        with safe_urlopen(req, timeout=10) as r:
            status, body = r.status, r.read().decode("utf-8", "replace")
        if status != 200:
            return svc_result(name, "error", f"NZBGet returned HTTP {status}",
                [_issue("error", "Connection", f"NZBGet returned HTTP {status}.",
                        DOC_LINKS.get("nzbget_http", ""))])
        data = json.loads(body) if body.strip() else {}
        result = data.get("result", {}) if isinstance(data, dict) else {}
        if isinstance(result, dict) and result.get("DownloadPaused"):
            return svc_result(name, "warning", "Downloads paused",
                [_issue("warning", "Queue", "NZBGet downloading is paused.",
                        DOC_LINKS.get("nzbget_http", ""))])
        return svc_result(name, "ok", "Online", [])
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return svc_result(name, "error", "Login failed (check username/password)",
                [_issue("error", "Authentication",
                        "NZBGet rejected the login. Check the username and password.",
                        DOC_LINKS.get("nzbget_login", ""))])
        return svc_result(name, "error", f"NZBGet returned HTTP {e.code}",
            [_issue("error", "Connection", f"NZBGet returned HTTP {e.code}: {e.reason}.",
                    DOC_LINKS.get("nzbget_http", ""))])
    except Exception as e:
        return svc_result(name, "error", f"Unreachable: {e}",
            [_issue("error", "Unreachable",
                    "Couldn't reach NZBGet. Check the address and that the service is running.",
                    DOC_LINKS.get("nzbget_unreachable", ""))])


def _issue_id(name, e):
    """Stable content-hash id for an issue, so dismissals survive re-polling.
    Shared by svc_result and the queue scan so both build ids the same way."""
    raw = f"{name}|{e.get('source','')}|{e.get('message','')}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def svc_result(name, level, summary, errors):
    """Build the standard result object every checker returns."""
    # give every issue a stable id so dismissals survive re-polling
    for e in errors:
        e["id"] = _issue_id(name, e)
        e["service"] = name
    return {
        "name": name,
        "level": level,                       # ok | warning | error
        "summary": summary,
        "errors": errors,
        "checked": datetime.now().strftime("%H:%M:%S")
    }


# ============================================================================
# SERVICE REGISTRY
# ============================================================================
# Single source of truth for every monitored service. One entry per "type"; the
# default config, setup screen, credential checks and doc links are all derived
# from it. To add a service, see docs/adding-a-service.md.
#
# Entry fields:
#   label         display name (e.g. "qBittorrent")
#   blurb         one-line description for the setup tile
#   fields        settings the user fills in; "url" first, then any credentials
#   checker       check_*(name, cfg) -> svc_result(...); talks to the service
#   capabilities  what the app does with it. Every service has "monitor"; the
#                 rest are opt-in and mark a wired-up feature:
#                   "search"/"add" -> media search/add (the *arr apps)
#                   "queue"        -> active-downloads view
#                   "stats"        -> stats panel (library counts, now-playing)
#   docs          per-situation troubleshooting links, shown on errors/alerts
#
# "instances" maps the named services of a type to their default URLs. Most types
# have one; "arr" is the exception, covering several apps that share an API.

SERVICE_REGISTRY = {
    "cleanuparr": {
        "label": "Cleanuparr", "blurb": "Cleanup service health and reported problems",
        "fields": ["url", "api_key"], "checker": check_cleanuparr,
        "capabilities": ["monitor"], "docs": {"http": "https://cleanuparr.github.io/docs/"},
        "instances": {"cleanuparr": "http://localhost:11011"},
    },
    "docker": {
        "label": "Docker", "blurb": "Container status through a socket or restricted proxy",
        "fields": ["url"], "checker": check_docker, "capabilities": ["monitor"],
        "docs": {"http": "https://docs.docker.com/engine/"},
        "instances": {"docker": "http://docker-socket-proxy:2375"},
    },
    "arr": {
        "label": "Arr",
        "blurb": "Movies / TV / indexer",
        "fields": ["url", "api_key"],
        "checker": check_arr,
        # The *arr apps are our richest integration: besides uptime, they power
        # the search/add feature and the download-queue fallback view.
        "capabilities": ["monitor", "search", "add", "queue"],
        "docs": {},
        "instances": {
            "radarr":   "http://localhost:7878",
            "sonarr":   "http://localhost:8989",
            "prowlarr": "http://localhost:9696",
            "readarr":  "http://localhost:8787",
            "lidarr":   "http://localhost:8686",
        },
    },
    "plex": {
        "label": "Plex",
        "blurb": "Media server",
        "fields": ["url", "token"],
        "checker": check_plex,
        # Plex also feeds the stats panel (now-playing, library counts, streams).
        "capabilities": ["monitor", "stats"],
        "docs": {
            "unreachable": "https://support.plex.tv/articles/204604227-why-can-t-the-plex-app-find-or-connect-to-my-plex-media-server/",
            "http":        "https://support.plex.tv/articles/204604227-why-can-t-the-plex-app-find-or-connect-to-my-plex-media-server/",
            "libraries":   "https://support.plex.tv/articles/200289506-remote-access/",
        },
        "instances": {"plex": "http://localhost:32400"},
    },
    "qbit": {
        "label": "qBittorrent",
        "blurb": "Torrent client",
        "fields": ["url", "username", "password"],
        "checker": check_qbit,
        # qBittorrent gives us the detailed live torrent view on top of uptime.
        "capabilities": ["monitor", "queue"],
        "docs": {
            # Point at the FAQ (default credentials, password reset, WebUI access)
            # rather than the API reference -- friendlier for these two situations.
            "login":       "https://github.com/qbittorrent/qBittorrent/wiki/Frequently-Asked-Questions",
            "unreachable": "https://github.com/qbittorrent/qBittorrent/wiki/Frequently-Asked-Questions",
            "torrent":     "https://github.com/qbittorrent/qBittorrent/wiki/Frequently-Asked-Questions",
        },
        "instances": {"qbittorrent": "http://localhost:8080"},
    },
    "ombi": {
        "label": "Ombi",
        "blurb": "Requests",
        "fields": ["url", "api_key"],
        "checker": check_ombi,
        # Ombi is uptime-only for now. Its API exposes pending/failed request
        # counts too, so if you ever want that, add a "requests" capability and
        # a hook -- the checker already pokes the request endpoint as a soft test.
        "capabilities": ["monitor"],
        "docs": {
            "http":        "https://docs.ombi.app/info/faq/",
            "unreachable": "https://docs.ombi.app/guides/reverse-proxy/",
        },
        "instances": {"ombi": "http://localhost:5000"},
    },
    "seerr": {
        "label": "Seerr",
        "blurb": "Requests (Overseerr / Jellyseerr)",
        "fields": ["url", "api_key"],
        "checker": check_seerr,
        # Uptime-only for now. The API also exposes request counts and pending
        # approvals, so a "requests" capability + hook could surface those later.
        "capabilities": ["monitor"],
        "docs": {
            "http":        "https://docs.jellyseerr.dev/",
            "unreachable": "https://docs.jellyseerr.dev/getting-started/",
        },
        # Overseerr and Jellyseerr share one API, so they're a single service here.
        # Point it at whichever one you run (both default to port 5055).
        "instances": {
            "seerr": "http://localhost:5055",
        },
    },
    "jellyfin": {
        "label": "Jellyfin",
        "blurb": "Media server (beta)",
        "fields": ["url", "api_key"],
        "checker": check_jellyfin,
        # Jellyfin feeds the live stats view (now-playing) alongside or instead
        # of Plex. Support is beta and limited to monitoring + live stats.
        "capabilities": ["monitor", "stats"],
        "docs": {
            "http":        "https://jellyfin.org/docs/general/networking/",
            "unreachable": "https://jellyfin.org/docs/general/administration/troubleshooting/",
        },
        "instances": {"jellyfin": "http://localhost:8096"},
    },
    "tunarr": {
        "label": "Tunarr",
        "blurb": "Live TV channels (beta)",
        # No auth by default -- just the address. Beta: monitoring only (up/down).
        "fields": ["url"],
        "checker": check_tunarr,
        "capabilities": ["monitor"],
        "docs": {
            "http":        "https://tunarr.com/",
            "unreachable": "https://tunarr.com/",
        },
        "instances": {"tunarr": "http://localhost:8000"},
    },
    "sabnzbd": {
        "label": "SABnzbd",
        "blurb": "Usenet downloader (beta)",
        "fields": ["url", "api_key"],
        "checker": check_sabnzbd,
        # Beta: monitoring only (up/down + paused). The API also exposes the queue,
        # so a "queue" capability + hook could feed the active-downloads view later.
        "capabilities": ["monitor"],
        "docs": {
            "http":        "https://sabnzbd.org/wiki/configuration/4.3/general",
            "unreachable": "https://sabnzbd.org/wiki/",
        },
        "instances": {"sabnzbd": "http://localhost:8080"},
    },
    "nzbget": {
        "label": "NZBGet",
        "blurb": "Usenet downloader (beta)",
        "fields": ["url", "username", "password"],
        "checker": check_nzbget,
        "capabilities": ["monitor"],
        "docs": {
            "http":        "https://nzbget.com/documentation/",
            "login":       "https://nzbget.com/documentation/access-control/",
            "unreachable": "https://nzbget.com/documentation/",
        },
        "instances": {"nzbget": "http://localhost:6789"},
    },
}


# ----------------------------------------------------------------------------
# Everything below is DERIVED from the registry above. You shouldn't need to
# touch any of it when adding a service -- it rebuilds itself from SERVICE_REGISTRY.
# ----------------------------------------------------------------------------

# Map of service type -> its check function. Used by the poller to know how to
# health-check each service. (Same shape as the old hand-written CHECKERS dict,
# just built from the registry instead of typed out separately.)
CHECKERS = {t: spec["checker"] for t, spec in SERVICE_REGISTRY.items()}

# Which fields each service type needs filled in. Used by the onboarding check
# to decide if a service still needs credentials before we can monitor it.
REQUIRED_FIELDS = {t: list(spec["fields"]) for t, spec in SERVICE_REGISTRY.items()}

# Flat lookup of troubleshooting links, keyed "<type>_<situation>" (e.g.
# "plex_unreachable"). The checkers reference these by that flat key, so we
# flatten the per-service docs maps into one dict here.
DOC_LINKS = {
    f"{t}_{situation}": url
    for t, spec in SERVICE_REGISTRY.items()
    for situation, url in spec.get("docs", {}).items()
}

# Short descriptors for the setup screen, keyed by type (e.g. "qbit" ->
# "Torrent client"). Sent to the frontend so the setup tiles stay in sync with
# the registry instead of being hard-coded in the HTML.
SERVICE_BLURBS = {t: spec["blurb"] for t, spec in SERVICE_REGISTRY.items()}


def _build_default_services():
    """Build the default 'services' config block from the registry.

    Walks every instance of every service type and produces one config entry
    each. Services start OFF (disabled) by default -- the user turns on the ones
    they actually use during first-run setup or later in Settings, so the
    dashboard isn't cluttered with services nobody configured. Each entry still
    carries its default address and a blank slot for every credential field, so
    turning one on is just a matter of filling in the key."""
    out = {}
    for stype, spec in SERVICE_REGISTRY.items():
        for inst_name, default_url in spec["instances"].items():
            entry = {"enabled": True, "disabled": True, "hidden": False, "app": inst_name, "label": inst_name,
                     "url": default_url, "type": stype}
            # give each credential field (everything except url) a blank default
            for f in spec["fields"]:
                if f != "url":
                    entry[f] = ""
            out[inst_name] = entry
    return out


# Fill in the services block we left empty up in DEFAULT_CONFIG earlier.
DEFAULT_CONFIG["services"] = _build_default_services()


def service_capabilities(svc):
    """Return the capability list for a given service config entry.

    Looks up the service's type in the registry. Handy wherever a feature needs
    to ask 'can this service do X?' -- e.g. the search feature only offers
    services whose capabilities include 'search'."""
    spec = SERVICE_REGISTRY.get(svc.get("type"), {})
    return spec.get("capabilities", ["monitor"])


def services_with_capability(cfg, capability):
    """List the names of configured services that support a given capability
    and aren't disabled. Lets features light up automatically for any service
    whose registry entry opts into that capability, instead of hard-coding
    specific service names in the feature code."""
    out = []
    for name, svc in cfg.get("services", {}).items():
        if svc.get("disabled"):
            continue
        if capability in service_capabilities(svc):
            out.append(name)
    return out


# ----------------------------------------------------------------------------
# MEDIA SEARCH + ADD (Radarr / Sonarr lookup endpoints, posters included)
# ----------------------------------------------------------------------------
def _arr_post(base, path, key, payload, timeout=30):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{base}{path}", data=data,
        headers={"X-Api-Key": key, "Content-Type": "application/json"},
        method="POST",
    )
    with safe_urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def _poster_url(images):
    """Pull a usable poster/remote image URL from an *arr images array."""
    for img in images or []:
        if img.get("coverType") == "poster":
            return img.get("remoteUrl") or img.get("url") or ""
    # fall back to first image of any type
    if images:
        return images[0].get("remoteUrl") or images[0].get("url") or ""
    return ""


# ----------------------------------------------------------------------------
# What each searchable "kind" of media maps to. This is the lightweight bit:
# to make a new media type searchable, add a row here describing which service
# handles it and which lookup endpoint to hit. media_search() reads from this
# instead of having a pile of if/else branches, so books and music slot in the
# same way movies and TV did.
#
#   service   the named service that owns this kind (must be set up & enabled)
#   api       the API version path segment ("v3" for Radarr/Sonarr, "v1" for
#             the newer Lidarr/Readarr)
#   lookup    the lookup endpoint that takes ?term=... and returns matches
#   label     friendly name for error messages
#   id_fields which external-id fields to carry back from a result (used so the
#             frontend can show/add things; harmless if a service doesn't set them)
# ----------------------------------------------------------------------------
MEDIA_KINDS = {
    "movie":  {"service": "radarr",  "api": "v3", "lookup": "/api/v3/movie/lookup",   "label": "Radarr",
               "id_fields": ["tmdbId", "imdbId"]},
    "series": {"service": "sonarr",  "api": "v3", "lookup": "/api/v3/series/lookup",  "label": "Sonarr",
               "id_fields": ["tvdbId", "imdbId"]},
    "book":   {"service": "readarr", "api": "v1", "lookup": "/api/v1/search",         "label": "Readarr",
               "id_fields": ["foreignBookId", "titleSlug"]},
    "music":  {"service": "lidarr",  "api": "v1", "lookup": "/api/v1/search",         "label": "Lidarr",
               "id_fields": ["foreignArtistId", "foreignAlbumId"]},
}


def media_search(cfg, kind, term, service=None):
    """Search a media service for something to add. Which service and endpoint
    to use comes from MEDIA_KINDS. Only works if that service is set up (has a
    url + api key) and isn't disabled -- otherwise it returns a friendly error
    and the frontend just won't show that option."""
    spec = MEDIA_KINDS.get(kind)
    if not spec:
        return {"ok": False, "error": f"Don't know how to search for '{kind}'."}
    svc_name = resolve_media_service(cfg, kind, service)
    svc = cfg["services"].get(svc_name, {})
    if not svc:
        return {"ok": False, "error": "Select a configured instance for this media kind."}
    # gate: the service must exist, be enabled, and have its credentials
    if svc.get("disabled") or not svc.get("url") or not svc.get("api_key"):
        return {"ok": False, "error": f"{spec['label']} is not configured."}
    # gate: if the service told us (via its health check) that it has no
    # search-capable indexers, there's nothing to search -- say so plainly.
    for issue in STATE.get("services", {}).get(svc_name, {}).get("errors", []):
        if issue.get("source") == "IndexerSearchCheck":
            return {"ok": False, "error": f"{spec['label']} has no search-capable indexers."}
    base = svc["url"].rstrip("/")
    key = svc["api_key"]
    q = urllib.parse.urlencode({"term": term})
    try:
        status, body = http_get(f"{base}{spec['lookup']}?{q}", {"X-Api-Key": key}, timeout=20)
        if status != 200:
            return {"ok": False, "error": f"{spec['label']} returned HTTP {status}"}
        raw = json.loads(body) if body.strip() else []
        out = []
        for item in raw[:20]:
            # Readarr's /search wraps each hit; unwrap to the book/author object
            # if present, otherwise use the item directly (Radarr/Sonarr/Lidarr).
            obj = item.get("book") or item.get("album") or item.get("artist") or item.get("author") or item
            row = {
                "title": obj.get("title") or obj.get("artistName") or obj.get("authorName") or "",
                "year": obj.get("year", ""),
                "overview": (obj.get("overview", "") or "")[:240],
                "poster": _poster_url(obj.get("images")),
                "already": bool(obj.get("id")),   # has a local id => already in the library
            }
            # carry whatever external ids this kind cares about
            for f in spec["id_fields"]:
                row[f] = obj.get(f, "")
            out.append(row)
        return {"ok": True, "results": out, "kind": kind}
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"ok": False, "error": f"Search failed: {e}"}


def media_profiles(cfg, kind, service=None):
    """Return the quality profiles for Radarr (movie) or Sonarr (series)."""
    if kind not in ("movie", "series"):
        return {"ok": False, "error": "Books and music are search-only. Add them in Readarr or Lidarr."}
    svc_name = resolve_media_service(cfg, kind, service)
    svc = cfg["services"].get(svc_name, {})
    if not svc:
        return {"ok": False, "error": "Select a configured instance for this media kind."}
    if svc.get("disabled") or not svc.get("url") or not svc.get("api_key"):
        return {"ok": False, "error": f"{svc_name.title()} is not configured."}
    base = svc["url"].rstrip("/")
    key = svc["api_key"]
    try:
        _, body = http_get(f"{base}/api/v3/qualityprofile", {"X-Api-Key": key})
        profiles = json.loads(body) if body.strip() else []
        _, root_body = http_get(f"{base}/api/v3/rootfolder", {"X-Api-Key": key})
        roots = json.loads(root_body)
        default = (cfg.get("default_profiles") or {}).get(svc_name, (cfg.get("default_profiles") or {}).get(kind))
        return {
            "ok": True,
            "profiles": [{"id": p.get("id"), "name": p.get("name", "")} for p in profiles],
            "default": default,
            "roots": [{"path": r.get("path"), "id": r.get("id")} for r in roots],
        }
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"ok": False, "error": f"Couldn't load profiles: {e}"}


def media_add(cfg, kind, item, profile_id=None, service=None, root_folder=None):
    """Add a movie (Radarr) or series (Sonarr). Uses the first root folder; quality
    profile is the chosen profile_id, or the first available if none given."""
    if kind not in ("movie", "series"):
        return {"ok": False, "error": "Books and music are search-only. Add them in Readarr or Lidarr."}
    svc_name = resolve_media_service(cfg, kind, service)
    svc = cfg["services"].get(svc_name, {})
    if not svc:
        return {"ok": False, "error": "Select a configured instance for this media kind."}
    if svc.get("disabled") or not svc.get("url") or not svc.get("api_key"):
        return {"ok": False, "error": f"{svc_name.title()} is not configured."}
    base = svc["url"].rstrip("/")
    key = svc["api_key"]
    try:
        # need a root folder and a quality profile id to add anything
        _, rf_body = http_get(f"{base}/api/v3/rootfolder", {"X-Api-Key": key})
        roots = json.loads(rf_body) if rf_body.strip() else []
        if not roots:
            return {"ok": False, "error": f"No root folder set in {svc_name.title()}."}
        root_path = next((r.get("path") for r in roots if r.get("id") == root_folder), None) if isinstance(root_folder, int) else root_folder
        if isinstance(root_folder, int) and root_path is None:
            return {"ok": False, "error": "Selected root folder no longer exists."}
        root_path = root_path or roots[0].get("path", "")
        if root_path not in {r.get("path") for r in roots}:
            return {"ok": False, "error": "Selected root folder no longer exists."}
        _, qp_body = http_get(f"{base}/api/v3/qualityprofile", {"X-Api-Key": key})
        profiles = json.loads(qp_body) if qp_body.strip() else []
        if not profiles:
            return {"ok": False, "error": f"No quality profile in {svc_name.title()}."}
        valid_ids = {p.get("id") for p in profiles}
        if profile_id is not None and profile_id not in valid_ids:
            return {"ok": False, "error": "Selected quality profile no longer exists."}
        qid = profile_id if profile_id is not None else profiles[0].get("id", 1)

        if kind == "movie":
            payload = {
                "title": item.get("title"),
                "year": item.get("year"),
                "tmdbId": item.get("tmdbId"),
                "qualityProfileId": qid,
                "rootFolderPath": root_path,
                "monitored": True,
                "minimumAvailability": "released",
                "addOptions": {"searchForMovie": True},
            }
            status, body = _arr_post(base, "/api/v3/movie", key, payload)
        else:
            payload = {
                "title": item.get("title"),
                "tvdbId": item.get("tvdbId"),
                "qualityProfileId": qid,
                "rootFolderPath": root_path,
                "monitored": True,
                "languageProfileId": 1,
                "addOptions": {"searchForMissingEpisodes": True},
            }
            status, body = _arr_post(base, "/api/v3/series", key, payload)

        if status in (200, 201):
            return {"ok": True, "title": item.get("title")}
        return {"ok": False, "error": f"Add failed (HTTP {status}): {body[:200]}"}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        return {"ok": False, "error": f"HTTP {e.code}: {detail[:200]}"}
    except Exception as e:
        return {"ok": False, "error": f"Add failed: {e}"}


# ----------------------------------------------------------------------------
# TORRENTS (qBittorrent active list, beta feature)
# ----------------------------------------------------------------------------
def _qbit_login(svc):
    base = svc["url"].rstrip("/")
    data = urllib.parse.urlencode({
        "username": svc.get("username", ""), "password": svc.get("password", "")
    }).encode()
    req = urllib.request.Request(f"{base}/api/v2/auth/login", data=data, headers={"Referer": base})
    with safe_urlopen(req, timeout=10) as r:
        cookie = r.headers.get("Set-Cookie", "")
    return base, (cookie.split(";")[0] if cookie else None)


# qBittorrent states grouped into the two tabs
_DOWNLOADING_STATES = {"downloading", "stalledDL", "metaDL", "queuedDL", "forcedDL", "checkingDL", "allocating", "pausedDL", "stoppedDL"}
_SEEDING_STATES = {"uploading", "stalledUP", "queuedUP", "forcedUP", "checkingUP", "pausedUP", "stoppedUP"}


def _qbit_configured(cfg):
    svc = cfg["services"].get("qbittorrent", {})
    return (not svc.get("disabled")) and bool(svc.get("url")) and bool(svc.get("username"))


def _get_torrents_qbit(cfg):
    """Full torrent list from qBittorrent (richest data)."""
    svc = cfg["services"].get("qbittorrent", {})
    base, cookie = _qbit_login(svc)
    _, body = http_get(f"{base}/api/v2/torrents/info", auth_cookie=cookie)
    raw = json.loads(body) if body.strip() else []
    downloading, seeding = [], []
    for t in raw:
        st = t.get("state", "")
        prog = t.get("progress", 0) or 0
        row = {
            "id": t.get("hash", ""), "protocol": "torrent",
            "name": t.get("name", "")[:120],
            "state": st,
            "progress": round(prog * 100, 1),
            "dlspeed": t.get("dlspeed", 0),
            "upspeed": t.get("upspeed", 0),
            "size": t.get("size", 0),
            "seeds": t.get("num_seeds", 0),
            "peers": t.get("num_leechs", 0),
            "ratio": round(t.get("ratio", 0) or 0, 2),
            "eta": t.get("eta", 0),
        }
        if st in _SEEDING_STATES or (prog >= 1 and st not in _DOWNLOADING_STATES):
            seeding.append(row)
        else:
            downloading.append(row)
    downloading.sort(key=lambda x: x["dlspeed"], reverse=True)
    seeding.sort(key=lambda x: x["upspeed"], reverse=True)
    return {"ok": True, "source": "qbittorrent", "downloading": downloading, "seeding": seeding}


def _get_torrents_arr_queue(cfg):
    """Fallback: read the download queue from Radarr/Sonarr (client-agnostic).
    Shows what the *arr stack is actively downloading regardless of torrent client.
    Seeding data isn't available this way; the *arr apps stop tracking after import."""
    rows = []
    for svc_name in ("radarr", "sonarr"):
        svc = cfg["services"].get(svc_name, {})
        if svc.get("disabled") or not svc.get("url") or not svc.get("api_key"):
            continue
        base = svc["url"].rstrip("/")
        key = svc["api_key"]
        try:
            # queue is paginated; pull a big page including unknown items
            q = urllib.parse.urlencode({"pageSize": 200, "includeUnknownMovieItems": "true",
                                        "includeUnknownSeriesItems": "true"})
            _, body = http_get(f"{base}/api/v3/queue?{q}", {"X-Api-Key": key}, timeout=15)
            data = json.loads(body) if body.strip() else {}
            records = data.get("records", data if isinstance(data, list) else [])
            for r in records:
                size = r.get("size", 0) or 0
                left = r.get("sizeleft", 0) or 0
                prog = round((1 - (left / size)) * 100, 1) if size else 0
                rows.append({
                    "name": (r.get("title") or "")[:120],
                    "state": r.get("status", ""),
                    "progress": prog,
                    "dlspeed": 0,            # not reported by the *arr queue
                    "upspeed": 0,
                    "size": size,
                    "seeds": 0,
                    "peers": 0,
                    "ratio": 0,
                    "eta": 0,
                    "client": r.get("downloadClient", ""),
                    "app": svc_name,
                })
        except Exception:
            continue  # skip an app that isn't reachable; others may still work
    rows.sort(key=lambda x: x["progress"], reverse=True)
    return {"ok": True, "source": "arr_queue", "downloading": rows, "seeding": []}


def get_torrents(cfg):
    out = {"ok": True, "source": "combined", "downloading": [], "seeding": [], "errors": []}
    known = set()
    for name, svc in active_instances(cfg):
        if svc.get("type") not in ("qbit", "sabnzbd"):
            continue
        try:
            if svc["type"] == "qbit":
                data = _get_torrents_qbit({"services": {"qbittorrent": svc}})
            else:
                queue = sab_data(svc, "queue", start=0, limit=1000)
                rows = []
                for r in queue.get("slots", []):
                    total = float(r.get("mb", 0) or 0) * 1048576
                    rows.append({"name": r.get("filename", "Download"), "state": r.get("status", ""),
                                 "progress": float(r.get("percentage", 0) or 0), "size": total,
                                 "dlspeed": float(r.get("kbpersec", 0) or 0) * 1024,
                                 "upspeed": 0, "eta": duration_seconds(r.get("timeleft", "")),
                                 "id": r.get("nzo_id", ""), "protocol": "usenet"})
                data = {"downloading": rows, "seeding": []}
            for tab in ("downloading", "seeding"):
                for row in data.get(tab, []):
                    row.update(app=name, client=svc.get("label", name))
                    known.add(str(row.get("id", "")).lower())
                    out[tab].append(row)
        except Exception as e:
            out["errors"].append(f"{svc.get('label', name)}: {e}")
    for name, svc in active_instances(cfg, ("radarr", "sonarr")):
        try:
            for r in arr_queue_records(svc):
                ident = str(r.get("downloadId", "")).lower()
                if ident and ident in known:
                    continue
                known.add(ident)
                total = r.get("size", 0) or 0
                out["downloading"].append({"id": ident, "name": r.get("title", ""), "state": r.get("status", ""),
                    "progress": round(100*(1-(r.get("sizeleft", 0) or 0)/total), 1) if total else 0,
                    "size": total, "dlspeed": 0, "upspeed": 0, "eta": duration_seconds(r.get("timeleft", "")),
                    "app": name, "client": svc.get("label", name), "protocol": "queue"})
        except Exception as e:
            out["errors"].append(f"{svc.get('label', name)} queue: {e}")
    return out


# ----------------------------------------------------------------------------
# REMEDIATION ACTIONS  --  turn a diagnosed problem into a one-click fix.
#
# Each handler takes (svc_name, svc_cfg, params) and returns
# {"ok": bool, "message"/"error": str}. Handlers must never throw (the endpoint
# guards too). Available actions are attached to issues -- health-check issues in
# /api/status via _actions_for_issue, and stuck-queue issues in
# augment_queue_issues -- so the frontend knows which buttons to draw. The whole
# feature is gated by the beta "remediation" toggle, so anyone who dislikes the
# automation can switch it off (which also stops the extra queue polling).
# ----------------------------------------------------------------------------
def _arr_api_ver(name):
    """Radarr/Sonarr use v3; Prowlarr/Readarr/Lidarr use v1 (same rule as check_arr)."""
    return "v1" if name in ("prowlarr", "readarr", "lidarr") else "v3"


def _http_request(method, url, headers=None, data=None, timeout=20):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with safe_urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def _arr_testall(svc_name, svc, endpoint, label):
    """Shared body for the download-client / indexer 'test all' actions."""
    base = svc.get("url", "").rstrip("/"); key = svc.get("api_key", "")
    if not base or not key:
        return {"ok": False, "error": "Service isn't configured."}
    ver = _arr_api_ver(service_app(svc_name, svc))
    try:
        _, body = _http_request("POST", f"{base}/api/{ver}/{endpoint}/testall",
                                headers={"X-Api-Key": key, "Content-Type": "application/json"},
                                data=b"", timeout=30)
        results = json.loads(body) if body.strip() else []
        if not results:
            return {"ok": True, "message": f"No {label}s are configured to test."}
        bad = [r for r in results if not r.get("isValid", True)]
        if bad:
            return {"ok": False, "error": f"{len(bad)} of {len(results)} {label}(s) still failing."}
        return {"ok": True, "message": f"All {len(results)} {label}(s) passed."}
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"ok": False, "error": f"Test failed: {e}"}


def action_test_download_clients(svc_name, svc, params):
    return _arr_testall(svc_name, svc, "downloadclient", "download client")


def action_test_indexers(svc_name, svc, params):
    return _arr_testall(svc_name, svc, "indexer", "indexer")


def _qbit_torrent_op(svc, op, hashes):
    if not isinstance(hashes, list) or not hashes or len(hashes) > 20 or any(
            not isinstance(h, str) or not re.fullmatch(r"[a-fA-F0-9]{40,64}", h) for h in hashes):
        return {"ok": False, "error": "Specify valid torrent hashes."}
    try:
        base, cookie = _qbit_login(svc)
        if not cookie:
            return {"ok": False, "error": "Couldn't log in to qBittorrent."}
        data = urllib.parse.urlencode({"hashes": "|".join(hashes)}).encode()
        req = urllib.request.Request(f"{base}/api/v2/torrents/{op}", data=data,
                                     headers={"Referer": base, "Cookie": cookie}, method="POST")
        with safe_urlopen(req, timeout=15) as r:
            ok = 200 <= r.status < 300
        verb = {"recheck": "Re-check", "reannounce": "Re-announce"}.get(op, op)
        return {"ok": ok, "message": (f"{verb} started." if ok else None),
                "error": (None if ok else "qBittorrent rejected the request.")}
    except Exception as e:
        return {"ok": False, "error": f"Action failed: {e}"}


def action_qbit_recheck(svc_name, svc, params):
    hashes = params.get("hashes") or ([params["hash"]] if params.get("hash") else [])
    return _qbit_torrent_op(svc, "recheck", hashes)


def action_qbit_reannounce(svc_name, svc, params):
    hashes = params.get("hashes") or ([params["hash"]] if params.get("hash") else [])
    return _qbit_torrent_op(svc, "reannounce", hashes)


def action_queue_fix(svc_name, svc, params):
    """Revalidate the current queue item before deletion, and report partial success."""
    app = service_app(svc_name, svc)
    if app not in _QUEUE_ARR:
        return {"ok": False, "error": "This service does not support queue removal."}
    qid = params.get("queue_id")
    if not isinstance(qid, int) or isinstance(qid, bool) or qid <= 0:
        return {"ok": False, "error": "Invalid queue item."}
    base = svc.get("url", "").rstrip("/")
    headers = {"X-Api-Key": svc.get("api_key", ""), "Content-Type": "application/json"}
    removed = False
    try:
        _, body = http_get(f"{base}/api/v3/queue/{qid}", headers)
        current = json.loads(body)
        command, field, item_key = _QUEUE_ARR[app]
        item_id = current.get(item_key)
        expected = params.get("ids") or []
        if not item_id or expected != [item_id]:
            return {"ok": False, "error": "Queue item changed. Refresh before trying again."}
        q = urllib.parse.urlencode({"removeFromClient": "true", "blocklist": "true"})
        _http_request("DELETE", f"{base}/api/v3/queue/{qid}?{q}", headers=headers)
        removed = True
        payload = json.dumps({"name": command, field: [item_id]}).encode()
        _http_request("POST", f"{base}/api/v3/command", headers=headers, data=payload)
        return {"ok": True, "message": "Removed and blocklisted; new search started."}
    except Exception as e:
        prefix = "Removed and blocklisted, but the new search failed. " if removed else "Removal failed. "
        return {"ok": False, "partial": removed, "error": prefix + str(e)}


# Action name -> handler. The /api/action endpoint dispatches through this.
ACTIONS = {
    "test_download_clients": action_test_download_clients,
    "test_indexers":         action_test_indexers,
    "qbit_recheck":          action_qbit_recheck,
    "qbit_reannounce":       action_qbit_reannounce,
    "queue_fix":             action_queue_fix,
}


def _actions_for_issue(stype, issue):
    """Map a health-issue source (the *arr health-check name, or our qBit issues)
    to the remediation buttons we offer. Returns a list of action descriptors."""
    src = (issue.get("source") or "")
    if stype == "arr":
        if src.startswith("DownloadClient"):
            return [{"label": "Test download clients", "action": "test_download_clients",
                     "destructive": False, "params": {}}]
        if src.startswith("Indexer"):
            return [{"label": "Re-test indexers", "action": "test_indexers",
                     "destructive": False, "params": {}}]
    elif stype == "qbit":
        h = issue.get("hash")
        if h:
            return [{"label": "Force re-check", "action": "qbit_recheck",
                     "destructive": False, "params": {"hashes": [h]}},
                    {"label": "Re-announce", "action": "qbit_reannounce",
                     "destructive": False, "params": {"hashes": [h]}}]
    return []


# Which *arr instances have a meaningful download queue, plus the search command
# and id field used to re-search an item after we remove it.
_QUEUE_ARR = {
    "radarr": ("MoviesSearch", "movieIds", "movieId"),
    "sonarr": ("EpisodeSearch", "episodeIds", "episodeId"),
}

# How many already-blocklisted releases for one item means the user is probably
# stuck in a remove/re-search loop (the releases aren't the problem -- their
# client/connection/seeds are). At/above this we escalate the warning.
_LOOP_BLOCKLIST_THRESHOLD = 3

# Benign/transient queue warnings the *arr (or Unpackerr) resolves on its own --
# we must NOT flag these as stuck or offer to remove+blocklist them. Examples: a
# completed download that's just an archive waiting to be extracted, or one that
# already imported successfully and is only lingering while it seeds.
_BENIGN_QUEUE_MSGS = ("found archive", "extract", "already imported")
# Genuine-problem phrases: if any of these are present we DO flag, even alongside
# an otherwise-benign message.
_PROBLEM_QUEUE_MSGS = ("stalled", "no connection", "no peers", "not enough disk",
                       "reporting an error", "no files found")

# Proper troubleshooting wiki per *arr app. Queue/import problems are *arr-side,
# so they must link here (the servarr wiki) -- NOT to qBittorrent's docs.
_ARR_WIKI = {
    "radarr": "https://wiki.servarr.com/radarr/troubleshooting",
    "sonarr": "https://wiki.servarr.com/sonarr/troubleshooting",
}


def _queue_is_problem(rec):
    """Decide whether a queue record is a real stuck/failed download worth
    flagging -- as opposed to a normal pipeline state like 'found archive, will be
    extracted'. Hard failures always flag; a warning whose only message is benign
    (and has no problem phrase) is skipped."""
    tds = (rec.get("trackedDownloadStatus") or "").lower()
    status = (rec.get("status") or "").lower()
    state = (rec.get("trackedDownloadState") or "").lower()
    # already imported = success. Sonarr/Radarr keep the item in the queue while it
    # seeds and tag it 'warning', but the file is in your library. Never flag it.
    # (Note: status 'completed' is NOT a safe skip -- a completed download can still
    # have a failed import, which we DO want to flag.)
    if state == "imported":
        return False
    if tds not in ("warning", "error") and status not in ("failed", "warning"):
        return False
    # genuine failures (bad release, missing files, failed import) always flag
    if status == "failed" or tds == "error" or state in ("importfailed", "failedpending", "failed"):
        return True
    text = (rec.get("errorMessage") or "")
    for sm in (rec.get("statusMessages") or []):
        text += " " + " ".join(sm.get("messages") or [])
    low = text.lower()
    has_problem = any(p in low for p in _PROBLEM_QUEUE_MSGS)
    benign = any(b in low for b in _BENIGN_QUEUE_MSGS)
    if benign and not has_problem:
        return False      # e.g. "Found archive file, might need to be extracted"
    return True


def _arr_blocklist_counts(base, key, id_key, item_ids):
    """None means the guard could not be verified; automatic deletion must stop."""
    counts = {}
    wanted = set(i for i in item_ids if i)
    if not wanted:
        return counts
    try:
        for page in range(1, 101):
            q = urllib.parse.urlencode({"page": page, "pageSize": 200, "sortKey": "date", "sortDirection": "descending"})
            _, body = http_get(f"{base}/api/v3/blocklist?{q}", {"X-Api-Key": key}, timeout=10)
            data = json.loads(body)
            records = data["records"]
            for rec in records:
                for iid in wanted:
                    if rec.get(id_key) == iid or (id_key == "episodeId" and iid in (rec.get("episodeIds") or [])):
                        counts[iid] = counts.get(iid, 0) + 1
            if page * 200 >= data.get("totalRecords", len(records)):
                return counts
        return None
    except Exception:
        return None


def augment_queue_issues(cfg, results):
    """Scan the Radarr/Sonarr download queues for stuck/failed items and surface
    them with the right one-click fix. Only runs when remediation is enabled, so
    turning it off costs zero extra queue calls.

    Two wrinkles worth knowing about:

    1. De-dupe by torrent hash. The queue record's downloadId IS the qBittorrent
       hash, so a stuck download and a stalled torrent are the same problem --
       consolidate onto one issue rather than listing it twice.
    2. Cause-aware actions. A real failure (corrupt/missing files, failed import)
       wants remove + blocklist + re-search. A stall (no seeds, client or peer
       trouble) does not -- re-searching won't fix the connection and just loops --
       so we lead with Force re-check / Re-announce and push remove+blocklist to a
       warned last resort."""
    # Stalled/errored qBittorrent torrents by hash, so we can correlate.
    qbit_by_hash = {}
    for client, _ in active_instances(cfg, stype="qbit"):
        for issue in results.get(client, {}).get("errors", []):
            h = (issue.get("hash") or "").lower()
            if h:
                issue["service"] = client
                qbit_by_hash.setdefault(h, []).append(issue)
    arr_seen_stalls = set()   # downloadIds currently stalling, for grace-timer pruning

    for name, (search_name, ids_field, id_key) in queue_instances(cfg):
        svc = cfg["services"].get(name, {})
        if svc.get("disabled") or not svc.get("url") or not svc.get("api_key"):
            continue
        res = results.get(name)
        if not res:
            continue
        base = svc["url"].rstrip("/"); key = svc["api_key"]
        try:
            records = arr_queue_records(svc)
        except Exception:
            continue
        # Collect the stuck/failed records first, then fetch the blocklist ONCE
        # (only if there's something stuck) to see how many releases we've already
        # burned per item -- the signal for "you're in a loop".
        stuck = [r for r in records if _queue_is_problem(r)]
        if not stuck:
            continue
        blockcounts = _arr_blocklist_counts(base, key, id_key, [r.get(id_key) for r in stuck]) or {}
        stuck_err = stuck_warn = 0
        for rec in stuck:
            tds = (rec.get("trackedDownloadStatus") or "").lower()   # ok | warning | error
            status = (rec.get("status") or "").lower()
            title = (rec.get("title") or "Unknown release")[:80]
            detail = rec.get("errorMessage") or ""
            if not detail:
                parts = []
                for sm in (rec.get("statusMessages") or []):
                    parts.extend(sm.get("messages") or [])
                detail = "; ".join(parts[:2]) if parts else (
                    rec.get("trackedDownloadState") or status or "unknown")
            state = (rec.get("trackedDownloadState") or "").lower()
            dlid = (rec.get("downloadId") or "").lower()
            matches = qbit_by_hash.get(dlid, [])
            qe = matches[0] if len(matches) == 1 else None                      # matching qBit torrent, if any
            qstate = ((qe.get("state") if qe else "") or "").lower()
            low = f"{detail} {state} {qstate}".lower()

            # Is this a genuine failure (removing & re-searching is correct), or a
            # stall/connectivity issue (where it usually won't help and can loop)?
            failed = (status == "failed" or tds == "error"
                      or state in ("importfailed", "failedpending", "failed")
                      or qstate in ("error", "missingfiles")
                      or any(w in low for w in ("missing files", "corrupt", "failed", "not enough disk")))
            lvl = "error" if failed else "warning"

            # If the *arr has already blocklisted a pile of releases for this exact
            # item and it's still failing, the releases probably aren't the problem
            # (client/connection/seeds are), so escalate the warning.
            bcount = blockcounts.get(rec.get(id_key), 0)
            looping = bcount >= _LOOP_BLOCKLIST_THRESHOLD
            note = ""
            if looping:
                note = (f" · {bcount} releases already blocklisted, likely a "
                        "download-client/connection problem, not the release.")

            # "Manual import required" needs a person, not automation: the download
            # is fine, the *arr just couldn't auto-import it. Flag it, but DON'T
            # offer remove+blocklist (that would throw away a good download) or the
            # qBit fixes (the torrent isn't the problem).
            manual = "manual import" in low
            # Proper doc link: queue/import problems are *arr-side, so point at the
            # servarr wiki rather than qBittorrent's docs.
            doc = _ARR_WIKI.get(service_app(name, svc), "https://wiki.servarr.com/")

            # Stall grace: a transient connectivity stall still shows, but stays
            # provisional (no alert) until it's been stalled past the grace window.
            # A correlated item (qe set) is governed by the qBit checker's own
            # grace, so only handle the non-correlated case here.
            stalling = (not failed and not manual and
                        (qstate == "stalleddl"
                         or any(w in low for w in ("stalled", "no connection", "no peers"))))
            provisional = False
            if stalling and dlid and qe is None:
                arr_seen_stalls.add((name, dlid))
                if not _stall_held(_ARR_STALL_SINCE, (name, dlid), True):
                    provisional = True

            # Import-scan grace: "No files found are eligible for import" is usually
            # transient (the *arr is still finishing, or extraction hasn't completed)
            # and clears on the next import pass. Hold off entirely until it has
            # persisted past the grace window, then flag it as a real stuck import.
            if (not failed and not manual and not stalling and dlid
                    and ("eligible for import" in low or "no files found" in low)):
                arr_seen_stalls.add((name, dlid))   # shares the transient grace timer + pruning
                if not _stall_held(_ARR_STALL_SINCE, (name, dlid), True):
                    continue   # within grace: don't show or flag it yet

            # Remove + blocklist + re-search (cause-aware confirmation text).
            remove_act = None
            if not manual and rec.get("id") and rec.get(id_key):
                confirm = ("Remove this download, blocklist the release so it isn't "
                           "grabbed again, then search for a different one?")
                if looping:
                    confirm = (f"You've already blocklisted {bcount} releases for this and it "
                               "still isn't working. The problem is almost certainly your "
                               "download client, VPN/connection, or a lack of seeds, not the "
                               "releases, so removing and re-searching will likely just grab "
                               "another one that stalls.\n\nRemove and blocklist anyway?")
                elif not failed:
                    confirm += ("\n\nHeads-up: the release looks fine, it just isn't "
                                "downloading (usually no seeds, or a download-client / "
                                "connection problem). Removing and re-searching often "
                                "won't fix that and can loop. Try Force re-check / "
                                "Re-announce first, and only remove if you've already "
                                "ruled out your client and a lack of seeds.")
                remove_act = {"label": "Remove + blocklist + re-search", "action": "queue_fix",
                              "destructive": True, "confirm": confirm, "service": name,
                              "params": {"queue_id": rec.get("id"), "search_name": search_name,
                                         "ids_field": ids_field, "ids": [rec.get(id_key)]}}

            # Gentle client-side fixes, only when we can target the qBit torrent
            # (and not for manual-import, where the torrent isn't the problem).
            gentle = []
            if not manual and qe and dlid:
                gentle = [{"label": "Force re-check", "action": "qbit_recheck",
                           "destructive": False, "service": qe["service"], "params": {"hashes": [dlid]}},
                          {"label": "Re-announce", "action": "qbit_reannounce",
                           "destructive": False, "service": qe["service"], "params": {"hashes": [dlid]}}]

            # Order by cause: failures lead with remove; stalls lead with the gentle fixes.
            actions = []
            if failed:
                if remove_act:
                    actions.append(remove_act)
                actions.extend(gentle)
            else:
                actions.extend(gentle)
                if remove_act:
                    actions.append(remove_act)

            if qe is not None:
                # Correlated: same torrent qBittorrent already flagged. Consolidate
                # every action onto that one issue and DON'T add a second one here.
                qe["actions"] = actions
                if note:
                    qe["message"] = (qe.get("message") or "") + note
                # For an import/file problem the *arr wiki is the right help; a pure
                # connectivity stall keeps qBittorrent's own troubleshooting link.
                if manual or failed:
                    qe["fix"] = doc
                continue

            # Not correlated (different client, or qBit isn't flagging it): show it
            # on the *arr card as its own issue. Queue/import problems link to the
            # servarr wiki, never qBittorrent's docs.
            issue = _issue(lvl, title, f"Stuck download: {detail}"[:300], doc)
            issue["id"] = _issue_id(name, issue)   # id from the core message, stable as bcount changes
            issue["service"] = name
            if provisional:
                issue["provisional"] = True   # shows on the dashboard, but no alert yet
            if note:
                issue["message"] = (issue["message"] + note)[:360]
            if actions:
                issue["actions"] = actions
            res.setdefault("errors", []).append(issue)
            if lvl == "error":
                stuck_err += 1
            else:
                stuck_warn += 1
        if stuck_err and res.get("level") != "error":
            res["level"] = "error"
        elif stuck_warn and res.get("level") == "ok":
            res["level"] = "warning"
        if (stuck_err or stuck_warn) and res.get("summary") in ("Healthy", None, ""):
            res["summary"] = f"{stuck_err + stuck_warn} stuck download(s)"

    # prune *arr stall timers for downloads that are no longer stalling
    for k in list(_ARR_STALL_SINCE):
        if k not in arr_seen_stalls:
            del _ARR_STALL_SINCE[k]


# ----------------------------------------------------------------------------
# BLOCKED-FILE SCAN  --  catch fake/malware releases (e.g. a torrent that ships a
# .exe instead of a video). Reads the file list of only the torrents tied to
# Radarr/Sonarr (matched by hash) from qBittorrent, checks each file's extension
# against the user's blocklist, and either flags it with a one-click fix
# (default) or auto-removes it (opt-in). qBittorrent only; archives can't be
# inspected. Each torrent's files are scanned once and cached.
# ----------------------------------------------------------------------------
_MALWARE_SCANNED = {}   # torrent hash -> [] (clean) or [bad filenames]; absent = not scanned


def _qbit_scan_files(base, cookie, h, exts):
    """Return a list of blocked filenames in a torrent, [] if clean, or None if
    the file list isn't available yet (no metadata) so the caller retries."""
    try:
        _, body = http_get(f"{base}/api/v2/torrents/files?hash={urllib.parse.quote(h)}",
                           auth_cookie=cookie)
        files = json.loads(body) if body.strip() else []
    except Exception:
        return None
    if not isinstance(files, list) or not files:
        return None   # metadata not fetched yet
    bad = []
    for f in files:
        nm = (f.get("name") or "")
        if any(nm.lower().endswith(e) for e in exts):
            bad.append(nm.rsplit("/", 1)[-1][:60])
    return bad


def scan_blocked_files(cfg, results):
    """Scan each client independently. Cache is scoped to client and current rules."""
    beta = cfg.get("beta", {})
    exts = tuple(sorted(set("." + str(e).strip().lower().lstrip(".")
                            for e in beta.get("malware_extensions", _DEFAULT_BLOCKED_EXTS) if str(e).strip().lstrip("."))))
    if not exts:
        return
    autoremove = bool(beta.get("malware_autoremove"))
    live = set()
    handled = set()
    for client, qbit in active_instances(cfg, stype="qbit"):
        try:
            base, cookie = _qbit_login(qbit)
            if not cookie:
                continue
            _, body = http_get(f"{base}/api/v2/torrents/info", auth_cookie=cookie)
            hashes = {t.get("hash", "").lower() for t in json.loads(body)}
        except Exception:
            continue
        for name, (command, field, id_key) in queue_instances(cfg):
            svc = cfg["services"][name]
            if name not in results:
                continue
            try:
                records = arr_queue_records(svc)
            except Exception:
                continue
            for rec in records:
                h = (rec.get("downloadId") or "").lower()
                if h not in hashes or (name, rec.get("id")) in handled:
                    continue
                handled.add((name, rec.get("id")))
                cache_key = (client, base, h, exts)
                live.add(cache_key)
                found = _MALWARE_SCANNED.get(cache_key)
                if found is None:
                    found = _qbit_scan_files(base, cookie, h, exts)
                    if found is None:
                        continue
                    _MALWARE_SCANNED[cache_key] = found
                if not found:
                    continue
                item = rec.get(id_key)
                params = {"queue_id": rec.get("id"), "ids": [item], "search_name": command, "ids_field": field}
                msg = "Blocked file type in download: " + ", ".join(found[:3])
                level = "error"
                can_fix = bool(item and rec.get("id"))
                if autoremove and can_fix:
                    counts = _arr_blocklist_counts(svc["url"].rstrip("/"), svc["api_key"], id_key, [item])
                    if counts is None:
                        msg += ". Auto-remove paused: cannot verify the blocklist safety limit."
                    elif counts.get(item, 0) >= _LOOP_BLOCKLIST_THRESHOLD:
                        msg += ". Auto-remove paused after repeated bad releases."
                    else:
                        result = execute_action(cfg, name, "queue_fix", params, automatic=True)
                        msg += ". " + (result.get("message") if result.get("ok") else result.get("error", "Removal failed."))
                        if result.get("ok"):
                            level = "warning"
                            can_fix = False
                        elif result.get("partial"):
                            can_fix = False
                issue = _issue(level, (rec.get("title") or "Download")[:80], msg[:500])
                issue.update(id=_issue_id(name, issue), service=name)
                if can_fix:
                    issue["actions"] = [{"label": "Remove + blocklist + re-search", "action": "queue_fix",
                                         "service": name, "destructive": True, "params": params,
                                         "confirm": "Delete this download, blocklist it, and start a new search?"}]
                res = results[name]
                res.setdefault("errors", []).append(issue)
                if level == "error" or res.get("level") == "ok":
                    res["level"] = level
    for key in list(_MALWARE_SCANNED):
        if key not in live:
            _MALWARE_SCANNED.pop(key, None)


# ----------------------------------------------------------------------------
# STATS (Plex now-playing, library counts, per-drive storage, uptime)
# ----------------------------------------------------------------------------
def _arr_count(svc, kind):
    """Total movies (Radarr) or episodes (Sonarr) via the v3 API."""
    base = svc["url"].rstrip("/"); key = svc.get("api_key", "")
    if not key:
        return None
    try:
        if kind == "movie":
            _, body = http_get(f"{base}/api/v3/movie", {"X-Api-Key": key}, timeout=15)
            return len(json.loads(body)) if body.strip() else 0
        else:
            # episode counts come from the series statistics
            _, body = http_get(f"{base}/api/v3/series", {"X-Api-Key": key}, timeout=15)
            series = json.loads(body) if body.strip() else []
            total = 0
            for s in series:
                st = s.get("statistics", {})
                total += st.get("episodeFileCount", 0) or 0
            return total
    except Exception:
        return None


def _arr_diskspace(svc):
    """Per-drive free/total from an *arr /diskspace endpoint."""
    base = svc["url"].rstrip("/"); key = svc.get("api_key", "")
    if not key:
        return []
    try:
        _, body = http_get(f"{base}/api/v3/diskspace", {"X-Api-Key": key}, timeout=15)
        rows = json.loads(body) if body.strip() else []
        out = []
        for r in rows:
            total = r.get("totalSpace", 0) or 0
            free = r.get("freeSpace", 0) or 0
            if total <= 0:
                continue
            out.append({
                "label": r.get("label") or r.get("path", ""),
                "path": r.get("path", ""),
                "total": total,
                "free": free,
                "used": total - free,
                "pct": round((total - free) / total * 100, 1),
            })
        return out
    except Exception:
        return []


def _plex_sessions(svc):
    """Active Plex streams via /status/sessions."""
    base = svc["url"].rstrip("/"); token = svc.get("token", "")
    if not token:
        return None
    try:
        q = urllib.parse.quote(token)
        _, body = http_get(f"{base}/status/sessions?X-Plex-Token={q}",
                           {"Accept": "application/json"}, timeout=12)
        data = json.loads(body) if body.strip() else {}
        mc = data.get("MediaContainer", {})
        items = mc.get("Metadata", []) or []
        streams = []
        for m in items:
            # progress
            dur = m.get("duration", 0) or 0
            view = m.get("viewOffset", 0) or 0
            pct = round(view / dur * 100, 1) if dur else 0
            mtype = m.get("type", "")
            # title (episodes show grandparent + s/e) + a clean title/year for poster lookup
            if mtype == "episode":
                gp = m.get("grandparentTitle", "")
                idx, pidx = m.get("index"), m.get("parentIndex")
                se = f" · S{pidx:02d}E{idx:02d}" if idx and pidx else ""
                title = f"{gp}{se}"
                lookup_title = gp                      # match the series in Sonarr
                lookup_year = ""
                # prefer the show poster (grandparentThumb) for episodes
                thumb = m.get("grandparentThumb") or m.get("thumb") or ""
            else:
                title = m.get("title", "")
                lookup_title = m.get("title", "")
                lookup_year = m.get("year", "") or ""
                thumb = m.get("thumb") or ""
            # transcode vs direct
            player = m.get("Player", {})
            user = m.get("User", {}).get("title", "")
            tc = m.get("TranscodeSession")
            mode = "transcode" if tc else "direct play"
            res = ""
            try:
                res = (m.get("Media", [{}])[0].get("videoResolution", "") or "").upper()
            except Exception:
                pass
            streams.append({"title": title, "user": user, "mode": mode,
                            "res": res, "progress": pct, "type": mtype,
                            "thumb": thumb, "lookup_title": lookup_title,
                            "lookup_year": lookup_year, "source": "Plex"})
        return {"count": len(streams), "streams": streams}
    except Exception:
        return None


def _jellyfin_sessions(svc):
    """Active Jellyfin streams via /Sessions. There's no dedicated now-playing
    endpoint -- /Sessions returns every session and the ones actually playing
    have a NowPlayingItem key, so we filter on that. We only read fields Jellyfin
    reports consistently (title, user, paused, direct-vs-transcode); we
    deliberately skip bandwidth and resolution, which vary by client and aren't
    reliable. Returns the same shape as _plex_sessions so the stats view can
    treat both the same."""
    base = svc["url"].rstrip("/"); key = svc.get("api_key", "")
    if not key:
        return None
    try:
        _, body = http_get(f"{base}/Sessions", {"X-Emby-Token": key, "Accept": "application/json"}, timeout=12)
        data = json.loads(body) if body.strip() else []
        streams = []
        for s in data:
            npi = s.get("NowPlayingItem")
            if not npi:
                continue   # only sessions actually playing something
            mtype = (npi.get("Type") or "").lower()   # "episode" | "movie" | ...
            if mtype == "episode":
                series = npi.get("SeriesName", "")
                idx, pidx = npi.get("IndexNumber"), npi.get("ParentIndexNumber")
                se = f" · S{pidx:02d}E{idx:02d}" if idx and pidx else ""
                title = f"{series}{se}"
                lookup_title = series
            else:
                title = npi.get("Name", "")
                lookup_title = npi.get("Name", "")
            # progress: Jellyfin reports ticks (100ns units) in PlayState/RunTimeTicks
            dur = npi.get("RunTimeTicks", 0) or 0
            pos = (s.get("PlayState", {}) or {}).get("PositionTicks", 0) or 0
            pct = round(pos / dur * 100, 1) if dur else 0
            paused = bool((s.get("PlayState", {}) or {}).get("IsPaused"))
            # transcode vs direct: trust TranscodingInfo presence, not a guess.
            play_method = (s.get("PlayState", {}) or {}).get("PlayMethod", "")
            is_transcode = bool(s.get("TranscodingInfo")) or play_method == "Transcode"
            mode = "transcode" if is_transcode else "direct play"
            user = s.get("UserName", "")
            streams.append({"title": title, "user": user, "mode": mode,
                            "res": "", "progress": pct, "type": mtype,
                            "paused": paused, "thumb": "",
                            "lookup_title": lookup_title, "lookup_year": "",
                            "source": "Jellyfin"})
        return {"count": len(streams), "streams": streams}
    except Exception:
        return None


# rolling in-memory log of (timestamp, total live stream count) for the 24h graph
_STREAM_HISTORY = []


def _fetch_bytes(url, headers=None, timeout=12):
    """Fetch raw bytes + content-type. Returns (bytes, content_type) or (None, None)."""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with safe_urlopen(req, timeout=timeout) as r:
            ct = r.headers.get("Content-Type", "").split(";", 1)[0].lower()
            data = r.read(5 * 1024 * 1024 + 1)
            if data and len(data) <= 5 * 1024 * 1024 and ct in ("image/jpeg", "image/png", "image/webp", "image/gif", "image/avif"):
                return data, ct
    except Exception:
        pass
    return None, None


def _arr_poster_url(cfg, kind, title, year=""):
    """Look up a poster remoteUrl from Radarr/Sonarr for a given title."""
    try:
        res = media_search(cfg, kind, title)
        if not res.get("ok"):
            return ""
        results = res.get("results", [])
        if not results:
            return ""
        # prefer an exact title (and year) match, else first result
        for r in results:
            if r.get("title", "").lower() == title.lower():
                if not year or str(r.get("year", "")) == str(year):
                    if r.get("poster"):
                        return r["poster"]
        return results[0].get("poster", "")
    except Exception:
        return ""


def _combined_now_playing(cfg):
    streams = []
    for name, svc in active_instances(cfg):
        fetcher = {"plex": _plex_sessions, "jellyfin": _jellyfin_sessions}.get(svc.get("type"))
        if fetcher:
            sessions = fetcher(svc) or {}
            for row in sessions.get("streams", []):
                row.update(instance=name, source=svc.get("label", name))
                streams.append(row)
    return streams


def get_poster(cfg, idx):
    """Resolve a poster image for now-playing stream #idx (index into the
    combined Plex+Jellyfin list). Tries the Plex thumb first (server-side, with
    token), then falls back to a Radarr/Sonarr poster lookup by title. Jellyfin
    streams have no thumb, so they go straight to the arr fallback.
    Returns (bytes, content_type) or (None, None)."""
    streams = get_stats(cfg).get("now_playing", {}).get("streams", [])
    if idx < 0 or idx >= len(streams):
        return None, None
    s = streams[idx]

    # 1) Plex thumbnail (only Plex streams carry one), proxied server-side so the
    # token never reaches the browser
    thumb = s.get("thumb")
    plex = cfg["services"].get(s.get("instance", "plex"), {})
    token = plex.get("token", "")
    if thumb and token and plex.get("type") == "plex":
        base = plex["url"].rstrip("/")
        url = f"{base}{thumb}{'&' if '?' in thumb else '?'}X-Plex-Token={urllib.parse.quote(token)}"
        data, ct = _fetch_bytes(url)
        if data:
            return data, ct

    # 2) fall back to Radarr (movie) / Sonarr (series) poster by title; works
    # for Jellyfin streams too, since it matches on the title we parsed out
    kind = "series" if s.get("type") == "episode" else "movie"
    purl = _arr_poster_url(cfg, kind, s.get("lookup_title", ""), s.get("lookup_year", ""))
    if purl:
        data, ct = _fetch_bytes(purl)
        if data:
            return data, ct

    return None, None


def _record_stream_count(n):
    now = datetime.now().timestamp()
    _STREAM_HISTORY.append((now, n))
    cutoff = now - 86400
    while _STREAM_HISTORY and _STREAM_HISTORY[0][0] < cutoff:
        _STREAM_HISTORY.pop(0)


def uptime_percentages():
    """Time-weighted health during observed periods; offline monitor time is unknown."""
    now = time.time()
    cutoff = now - 30 * 86400
    with OBSERVATION_LOCK:
        data = _read_json(OBSERVATION_FILE, {})
    out = {}
    for name, periods in data.items():
        observed = good = 0.0
        for start, end, healthy in periods:
            duration = max(0, min(now, end) - max(cutoff, start))
            observed += duration
            if healthy:
                good += duration
        if observed:
            out[name] = round(100 * good / observed, 2)
    return out


def _jellyfin_library_counts(svc):
    """Movie + episode counts straight from Jellyfin via /Items/Counts.
    Returns {"movies": n, "episodes": n} or None on failure."""
    base = svc["url"].rstrip("/"); key = svc.get("api_key", "")
    if not key:
        return None
    try:
        _, body = http_get(f"{base}/Items/Counts", {"X-Emby-Token": key, "Accept": "application/json"}, timeout=12)
        data = json.loads(body) if body.strip() else {}
        return {"movies": data.get("MovieCount", 0), "episodes": data.get("EpisodeCount", 0)}
    except Exception:
        return None


def _plex_library_counts(svc):
    """Movie + episode totals from Plex by summing each library section's count
    via /library/sections. Returns {"movies": n, "episodes": n} or None."""
    base = svc["url"].rstrip("/"); token = svc.get("token", "")
    if not token:
        return None
    try:
        q = urllib.parse.quote(token)
        _, body = http_get(f"{base}/library/sections?X-Plex-Token={q}", {"Accept": "application/json"}, timeout=12)
        data = json.loads(body) if body.strip() else {}
        secs = (data.get("MediaContainer", {}) or {}).get("Directory", []) or []
        movies = episodes = 0
        for s in secs:
            stype = s.get("type"); skey = s.get("key")
            if stype not in ("movie", "show") or not skey:
                continue
            # count items in this section (episodes for show libraries)
            ep = "4" if stype == "show" else "1"   # Plex type 4 = episode, 1 = movie
            try:
                _, b2 = http_get(f"{base}/library/sections/{skey}/all?type={ep}&X-Plex-Token={q}&X-Plex-Container-Size=0&X-Plex-Container-Start=0",
                                 {"Accept": "application/json"}, timeout=12)
                d2 = json.loads(b2) if b2.strip() else {}
                total = (d2.get("MediaContainer", {}) or {}).get("totalSize", 0) or 0
            except Exception:
                total = 0
            if stype == "movie": movies += total
            else: episodes += total
        return {"movies": movies, "episodes": episodes}
    except Exception:
        return None


# Short-lived server-side cache for the stats payload. The dashboard fetches
# /api/stats on a throttle, but multiple tabs (and the inline + modal views) can
# still pile up requests; this coalesces them so we don't re-run the whole
# fan-out for every caller. On a miss, _compute_stats runs the underlying calls
# in parallel, so one slow/unreachable service no longer blocks the response.
_STATS_CACHE = {"ts": 0.0, "data": None}
_STATS_LOCK = threading.Lock()
_STATS_TTL = 15  # seconds


def get_stats(cfg):
    """Cached entry point. Returns the last computed stats if they're younger than
    _STATS_TTL, otherwise recomputes (with parallel fetches) and caches. The lock
    also serializes concurrent misses, so a burst of callers triggers one compute
    and everyone shares the result."""
    now = time.time()
    with _STATS_LOCK:
        cached = _STATS_CACHE["data"]
        if cached is not None and (now - _STATS_CACHE["ts"]) < _STATS_TTL:
            return cached
        data = _compute_stats(cfg)
        _STATS_CACHE["ts"] = time.time()
        _STATS_CACHE["data"] = data
        return data


def _compute_stats(cfg):
    out = {"ok": True, "uptime": uptime_percentages()}
    if cfg.get("beta", {}).get("lite_stats"):
        out["lite"] = True
        return out
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        tasks[("streams", "")] = pool.submit(_combined_now_playing, cfg)
        tasks[("downloads", "")] = pool.submit(get_torrents, cfg)
        for name, svc in active_instances(cfg):
            if svc.get("type") in ("plex", "jellyfin"):
                fn = _plex_library_counts if svc["type"] == "plex" else _jellyfin_library_counts
                tasks[("library", name)] = pool.submit(fn, svc)
            if service_app(name, svc) in ("radarr", "sonarr"):
                tasks[("disk", name)] = pool.submit(_arr_diskspace, svc)
    libraries, drives, streams = [], [], []
    for (kind, name), future in tasks.items():
        try:
            data = future.result()
        except Exception:
            continue
        if kind == "library" and data:
            libraries.append(dict(server=cfg["services"][name].get("label", name), **data))
        elif kind == "disk":
            for row in data or []:
                row = dict(row)
                row["label"] = cfg["services"][name].get("label", name) + ": " + row.get("label", "Storage")
                drives.append(row)
        elif kind == "streams":
            streams = data or []
        elif kind == "downloads" and data:
            out["torrents"] = len(data.get("downloading", [])) + len(data.get("seeding", []))
    out["library_by_server"] = libraries
    # Overlapping libraries cannot be deduplicated from counts; retain a clearly labeled estimate.
    for metric in ("movies", "episodes"):
        values = [r[metric] for r in libraries if isinstance(r.get(metric), (int, float))]
        if values:
            out[metric] = max(values)
    if not libraries:
        for app, kind, metric in (("radarr", "movie", "movies"), ("sonarr", "series", "episodes")):
            values = [_arr_count(svc, kind) for _, svc in active_instances(cfg, (app,))]
            values = [v for v in values if isinstance(v, (int, float))]
            if values:
                out[metric] = max(values)
    out["drives"] = drives
    transcoding = sum(s.get("mode") == "transcode" for s in streams)
    out["now_playing"] = {"streams": streams, "count": len(streams), "transcoding": transcoding,
                          "direct": len(streams)-transcoding, "sources": list(dict.fromkeys(s.get("source") for s in streams))}
    _record_stream_count(len(streams))
    out["stream_history"] = [n for _, n in _STREAM_HISTORY][-48:]
    return out


# ----------------------------------------------------------------------------
# UPDATE CHECK (GitHub Releases, once a day, notify only)
# ----------------------------------------------------------------------------
_UPDATE_CACHE = {"checked": 0, "data": None}
_UPDATE_LOCK = threading.Lock()
_UPDATE_TTL = 86400  # re-check at most once per day


def _parse_version(v):
    """'v1.4.0' or '1.4.0' -> (1,4,0) tuple for comparison; non-numeric parts ignored."""
    if not v:
        return ()
    v = str(v).strip().lstrip("vV")
    # take leading dotted-number portion (handles tags like 1.4.0-beta)
    parts = []
    for chunk in v.split("."):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        if num == "":
            break
        parts.append(int(num))
    return tuple(parts)


def _is_newer(remote, local):
    r, l = _parse_version(str(remote).split("-", 1)[0]), _parse_version(str(local).split("-", 1)[0])
    # pad to equal length
    n = max(len(r), len(l))
    r = r + (0,) * (n - len(r))
    l = l + (0,) * (n - len(l))
    if r != l:
        return r > l
    # A stable release supersedes its release candidate with the same numbers.
    return "-" not in str(remote) and "-" in str(local)


def check_for_update(force=False):
    """Hit the GitHub Releases API at most once a day. Returns dict or None.
    Fails silently (returns last cache / None) when offline."""
    now = time.time()
    with _UPDATE_LOCK:
        if not force and (now - _UPDATE_CACHE["checked"] < _UPDATE_TTL):
            return _UPDATE_CACHE["data"]
    data = None
    try:
        req = urllib.request.Request(RELEASES_API, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "GuardTowarr",
        })
        with safe_urlopen(req, timeout=10) as r:
            rel = json.loads(r.read().decode("utf-8"))
        # ignore drafts / prereleases
        if not rel.get("draft") and not rel.get("prerelease"):
            tag = rel.get("tag_name", "")
            if tag and _is_newer(tag, CURRENT_VERSION):
                data = {
                    "available": True,
                    "version": tag,
                    "current": CURRENT_VERSION,
                    "notes": rel.get("body", "") or "",
                    "published": rel.get("published_at", ""),
                    "url": rel.get("html_url", RELEASES_PAGE),
                }
        if data is None:
            data = {"available": False, "current": CURRENT_VERSION}
    except Exception:
        # offline or API error, so keep whatever we had, don't surface an error
        data = _UPDATE_CACHE["data"]
    with _UPDATE_LOCK:
        _UPDATE_CACHE["checked"] = now
        _UPDATE_CACHE["data"] = data
    return data


def _parse_release_notes(body, limit=5):
    """Pull bullet lines from a release body. Returns (bullets, has_more)."""
    bullets = []
    for line in (body or "").splitlines():
        s = line.strip()
        if s[:1] in ("-", "*", "•"):
            text = s[1:].strip()
            if text:
                bullets.append(text)
    has_more = len(bullets) > limit
    return bullets[:limit], has_more


# ----------------------------------------------------------------------------
# DISMISS PERSISTENCE
# ----------------------------------------------------------------------------
DISMISS_LOCK = threading.Lock()
_DISMISSED = None   # in-memory cache; None until the first load reads the file


def _read_dismissed_file():
    if os.path.exists(DISMISS_FILE):
        try:
            with open(DISMISS_FILE) as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return {}


def load_dismissed():
    """Dismissed-issues map, cached in memory so the poller and /api/status don't
    re-read the file every cycle. Returns a copy so callers can't mutate the cache."""
    global _DISMISSED
    with DISMISS_LOCK:
        if _DISMISSED is None:
            _DISMISSED = _read_dismissed_file()
        return dict(_DISMISSED)


def save_dismissed(d):
    global _DISMISSED
    with DISMISS_LOCK:
        _DISMISSED = dict(d)   # keep the cache in lockstep with what's on disk
        atomic_json(DISMISS_FILE, d)


def dismiss_issue(issue_id, meta):
    d = load_dismissed()
    d[issue_id] = {
        "dismissed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "service": meta.get("service", ""),
        "message": meta.get("message", "")
    }
    save_dismissed(d)


def restore_issue(issue_id):
    d = load_dismissed()
    if issue_id in d:
        del d[issue_id]
        save_dismissed(d)


def restore_all():
    save_dismissed({})


# ----------------------------------------------------------------------------
# POLLER
# ----------------------------------------------------------------------------
REFRESH_NOW = threading.Event()  # set by /api/refresh to force an immediate poll

# ----------------------------------------------------------------------------
# HISTORY (state-transition log with 30-day retention)
# ----------------------------------------------------------------------------
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
HISTORY_LOCK = threading.Lock()
HISTORY_RETENTION_DAYS = 30


def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            return []
    return []


def _prune_history(events):
    cutoff = time.time() - HISTORY_RETENTION_DAYS * 86400
    if not isinstance(events, list):
        return []
    recent, anchors = [], {}
    for e in events:
        if not isinstance(e, dict) or not isinstance(e.get("ts"), (int, float)):
            continue
        if e["ts"] >= cutoff:
            recent.append(e)
        elif e.get("service") and e["ts"] > anchors.get(e["service"], {}).get("ts", 0):
            anchors[e["service"]] = e
    return sorted(list(anchors.values()) + recent, key=lambda e: e["ts"])


def log_history(service, kind, level, summary):
    """kind: 'down' | 'recover'. Appended with a unix timestamp."""
    with HISTORY_LOCK:
        events = _prune_history(load_history())
        events.append({
            "ts": datetime.now().timestamp(),
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "service": service,
            "kind": kind,
            "level": level,
            "summary": summary,
        })
        atomic_json(HISTORY_FILE, events)


def history_summary():
    """Per-service outage counts for last 24h / 7d / 30d, plus recent events."""
    events = _prune_history(load_history())
    now = datetime.now().timestamp()
    spans = {"day": 86400, "week": 604800, "month": 2592000}
    per = {}
    for e in events:
        if e.get("kind") != "down":
            continue
        svc = e.get("service", "")
        d = per.setdefault(svc, {"day": 0, "week": 0, "month": 0})
        age = now - e.get("ts", 0)
        for k, secs in spans.items():
            if age <= secs:
                d[k] += 1
    recent = sorted(events, key=lambda e: e.get("ts", 0), reverse=True)[:50]
    return {"counts": per, "recent": recent}


# ----------------------------------------------------------------------------
# NOTIFICATIONS: edge detection, quiet hours, overnight summary
# ----------------------------------------------------------------------------
# last notified severity per service, for edge detection (ok | warning | error)
_LAST_NOTIFY_STATE = {}
_SEV_RANK = {"ok": 0, "warning": 1, "error": 2}

# when each service entered a problem state, so a recovery can report how long it
# was down. Set on the ok -> problem crossing, cleared on recovery.
_DOWN_SINCE = {}

# queued events during quiet hours, flushed as one summary when quiet ends
_QUIET_QUEUE = []
_WAS_QUIET = False

# On startup (or a server reboot), services are often still coming up, so for a
# short settle window we suppress per-service alerts and instead send ONE summary
# of whatever is still wrong when the window ends -- so a restart doesn't bombard.
_STARTUP_GRACE_SECONDS = 120   # 2 minutes
_startup_deadline = None        # set on the first maybe_notify call
_startup_flushed = False


def _parse_hhmm(s):
    try:
        h, m = s.split(":"); return int(h) * 60 + int(m)
    except Exception:
        return None


def in_quiet_hours(notif, now=None):
    if not notif.get("quiet_enabled"):
        return False
    start = _parse_hhmm(notif.get("quiet_start", "23:00"))
    end = _parse_hhmm(notif.get("quiet_end", "07:00"))
    if start is None or end is None:
        return False
    now = now or datetime.now()
    cur = now.hour * 60 + now.minute
    if start == end:
        return False
    if start < end:
        return start <= cur < end           # same-day window
    return cur >= start or cur < end          # window crosses midnight


def send_ntfy(cfg_notif, title, message, priority="default", tags=""):
    """Fire a single ntfy notification. Returns (ok, error)."""
    server = (cfg_notif.get("ntfy_server") or "https://ntfy.sh").rstrip("/")
    topic = (cfg_notif.get("topic") or "").strip()
    if not topic:
        return False, "No ntfy topic set."
    url = f"{server}/{urllib.parse.quote(topic)}"
    try:
        req = urllib.request.Request(url, data=message.encode("utf-8"), method="POST")
        req.add_header("Title", title)
        if priority:
            req.add_header("Priority", priority)
        if tags:
            req.add_header("Tags", tags)
        with safe_urlopen(req, timeout=10) as r:
            return (r.status in (200, 201)), None
    except Exception as e:
        return False, str(e)


# severity -> Discord embed color (decimal RGB)
_DISCORD_COLORS = {"error": 0xE5484D, "warning": 0xE5A00D, "ok": 0x3BB85A, "info": 0x5865F2}


def send_discord(cfg_notif, title, message, level="info", fix_url=""):
    """Fire a single Discord webhook notification as a color-coded embed. Returns (ok, error)."""
    url = (cfg_notif.get("discord_webhook") or "").strip()
    if not url:
        return False, "No Discord webhook set."
    color = _DISCORD_COLORS.get(level, _DISCORD_COLORS["info"])
    icon = {"error": "🔴", "warning": "🟡", "ok": "🟢", "info": "🔔"}.get(level, "🔔")
    embed = {
        "title": f"{icon}  {title}",
        "description": message,
        "color": color,
        "timestamp": datetime.now().astimezone().isoformat(),
        "footer": {"text": "GuardTowarr"},
    }
    if fix_url:
        embed["fields"] = [{"name": "Troubleshooting", "value": f"[View documentation]({fix_url})"}]
    payload = {"username": "GuardTowarr", "embeds": [embed]}
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        # Discord rejects requests without a User-Agent; urllib's default is often blocked.
        req.add_header("User-Agent", "GuardTowarr (https://github.com/tonytrawl/GuardTowarr)")
        with safe_urlopen(req, timeout=10) as r:
            ok = 200 <= r.status < 300
            if not ok:
                print(f"[discord] unexpected status {r.status}")
            return ok, None
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8")[:300]
        except Exception:
            pass
        msg = f"HTTP {e.code} from Discord: {body or e.reason}"
        print(f"[discord] {msg}")
        return False, msg
    except Exception as e:
        print(f"[discord] send failed: {e}")
        return False, str(e)


# Map our severity levels to Pushover's priority scale (-2..2). We keep errors at
# normal priority (0) rather than high (1) so we don't override the user's own
# Pushover quiet-hours/sound settings unless they want that; warnings/info go low.
_PUSHOVER_PRIORITY = {"error": 0, "warning": -1, "ok": -1, "info": -1}


def send_pushover(cfg_notif, title, message, level="info", fix_url=""):
    """Fire a single Pushover notification. Each user supplies their own app
    token + user key (registered free at pushover.net), so nothing routes
    through us. Returns (ok, error). Success is HTTP 200 with status:1."""
    token = (cfg_notif.get("pushover_token") or "").strip()
    user = (cfg_notif.get("pushover_user") or "").strip()
    if not token or not user:
        return False, "Pushover token or user key not set."
    params = {
        "token": token,
        "user": user,
        "title": title,
        "message": message,
        "priority": _PUSHOVER_PRIORITY.get(level, 0),
    }
    # attach the troubleshooting link as a tappable supplementary URL, same as
    # the "View documentation" link we add to Discord alerts
    if fix_url:
        params["url"] = fix_url
        params["url_title"] = "View documentation"
    try:
        data = urllib.parse.urlencode(params).encode("utf-8")
        req = urllib.request.Request("https://api.pushover.net/1/messages.json",
                                     data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with safe_urlopen(req, timeout=10) as r:
            body = r.read().decode("utf-8", "replace")
            try:
                ok = json.loads(body).get("status") == 1
            except Exception:
                ok = 200 <= r.status < 300
            if not ok:
                print(f"[pushover] unexpected response: {body[:200]}")
            return ok, (None if ok else "Pushover rejected the message.")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8")[:300]
        except Exception:
            pass
        msg = f"HTTP {e.code} from Pushover: {body or e.reason}"
        print(f"[pushover] {msg}")
        return False, msg
    except Exception as e:
        print(f"[pushover] send failed: {e}")
        return False, str(e)


def send_telegram(cfg_notif, title, message, level="info", fix_url=""):
    """Fire a single Telegram message via the Bot API. The user makes a bot with
    @BotFather (which gives a token) and supplies the chat id to deliver to. Sent
    as plain text (Telegram auto-links bare URLs) so message contents can't break
    Markdown parsing. Returns (ok, error)."""
    token = (cfg_notif.get("telegram_token") or "").strip()
    chat = (cfg_notif.get("telegram_chat") or "").strip()
    if not token or not chat:
        return False, "Telegram bot token or chat id not set."
    icon = {"error": "🔴", "warning": "🟡", "ok": "🟢", "info": "🔔"}.get(level, "🔔")
    text = f"{icon} {title}\n\n{message}"
    if fix_url:
        text += f"\n\nFix: {fix_url}"
    params = {"chat_id": chat, "text": text, "disable_web_page_preview": "true"}
    try:
        data = urllib.parse.urlencode(params).encode("utf-8")
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage",
                                     data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with safe_urlopen(req, timeout=10) as r:
            body = r.read().decode("utf-8", "replace")
            try:
                ok = json.loads(body).get("ok") is True
            except Exception:
                ok = 200 <= r.status < 300
            return ok, (None if ok else "Telegram rejected the message.")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8")[:300]
        except Exception:
            pass
        msg = f"HTTP {e.code} from Telegram: {body or e.reason}"
        print(f"[telegram] {msg}")
        return False, msg
    except Exception as e:
        print(f"[telegram] send failed: {e}")
        return False, str(e)


def send_alert(notif, title, message, priority="default", tags="", level="info", fix_url=""):
    """Fan out a single alert to every enabled channel (ntfy, Discord, Pushover,
    Telegram). Returns (ok, error) where ok is True if at least one channel
    accepted it."""
    results = []
    # ntfy: opt-in flag (default on) plus a topic
    if notif.get("ntfy_enabled", True) and (notif.get("topic") or "").strip():
        body = message + (f"\n\nFix: {fix_url}" if fix_url else "")
        results.append(send_ntfy(notif, title, body, priority=priority, tags=tags))
    # Discord: opt-in, independent of ntfy
    if notif.get("discord_enabled") and (notif.get("discord_webhook") or "").strip():
        results.append(send_discord(notif, title, message, level=level, fix_url=fix_url))
    # Pushover: opt-in, needs both an app token and a user key
    if notif.get("pushover_enabled") and (notif.get("pushover_token") or "").strip() and (notif.get("pushover_user") or "").strip():
        results.append(send_pushover(notif, title, message, level=level, fix_url=fix_url))
    # Telegram: opt-in, needs both a bot token and a chat id
    if notif.get("telegram_enabled") and (notif.get("telegram_token") or "").strip() and (notif.get("telegram_chat") or "").strip():
        results.append(send_telegram(notif, title, message, level=level, fix_url=fix_url))
    if not results:
        return False, "No notification channel configured."
    ok = any(r[0] for r in results)
    err = next((r[1] for r in results if not r[0]), None)
    return ok, (None if ok else err)


def any_channel_ready(notif):
    """True if at least one delivery channel is configured (ntfy topic, Discord webhook, Pushover keys, or Telegram bot)."""
    has_ntfy = bool(notif.get("ntfy_enabled", True) and (notif.get("topic") or "").strip())
    has_discord = bool(notif.get("discord_enabled") and (notif.get("discord_webhook") or "").strip())
    has_pushover = bool(notif.get("pushover_enabled") and (notif.get("pushover_token") or "").strip() and (notif.get("pushover_user") or "").strip())
    has_telegram = bool(notif.get("telegram_enabled") and (notif.get("telegram_token") or "").strip() and (notif.get("telegram_chat") or "").strip())
    return has_ntfy or has_discord or has_pushover or has_telegram


def effective_level(name, res, dismissed):
    """A service's level for ALERTING -- ignores dismissed issues, and ignores
    'provisional' ones (a freshly-stalled torrent still inside its grace window),
    so neither triggers a notification. The dashboard shows those anyway; this only
    governs whether we alert."""
    errs = res.get("errors", [])
    lvl = res.get("level", "ok")
    if not errs:
        # service-level state (e.g. unreachable) with no itemized issues
        return lvl
    active = [e for e in errs if e.get("id") not in dismissed and not e.get("provisional")]
    if not active:
        return "ok"  # everything itemized is dismissed or still in its grace window
    return "error" if any(e.get("level") == "error" for e in active) else "warning"


def _flush_quiet_summary(notif):
    """Send one summary notification for everything queued during quiet hours."""
    global _QUIET_QUEUE
    if not _QUIET_QUEUE:
        return
    downs = [e for e in _QUIET_QUEUE if e["kind"] == "down"]
    blips = [e for e in _QUIET_QUEUE if e["kind"] == "blip"]
    recovers = [e for e in _QUIET_QUEUE if e["kind"] == "recover"]
    torrents = [e for e in _QUIET_QUEUE if e["kind"] == "torrent"]
    lines = []
    for e in downs:
        lines.append(f"⚠ {e['service'].title()}: {e['summary']}")
    for e in blips:
        lines.append(f"• {e['service'].title()}: had a blip (recovered)")
    for e in recovers:
        lines.append(f"✓ {e['service'].title()}: recovered")
    for e in torrents:
        lines.append(f"✓ {e['summary']}")
    body = "\n".join(lines) if lines else "No issues overnight."
    n = len(downs) + len(blips)
    nt = len(torrents)
    bits = []
    if n: bits.append(f"{n} issue(s)")
    if nt: bits.append(f"{nt} download(s)")
    title = f"Overnight summary: {', '.join(bits)}" if bits else "Overnight summary: all clear"
    send_alert(notif, title, body, priority="default", tags="sunrise", level="info")
    _QUIET_QUEUE = []


def _send_startup_summary(notif, results, dismissed, threshold, ignore):
    """At the end of the startup settle window, send ONE summary of whatever is
    still at/above the alert threshold. Anything that recovered while services
    were booting simply isn't listed. Nothing is sent on a clean startup."""
    if not notif.get("enabled") or not any_channel_ready(notif):
        return
    if in_quiet_hours(notif):
        return   # don't break quiet hours; the dashboard still shows current state
    bad = []
    for name, res in results.items():
        if name in ignore:
            continue
        lvl = effective_level(name, res, dismissed)
        if _SEV_RANK.get(lvl, 0) >= threshold:
            bad.append((name, lvl, res.get("summary", "")))
    if not bad:
        return   # clean startup -> stay silent
    bad.sort(key=lambda b: _SEV_RANK.get(b[1], 0), reverse=True)
    lines = [f"{'🔴' if lvl == 'error' else '⚠'} {n.title()}: {s}" for n, lvl, s in bad]
    title = f"GuardTowarr started: {len(bad)} service(s) need attention"
    send_alert(notif, title, "\n".join(lines), priority="default", tags="warning", level="warning")


# ----------------------------------------------------------------------------
# TORRENT-FINISHED NOTIFICATIONS (beta)
# ----------------------------------------------------------------------------
# track torrent hash -> was-complete, to fire once on the downloading->done edge
_TORRENT_DONE_STATE = {}
_TORRENT_DONE_SEEDED = False  # don't fire for everything already-complete on first run


def _arr_queue_titles(cfg):
    titles = {}
    for name, svc in active_instances(cfg, ("radarr", "sonarr")):
        try:
            for row in arr_queue_records(svc):
                titles[str(row.get("downloadId", "")).lower()] = row.get("title", "")
        except Exception:
            continue
    return titles


def check_torrent_completions(cfg):
    notif = cfg.get("notifications", {})
    if not notif.get("enabled") or not notif.get("torrent_done") or not any_channel_ready(notif):
        return
    for name, svc in active_instances(cfg, stype="qbit"):
        try:
            base, cookie = _qbit_login(svc)
            _, body = http_get(base + "/api/v2/torrents/info", auth_cookie=cookie)
            torrents = json.loads(body)
        except Exception:
            continue
        seen, completed = set(), []
        for row in torrents:
            key = (name, row.get("hash", ""))
            seen.add(key)
            done = (row.get("progress", 0) or 0) >= 1
            if done and _TORRENT_DONE_STATE.get(key) is False:
                completed.append(row)
            _TORRENT_DONE_STATE[key] = done
        for key in list(_TORRENT_DONE_STATE):
            if isinstance(key, tuple) and key[0] == name and key not in seen:
                _TORRENT_DONE_STATE.pop(key, None)
        titles = _arr_queue_titles(cfg) if completed else {}
        for row in completed:
            title = titles.get(row.get("hash", "").lower()) or row.get("name", "Download")
            message = f"{title} finished downloading ({svc.get('label', name)})"
            if in_quiet_hours(notif):
                _QUIET_QUEUE.append({"service": name, "kind": "torrent", "summary": message})
            else:
                send_alert(notif, "Download complete", message, level="ok")


def _fmt_duration(secs):
    """'5m', '45s', '1h 12m' from a number of seconds."""
    secs = int(secs or 0)
    if secs < 60:
        return f"{secs}s"
    mins = secs // 60
    if mins < 60:
        return f"{mins}m"
    hrs, mins = divmod(mins, 60)
    return f"{hrs}h {mins}m" if mins else f"{hrs}h"


def _name_list(names):
    """'Radarr', 'Radarr and Sonarr', 'Radarr, Sonarr, and Prowlarr'."""
    names = [n.title() for n in names]
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + f", and {names[-1]}"


def _transition_text(changed, eligible, down, durations=None):
    """Build (title, body) for a multi-service transition. `changed` = the services
    that flipped this poll; `eligible` = every alertable service. Frames it as
    'all services', 'all except X', or a short list."""
    total = len(eligible)
    n = len(changed)
    not_changed = [e for e in eligible if e not in changed]
    if down:
        if total and n == total:
            return ("🔴 All services went down",
                    f"All {n} services are unreachable. This usually points to the host "
                    f"or network, not the apps themselves.")
        if 0 < len(not_changed) <= 2:
            return ("🔴 Most services went down",
                    f"All services except {_name_list(not_changed)} went down ({n} of {total}).")
        return (f"🔴 {n} services went down", _name_list(changed) + ".")
    # recoveries
    durs = [durations.get(x) for x in changed if durations and durations.get(x)]
    durtxt = f" (down ~{_fmt_duration(max(durs))})" if durs else ""
    if total and n == total:
        return ("✅ All services recovered", f"All {n} services are back online{durtxt}.")
    if 0 < len(not_changed) <= 2:
        return ("✅ Services recovered",
                f"All services except {_name_list(not_changed)} are back online{durtxt}.")
    parts = []
    for x in changed:
        d = durations.get(x) if durations else None
        parts.append(f"{x.title()} (down {_fmt_duration(d)})" if d else x.title())
    return (f"✅ {n} services recovered", ", ".join(parts) + " are back online.")


def _emit_transition_alerts(notif, went_bad, recovered, eligible):
    """One alert for a single change (exactly as before); a summary when several
    services flip together in the same poll."""
    if len(went_bad) == 1:
        name, lvl, summary, fix = went_bad[0]
        send_alert(notif, f"{name.title()}: {'Error' if lvl == 'error' else 'Warning'}",
                   summary, priority="high" if lvl == "error" else "default",
                   tags="rotating_light" if lvl == "error" else "warning",
                   level="error" if lvl == "error" else "warning", fix_url=fix)
    elif went_bad:
        anyerr = any(l == "error" for _, l, _, _ in went_bad)
        title, body = _transition_text([n for n, _, _, _ in went_bad], eligible, down=True)
        send_alert(notif, title, body, priority="high" if anyerr else "default",
                   tags="rotating_light" if anyerr else "warning",
                   level="error" if anyerr else "warning")

    if len(recovered) == 1:
        name, dur = recovered[0]
        extra = f" (down {_fmt_duration(dur)})" if dur else ""
        send_alert(notif, f"{name.title()}: Recovered", f"{name.title()} is healthy again{extra}.",
                   priority="default", tags="white_check_mark", level="ok")
    elif recovered:
        title, body = _transition_text([n for n, _ in recovered], eligible, down=False,
                                       durations=dict(recovered))
        send_alert(notif, title, body, priority="default", tags="white_check_mark", level="ok")


def maybe_notify(results):
    global _WAS_QUIET, _startup_deadline, _startup_flushed
    cfg = get_config()
    notif = cfg.get("notifications", {})
    dismissed = set(load_dismissed().keys())

    # Compute transitions first (history is logged regardless of notification settings)
    threshold = _SEV_RANK.get(notif.get("severity", "error"), 2)
    ignore = set(notif.get("ignore_services", []))
    notify_recovery = notif.get("notify_recovery", True)
    quiet = in_quiet_hours(notif)

    # Startup settle window: suppress per-service alerts until it ends, then send
    # one summary. Avoids a flood when GuardTowarr (or the server) just came up.
    now_ts = time.time()
    if _startup_deadline is None:
        _startup_deadline = now_ts + _STARTUP_GRACE_SECONDS
    in_startup = not _startup_flushed

    # When quiet hours just ended, send the batched summary.
    if _WAS_QUIET and not quiet and notif.get("enabled"):
        _flush_quiet_summary(notif)
    _WAS_QUIET = quiet

    went_bad_list = []    # (name, lvl, summary, fix) collected this poll (non-quiet)
    recovered_list = []   # (name, downtime_seconds_or_None)
    eligible = [n for n in results if n not in ignore]   # alertable services

    for name, res in results.items():
        lvl = effective_level(name, res, dismissed)
        prev = _LAST_NOTIFY_STATE.get(name, "ok")
        prev_rank, cur_rank = _SEV_RANK.get(prev, 0), _SEV_RANK.get(lvl, 0)
        summary = res.get("summary", "Issue detected")

        went_bad = cur_rank >= threshold and cur_rank > prev_rank
        recovered = cur_rank == 0 and prev_rank >= threshold

        # ---- history + downtime tracking (independent of notify on/off) ----
        recover_dur = None
        if cur_rank >= 1 and cur_rank > prev_rank:
            log_history(name, "down", lvl, summary)
        elif cur_rank == 0 and prev_rank >= 1:
            log_history(name, "recover", "ok", f"{name.title()} healthy again")
            ds = _DOWN_SINCE.pop(name, None)
            recover_dur = (now_ts - ds) if ds else None
        if cur_rank >= 1 and prev_rank == 0:
            _DOWN_SINCE[name] = now_ts   # outage start, for the recovery's downtime

        _LAST_NOTIFY_STATE[name] = lvl

        # ---- notifications ----
        # During the startup settle window we record state/history (above) but
        # hold per-service alerts; one summary is sent when the window ends.
        if in_startup:
            continue
        if not notif.get("enabled") or not any_channel_ready(notif):
            continue
        if name in ignore:
            continue

        if quiet:
            # queue rather than send; a recovered-during-night item becomes a "blip"
            if went_bad:
                _QUIET_QUEUE.append({"service": name, "kind": "down", "summary": summary})
            elif recovered:
                downgraded = False
                for e in _QUIET_QUEUE:
                    if e["service"] == name and e["kind"] == "down":
                        e["kind"] = "blip"; downgraded = True
                if not downgraded and notify_recovery:
                    _QUIET_QUEUE.append({"service": name, "kind": "recover", "summary": ""})
            continue

        # not quiet -> collect this poll's transitions; delivered (single or summary) below
        if went_bad:
            fix = next((e.get("fix") for e in res.get("errors", []) if e.get("fix")), "")
            went_bad_list.append((name, lvl, summary, fix))
        elif recovered and notify_recovery:
            recovered_list.append((name, recover_dur))

    # Burst-aware delivery: a single change sends one alert (exactly as before);
    # several services flipping together in one poll (e.g. a host reboot) become a
    # summary instead of a flood.
    if went_bad_list or recovered_list:
        _emit_transition_alerts(notif, went_bad_list, recovered_list, eligible)

    # End of the startup window: send the one-shot summary, then resume normal
    # per-service alerting. (State + history were already updated in the loop.)
    if in_startup and now_ts >= _startup_deadline:
        _startup_flushed = True
        _send_startup_summary(notif, results, dismissed, threshold, ignore)


# Dependency rules: a downstream issue (matched by substrings) is explained by one
# of the listed root services being down. When a root is down, the *arr apps light
# up with the same complaint, so we tag the downstream copy and stop it alerting --
# the root's own alert covers the whole group.
_DEP_RULES = [
    (("indexer",), ("prowlarr",)),
    (("download client", "downloadclient"), ("qbittorrent", "sabnzbd", "nzbget")),
]
# Only the media *arr apps have these downstream dependencies.
_DEP_DOWNSTREAM = {"radarr", "sonarr", "readarr", "lidarr"}
_DEP_LABELS = {"prowlarr": "Prowlarr", "qbittorrent": "qBittorrent",
               "sabnzbd": "SABnzbd", "nzbget": "NZBGet"}


def apply_dependency_context(cfg, results):
    if not cfg.get("notifications", {}).get("dependency_aware", True):
        return
    for patterns, roots in _DEP_RULES:
        candidates = [(n, s) for n, s in active_instances(cfg, roots)]
        down = [n for n, _ in candidates if results.get(n, {}).get("level") == "error"]
        if len(candidates) != 1 or not down:
            continue
        root = down[0]
        for name, svc in active_instances(cfg, _DEP_DOWNSTREAM):
            for issue in results.get(name, {}).get("errors", []):
                blob = f"{issue.get('source', '')} {issue.get('message', '')}".lower()
                if any(p in blob for p in patterns):
                    issue["caused_by"] = root
                    issue["provisional"] = True
                    issue["message"] += f" (likely caused by {cfg['services'][root].get('label', root)} being down)"


def run_poll_once():
    cfg = get_config()
    started = time.time()
    results = {}
    with STATE_LOCK:
        STATE["polling"] = True
    def check(name, svc):
        try:
            checker = CHECKERS.get(svc.get("type"))
            if not checker:
                return svc_result(name, "warning", "Unsupported service type", [])
            result = checker(name, svc)
            result["checked_at"] = time.time()
            return result
        except Exception as e:
            return svc_result(name, "error", f"Check failed: {e}", [])
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        jobs = {pool.submit(check, n, s): n for n, s in active_instances(cfg)}
        for future in concurrent.futures.as_completed(jobs):
            results[jobs[future]] = future.result()
            with STATE_LOCK:
                STATE["services"][jobs[future]] = copy.deepcopy(results[jobs[future]])
    for enabled, fn in ((cfg.get("beta", {}).get("remediation", True), augment_queue_issues),
                        (cfg.get("beta", {}).get("malware_scan"), scan_blocked_files)):
        if enabled:
            try:
                fn(cfg, results)
            except Exception as e:
                print(f"[diagnostics] {e}")
    apply_dependency_context(cfg, results)
    record_observations(results, cfg.get("poll_interval", 30))
    with STATE_LOCK:
        STATE.update(services=results, last_poll=datetime.now().isoformat(timespec="seconds"),
                     last_poll_epoch=time.time(), poll_duration=round(time.time()-started, 2), polling=False)
    for fn in (maybe_notify,):
        try:
            fn(results)
        except Exception as e:
            print(f"[notifications] {e}")
    check_torrent_completions(cfg)


def poll_loop():
    while True:
        try:
            run_poll_once()
        except Exception as e:
            with STATE_LOCK:
                STATE["polling"] = False
                STATE["poll_error"] = "Monitoring cycle failed; retrying."
            print(f"[poll] {e}")
        if REFRESH_NOW.wait(timeout=max(5, get_config().get("poll_interval", 30))):
            REFRESH_NOW.clear()


# ----------------------------------------------------------------------------
# WEB SERVER
# ----------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    # Endpoints the restricted public port is allowed to serve (everything else
    # is 404'd there). Admin/credential/destructive routes are deliberately absent.
    _PUBLIC_GET = {"/api/status", "/api/stats", "/api/history", "/api/update"}
    _PUBLIC_POST = {"/api/search", "/api/profiles", "/api/add", "/api/action", "/api/torrents"}

    def log_message(self, *a):
        pass  # quiet

    def _json(self, obj, code=200):
        if self._is_public():
            obj = public_payload(obj, get_config())
        payload = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length < 0 or length > 1024 * 1024:
            raise ValueError("Request body is too large.")
        if not length:
            return {}
        try:
            body = json.loads(self.rfile.read(length).decode())
            if not isinstance(body, dict):
                raise ValueError("Expected a JSON object.")
            return body
        except Exception:
            raise ValueError("Invalid JSON object.")

    # ---- public-port gating -------------------------------------------------
    def _is_public(self):
        return getattr(self.server, "is_public", False)

    def _public_token_ok(self):
        """Constant-time check of the shared token, from the X-GT-Token header or
        a ?t= query param (needed for <img>/poster requests that can't set headers)."""
        token = (get_config().get("public", {}).get("token") or "")
        if not token:
            return False
        supplied = self.headers.get("X-GT-Token", "")
        if not supplied:
            try:
                supplied = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("t", [""])[0]
            except Exception:
                supplied = ""
        return bool(supplied) and hmac.compare_digest(str(supplied).encode(), str(token).encode())

    def _deny(self, code, msg="Not available on the public endpoint."):
        self._json({"ok": False, "error": msg}, code)
        return False

    def _public_get_ok(self):
        """For the public server: True to proceed with normal routing, else respond
        and return False. The page shell loads without a token; APIs need one."""
        path = self.path.split("?", 1)[0]
        if not path.startswith("/api/"):
            return True   # the static page / shell, no secrets in it
        if path.startswith("/api/poster"):
            return True if self._public_token_ok() else self._deny(401, "Token required.")
        if path in self._PUBLIC_GET:
            return True if self._public_token_ok() else self._deny(401, "Token required.")
        return self._deny(404)

    def _admin_host_ok(self):
        # The unauthenticated LAN port must not answer for attacker-controlled
        # DNS names. Otherwise DNS rebinding can turn a website into a LAN client.
        if self._is_public():
            return True
        try:
            host = urllib.parse.urlsplit("http://" + self.headers.get("Host", "")).hostname
            if not host:
                raise ValueError()
            try:
                ipaddress.ip_address(host)
                return True
            except ValueError:
                pass
            if host.lower().rstrip(".") in {"localhost", socket.gethostname().lower(), socket.getfqdn().lower()}:
                return True
            raise ValueError()
        except ValueError:
            return self._deny(403, "Use the server IP address or local hostname for the admin dashboard.")

    def do_GET(self):
        if not self._admin_host_ok():
            return
        if self._is_public() and not self._public_get_ok():
            return
        self.path = urllib.parse.urlsplit(self.path).path + ("?" + urllib.parse.urlsplit(self.path).query if self.path.startswith("/api/poster?") else "")
        if self.path == "/api/status":
            with STATE_LOCK:
                state = json.loads(json.dumps(STATE))
            state["dismissed"] = load_dismissed()
            cfg = get_config()
            last = state.get("last_poll_epoch", 0)
            state["stale"] = not last or time.time() - last > max(90, cfg.get("poll_interval", 30) * 3)
            state["version"] = CURRENT_VERSION
            state["search_instances"] = [{"service": n, "label": s.get("label", n), "kind": kind}
                for kind, spec in MEDIA_KINDS.items() for n, s in active_instances(cfg, (spec["service"],))
                if s.get("url") and s.get("api_key")]
            # surface display-relevant flags + onboarding needs
            svc_meta = {}
            onboarding = []
            for name, svc in cfg["services"].items():
                miss = [] if svc.get("disabled") else missing_credentials(svc)
                svc_meta[name] = {
                    "label": svc.get("label", name), "app": service_app(name, svc),
                    "type": svc.get("type"),
                    "enabled": svc.get("enabled", True),
                    "disabled": svc.get("disabled", False),
                    "hidden": svc.get("hidden", False),
                    "needs_setup": bool(miss),
                    "url": svc.get("url", ""),
                }
                if miss:
                    # Always surface the address field too (prefilled), so users on a
                    # non-default host can confirm/correct it during first-run setup.
                    prompt_fields = list(dict.fromkeys(["url"] + miss))
                    values = {f: svc.get(f, "") for f in prompt_fields}
                    onboarding.append({
                        "service": name, "type": svc.get("type"),
                        "missing": prompt_fields, "values": values,
                    })
            state["service_meta"] = svc_meta
            state["onboarding"] = onboarding
            # Attach one-click remediation actions to health issues (on the copy,
            # never the live STATE). Queue issues already carry their own actions.
            # Gated by the beta toggle so the buttons vanish when it's off.
            if cfg.get("beta", {}).get("remediation", True):
                for sname, sres in state.get("services", {}).items():
                    stype = (cfg["services"].get(sname, {}) or {}).get("type")
                    for e in sres.get("errors", []):
                        if "actions" in e:
                            continue
                        acts = _actions_for_issue(stype, e)
                        if acts:
                            e["actions"] = acts
            # First-run catalog: every service with its required fields, plus the
            # short blurb and capability list pulled from the registry, so the
            # setup screen can describe each service without the frontend
            # hard-coding any of it.
            state["setup_complete"] = cfg.get("setup_complete", False)
            state["service_catalog"] = [
                {
                    "service": name,
                    "label": svc.get("label", name), "app": service_app(name, svc),
                    "type": svc.get("type"),
                    "url": svc.get("url", ""),
                    "fields": list(dict.fromkeys(["url"] + REQUIRED_FIELDS.get(svc.get("type"), []))),
                    "blurb": SERVICE_BLURBS.get(svc.get("type"), ""),
                    "capabilities": service_capabilities(svc),
                }
                for name, svc in cfg["services"].items()
            ]
            # Which media kinds can actually be searched right now. A kind is
            # available only if its backing service is enabled, has an api key,
            # AND isn't reporting that it has no search-capable indexers. That
            # last check matters for Readarr/Lidarr: if the app's own health
            # endpoint says "IndexerSearchCheck -- no indexers with Automatic
            # Search enabled", searching would just return nothing, so we hide
            # the option instead of letting it look broken.
            poll_results = STATE.get("services", {})
            def _can_search(svc_name):
                res = poll_results.get(svc_name, {})
                for issue in res.get("errors", []):
                    if issue.get("source") == "IndexerSearchCheck":
                        return False
                return True
            search_kinds = []
            for k, spec in MEDIA_KINDS.items():
                ready = any(s.get("url") and s.get("api_key") and _can_search(n)
                            for n, s in active_instances(cfg, (spec["service"],)))
                if ready:
                    search_kinds.append(k)
            state["search_kinds"] = search_kinds
            state["poll_interval"] = cfg.get("poll_interval", POLL_INTERVAL)
            state["theme"] = cfg.get("theme", "auto")
            state["beta"] = cfg.get("beta", {"torrents": False})
            state["notifications_enabled"] = cfg.get("notifications", {}).get("enabled", False)
            state["ui"] = cfg.get("ui", {})
            # On the public port, scrub anything that leaks internal addresses or
            # would let a remote visitor reconfigure the app. Service health still
            # shows; the URLs/IPs and onboarding values do not.
            if self._is_public():
                for m in state.get("service_meta", {}).values():
                    m["url"] = ""
                for c in state.get("service_catalog", []):
                    c["url"] = ""
                # only show fix buttons remotely when remote actions are allowed;
                # otherwise strip them (and /api/action stays blocked)
                if not cfg.get("public", {}).get("allow_actions"):
                    for sres in state.get("services", {}).values():
                        for e in sres.get("errors", []):
                            e.pop("actions", None)
                state["onboarding"] = []
                state["public"] = True
                state["allow_requests"] = bool(cfg.get("public", {}).get("allow_requests"))
                state["allow_actions"] = bool(cfg.get("public", {}).get("allow_actions"))
            self._json(state)

        elif self.path == "/api/config":
            # full config including credentials (local self-hosted tool, user-owned)
            self._json(get_config())

        elif self.path == "/api/history":
            self._json({"ok": True, "uptime": uptime_percentages(), "actions": _read_json(ACTION_FILE, [])[-50:][::-1], **history_summary()})

        elif self.path == "/api/stats":
            data = get_stats(get_config())
            if self._is_public() and isinstance(data, dict):
                for d in data.get("drives", []):
                    d["path"] = ""   # don't leak filesystem layout remotely
            self._json(data)

        elif self.path.startswith("/api/poster"):
            try:
                qs = urllib.parse.urlparse(self.path).query
                idx = int(urllib.parse.parse_qs(qs).get("i", ["0"])[0])
            except Exception:
                idx = 0
            data, ct = get_poster(get_config(), idx)
            if data:
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404); self.end_headers()

        elif self.path == "/api/update":
            cfg = get_config()
            if not cfg.get("ui", {}).get("update_check", True):
                return self._json({"available": False, "current": CURRENT_VERSION})
            info = check_for_update() or {"available": False, "current": CURRENT_VERSION}
            resp = dict(info)
            if info.get("available"):
                bullets, more = _parse_release_notes(info.get("notes", ""))
                resp["bullets"] = bullets
                resp["has_more"] = more
            self._json(resp)

        else:
            page = PAGE
            if self._is_public():
                # Tell the frontend it's the restricted view so it shows the token
                # gate and hides settings/services. (Real protection is the server
                # gating above; this is just UX.)
                allow = "true" if get_config().get("public", {}).get("allow_requests") else "false"
                flag = f"<script>window.GT_PUBLIC=true;window.GT_ALLOW_REQUESTS={allow};</script>"
                page = page.replace("<head>", "<head>" + flag, 1)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'self'")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(page.encode())

    def do_POST(self):
        if not self._admin_host_ok():
            return
        # Authenticate before reading a potentially slow or oversized body.
        if self._is_public() and not self._public_token_ok():
            return self._deny(401, "Token required.")
        origin = self.headers.get("Origin")
        if origin and urllib.parse.urlsplit(origin).netloc != self.headers.get("Host"):
            return self._deny(403, "Cross-origin writes are not allowed.")
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return self._deny(403, "Cross-site writes are not allowed.")
        if self.headers.get("Content-Length", "0") != "0" and self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            return self._deny(415, "Use application/json.")
        try:
            body = self._read_body()
        except (ValueError, TypeError):
            return self._json({"ok": False, "error": "Expected a JSON object under 1 MB."}, 400)
        for key in ("service", "action", "kind", "term", "root_folder", "id"):
            if key in body and not isinstance(body[key], str):
                return self._json({"ok": False, "error": f"{key} must be text."}, 400)
        for key in ("params", "item"):
            if key in body and not isinstance(body[key], dict):
                return self._json({"ok": False, "error": f"{key} must be an object."}, 400)
        for key in ("profile_id", "root_folder_id"):
            if body.get(key) is not None and (not isinstance(body[key], int) or isinstance(body[key], bool)):
                return self._json({"ok": False, "error": f"{key} must be an integer."}, 400)

        # Public port: only the allowlisted POSTs, behind the token, each behind its
        # own opt-in. Requests (search/add) need allow_requests; remediation needs
        # allow_actions. Both off by default, so it's read-only out of the box.
        if self._is_public():
            path = self.path.split("?", 1)[0]
            if path not in self._PUBLIC_POST:
                return self._deny(404)
            if not self._public_token_ok():
                return self._deny(401, "Token required.")
            pub = get_config().get("public", {})
            if path == "/api/torrents":
                pass   # read-only monitoring (no creds/IPs) -> the token is enough
            elif path == "/api/action":
                if not pub.get("allow_actions"):
                    return self._deny(403, "Actions are disabled on the public endpoint.")
            elif not pub.get("allow_requests"):
                return self._deny(403, "Requests are disabled on the public endpoint.")

        if self.path == "/api/dismiss":
            issue_id = body.get("id", "")
            if issue_id:
                dismiss_issue(issue_id, body)
                return self._json({"ok": True})
            return self._json({"ok": False, "error": "missing id"}, 400)

        if self.path == "/api/restore":
            issue_id = body.get("id", "")
            if issue_id == "__all__":
                restore_all()
            elif issue_id:
                restore_issue(issue_id)
            return self._json({"ok": True})

        if self.path == "/api/refresh":
            REFRESH_NOW.set()
            return self._json({"ok": True})

        if self.path == "/api/config":
            # body is the full new config; validate minimally then persist
            new_cfg = body.get("config")
            if not isinstance(new_cfg, dict) or "services" not in new_cfg:
                return self._json({"ok": False, "error": "invalid config"}, 400)
            try:
                new_cfg = validate_config(new_cfg)
            except (ValueError, TypeError) as e:
                return self._json({"ok": False, "error": str(e)}, 400)
            with CONFIG_LOCK:
                try:
                    save_config(new_cfg)
                except OSError:
                    return self._json({"ok": False, "error": "Could not save settings; previous settings retained."}, 500)
                CONFIG.clear()
                CONFIG.update(new_cfg)
            with _STATS_LOCK:
                _STATS_CACHE["ts"] = 0.0  # force a fresh stats compute (e.g. lite_stats toggled)
            REFRESH_NOW.set()  # apply immediately
            return self._json({"ok": True})

        if self.path == "/api/test-service":
            name = body.get("service", "")
            svc = body.get("config")
            try:
                cfg = validate_config({"services": {name: svc}})
                svc = cfg["services"][name]
                missing = missing_credentials(svc)
                if missing:
                    return self._json({"ok": False, "error": "Missing: " + ", ".join(missing)})
                result = CHECKERS[svc["type"]](name, svc)
                return self._json({"ok": result["level"] != "error", "result": result})
            except Exception as e:
                return self._json({"ok": False, "error": str(e)}, 400)

        if self.path == "/api/search":
            kind = body.get("kind", "movie")
            term = (body.get("term") or "").strip()
            if not term:
                return self._json({"ok": False, "error": "empty search"}, 400)
            return self._json(media_search(get_config(), kind, term, body.get("service")))

        if self.path == "/api/profiles":
            kind = body.get("kind", "movie")
            return self._json(media_profiles(get_config(), kind, body.get("service")))

        if self.path == "/api/add":
            kind = body.get("kind", "movie")
            item = body.get("item", {})
            profile_id = body.get("profile_id")
            if not isinstance(item, dict):
                return self._json({"ok": False, "error": "Invalid media item."}, 400)
            result = media_add(get_config(), kind, item, profile_id, body.get("service"), body.get("root_folder_id", body.get("root_folder")))
            # remember the chosen profile as the default for next time
            if result.get("ok") and profile_id is not None:
                with CONFIG_LOCK:
                    instance = resolve_media_service(CONFIG, kind, body.get("service"))
                    CONFIG.setdefault("default_profiles", {})[instance or kind] = profile_id
                save_config(get_config())
            return self._json(result)

        if self.path == "/api/torrents":
            cfg = get_config()
            if not cfg.get("beta", {}).get("torrents"):
                return self._json({"ok": False, "error": "Beta feature disabled."}, 403)
            return self._json(get_torrents(cfg))

        if self.path == "/api/test-notify":
            notif = get_config().get("notifications", {})
            sent, failed = [], []
            if notif.get("ntfy_enabled", True) and (notif.get("topic") or "").strip():
                ok, err = send_ntfy(notif, "GuardTowarr test",
                                    "If you can read this, ntfy notifications are working.",
                                    priority="default", tags="bell")
                (sent if ok else failed).append("ntfy" if ok else f"ntfy ({err})")
            if notif.get("discord_enabled") and (notif.get("discord_webhook") or "").strip():
                ok, err = send_discord(notif, "GuardTowarr test",
                                       "If you can read this, Discord notifications are working.",
                                       level="info")
                (sent if ok else failed).append("Discord" if ok else f"Discord ({err})")
            if notif.get("pushover_enabled") and (notif.get("pushover_token") or "").strip() and (notif.get("pushover_user") or "").strip():
                ok, err = send_pushover(notif, "GuardTowarr test",
                                        "If you can read this, Pushover notifications are working.",
                                        level="info")
                (sent if ok else failed).append("Pushover" if ok else f"Pushover ({err})")
            if notif.get("telegram_enabled") and (notif.get("telegram_token") or "").strip() and (notif.get("telegram_chat") or "").strip():
                ok, err = send_telegram(notif, "GuardTowarr test",
                                        "If you can read this, Telegram notifications are working.",
                                        level="info")
                (sent if ok else failed).append("Telegram" if ok else f"Telegram ({err})")
            if not sent and not failed:
                return self._json({"ok": False, "error": "No notification channel is enabled."})
            return self._json({"ok": bool(sent), "sent": sent, "failed": failed,
                               "error": ("; ".join(failed) if failed else None)})

        if self.path == "/api/action":
            cfg = get_config()
            if not cfg.get("beta", {}).get("remediation", True):
                return self._json({"ok": False, "error": "Remediation actions are turned off."}, 403)
            service = body.get("service", "")
            action = body.get("action", "")
            params = body.get("params") or {}
            svc = cfg["services"].get(service)
            if not svc:
                return self._json({"ok": False, "error": "Unknown service."}, 400)
            fn = ACTIONS.get(action)
            if not fn:
                return self._json({"ok": False, "error": "Unknown action."}, 400)
            try:
                result = execute_action(cfg, service, action, params)
            except Exception as e:
                result = {"ok": False, "error": f"Action failed: {e}"}
            if result.get("ok"):
                REFRESH_NOW.set()  # re-poll so the resolved issue clears quickly
            return self._json(result)

        self._json({"ok": False, "error": "unknown endpoint"}, 404)


def run_server(port, public=False):
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.ThreadingTCPServer(("0.0.0.0", port), Handler)
    httpd.is_public = public   # the Handler gates every request when this is set
    if public:
        print(f"[*] Public (restricted) endpoint at http://localhost:{port}")
    else:
        print(f"[*] Dashboard at http://localhost:{port}")
    httpd.serve_forever()


def _maybe_start_public_server():
    """Start the restricted public server if it's enabled and has a token set.
    Refuses to start without a token, so it can never come up unprotected."""
    pub = get_config().get("public", {})
    if not pub.get("enabled"):
        return
    if not (pub.get("token") or "").strip():
        print("[!] Public endpoint is enabled but has no token set; not starting it.")
        return
    try:
        pport = int(pub.get("port") or 9596)
    except Exception:
        pport = 9596
    threading.Thread(target=run_server, args=(pport, True), daemon=True).start()


# HTML lives in webpage.html, embedded at build time. Fallback inline below.
PAGE = ""


def _make_tray_image():
    """Build the watchtower tray icon. Reuses icon.ico if present, else draws it."""
    from PIL import Image, ImageDraw
    # Prefer the bundled/generated icon so the tray matches the exe icon exactly.
    base_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    for cand in (os.path.join(base_dir, "icon.ico"),
                 os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")):
        if os.path.exists(cand):
            try:
                im = Image.open(cand)
                im.size = (64, 64)
                im.load()
                return im.convert("RGBA")
            except Exception:
                pass
    # Fallback: draw the watchtower (same geometry as make_icon.py).
    s = 64
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    gold = (229, 160, 13, 255)
    dark = (21, 23, 25, 255)
    def vb(x, y):
        return (x / 24.0 * s, y / 24.0 * s)
    d.rounded_rectangle([2, 2, 62, 62], radius=14, fill=gold)
    d.polygon([vb(12, 3.2), vb(16.2, 7.2), vb(7.8, 7.2)], fill=dark)         # roof
    d.polygon([vb(9, 8), vb(15, 8), vb(14.5, 19), vb(9.5, 19)], fill=dark)   # body
    d.rounded_rectangle([*vb(7.6, 18.4), *vb(16.4, 20.6)], radius=2, fill=dark)  # base
    d.line([vb(12, 11), vb(12, 14.5)], fill=gold, width=2)                   # watch slit
    return img


def run_tray(port):
    """Run with a system-tray icon (no console). Falls back to console if pystray missing."""
    try:
        import pystray
    except Exception:
        return False  # not available; caller falls back to console mode

    import webbrowser

    def on_open(icon, item):
        webbrowser.open(f"http://localhost:{port}")

    def on_quit(icon, item):
        icon.stop()
        os._exit(0)

    menu = pystray.Menu(
        pystray.MenuItem("Open GuardTowarr", on_open, default=True),
        pystray.MenuItem("Quit", on_quit),
    )
    icon = pystray.Icon("GuardTowarr", _make_tray_image(), "GuardTowarr", menu)
    icon.run()  # blocks on the main thread
    return True


def _read_json(path, fallback):
    try:
        with open(path, encoding="utf-8") as f:
            value = json.load(f)
        return value if isinstance(value, type(fallback)) else copy.deepcopy(fallback)
    except (OSError, ValueError):
        return copy.deepcopy(fallback)


OBSERVATION_FILE = os.path.join(DATA_DIR, "observations.json")
OBSERVATION_LOCK = threading.Lock()
_OBS_LAST = {}
ACTION_FILE = os.path.join(DATA_DIR, "actions.json")
ACTION_LOCK = threading.Lock()
_ACTION_RUNNING = set()


def record_observations(results, interval):
    now = time.time()
    cutoff = now - 30 * 86400
    with OBSERVATION_LOCK:
        data = _read_json(OBSERVATION_FILE, {})
        for name, result in results.items():
            periods = data.setdefault(name, [])
            previous = _OBS_LAST.get(name)
            if previous and 0 < now - previous[0] <= max(120, interval * 3):
                start, healthy = previous
                if periods and periods[-1][1] == start and periods[-1][2] == healthy:
                    periods[-1][1] = now
                else:
                    periods.append([start, now, healthy])
            _OBS_LAST[name] = (now, result.get("level") == "ok")
        for name in list(_OBS_LAST):
            if name not in results:
                _OBS_LAST.pop(name, None)
        data = {name: [r for r in rows if r[1] > cutoff] for name, rows in data.items()}
        atomic_json(OBSERVATION_FILE, data)


def resolve_media_service(cfg, kind, service=None):
    spec = MEDIA_KINDS.get(kind)
    if not spec:
        return None
    choices = [n for n, s in active_instances(cfg, (spec["service"],)) if s.get("api_key") and s.get("url")]
    if service:
        return service if service in choices else None
    return choices[0] if len(choices) == 1 else None


def duration_seconds(value):
    try:
        parts = [float(v) for v in str(value).split(":")]
        return int(sum(v * 60 ** i for i, v in enumerate(reversed(parts))))
    except (ValueError, TypeError):
        return 0


def arr_queue_records(svc):
    rows = []
    for page in range(1, 101):
        query = urllib.parse.urlencode({"page": page, "pageSize": 200,
                                       "includeUnknownMovieItems": "true", "includeUnknownSeriesItems": "true"})
        _, body = http_get(svc["url"].rstrip("/") + "/api/v3/queue?" + query, {"X-Api-Key": svc["api_key"]})
        data = json.loads(body)
        rows.extend(data["records"])
        if len(rows) >= data.get("totalRecords", len(rows)):
            return rows
    raise ValueError("Queue exceeds supported pagination limit")


def execute_action(cfg, service, action, params, automatic=False):
    svc = cfg.get("services", {}).get(service)
    allowed = {"arr": {"test_download_clients", "test_indexers", "queue_fix"},
               "qbit": {"qbit_recheck", "qbit_reannounce"}}
    if not svc or svc.get("disabled") or not svc.get("enabled", True):
        return {"ok": False, "error": "Service is disabled or missing."}
    if action not in allowed.get(svc.get("type"), set()) or not isinstance(params, dict):
        return {"ok": False, "error": "Action is not supported by this service."}
    key = (service, action, json.dumps(params, sort_keys=True))
    event = {"id": str(time.time_ns()), "ts": time.time(), "service": service,
             "action": action, "automatic": automatic, "status": "pending"}
    with ACTION_LOCK:
        if key in _ACTION_RUNNING:
            return {"ok": False, "error": "This action is already running."}
        events = _read_json(ACTION_FILE, [])[-199:]
        events.append(event)
        atomic_json(ACTION_FILE, events)
        _ACTION_RUNNING.add(key)
    try:
        result = ACTIONS[action](service, svc, params)
    except Exception as e:
        result = {"ok": False, "error": str(e)}
    try:
        with ACTION_LOCK:
            events = _read_json(ACTION_FILE, [])
            for entry in events:
                if entry.get("id") == event["id"]:
                    entry.update(status="succeeded" if result.get("ok") else "partial" if result.get("partial") else "failed",
                                 message=result.get("message") or result.get("error"), finished_at=time.time())
            atomic_json(ACTION_FILE, events)
    except OSError:
        # The upstream action has already happened. Keep its actual outcome and
        # warn about the pending audit entry instead of encouraging a retry.
        field = "message" if result.get("ok") else "error"
        result[field] = (result.get(field) or "Action completed.") + " Action history could not be updated; verify the upstream state before retrying."
    finally:
        with ACTION_LOCK:
            _ACTION_RUNNING.discard(key)
    if result.get("ok") or result.get("partial"):
        REFRESH_NOW.set()
    return result


def public_payload(value, cfg):
    """Scrub every response, including history, action errors, and upstream text."""
    secrets = set()
    hosts = set()
    def gather(obj):
        if isinstance(obj, dict):
            for key, val in obj.items():
                if isinstance(val, str):
                    if any(k in key for k in ("password", "token", "api_key", "webhook", "username")) and val:
                        secrets.add(val)
                    if key == "url":
                        host = urllib.parse.urlsplit(val).hostname
                        if host:
                            hosts.add(host)
                gather(val)
        elif isinstance(obj, list):
            for item in obj:
                gather(item)
    gather(cfg)
    safe_docs = {"wiki.servarr.com", "support.plex.tv", "jellyfin.org", "docs.docker.com",
                 "sabnzbd.org", "nzbget.com", "cleanuparr.github.io", "tunarr.com", "docs.ombi.app",
                 "docs.jellyseerr.dev", "github.com"}
    def clean(obj, key=""):
        if isinstance(obj, dict):
            return {k: clean(v, k) for k, v in obj.items()
                    if k not in ("api_key", "password", "token", "username", "thumb", "sound_url")}
        if isinstance(obj, list):
            return [clean(v, key) for v in obj]
        if not isinstance(obj, str):
            return obj
        if key in ("url", "path", "host", "rootFolderPath", "poster"):
            return ""
        if key == "fix":
            parsed = urllib.parse.urlsplit(obj)
            if parsed.scheme not in ("http", "https") or parsed.hostname not in safe_docs or parsed.username:
                return ""
            return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", parsed.fragment))
        for secret in sorted(secrets | hosts, key=len, reverse=True):
            obj = obj.replace(secret, "[private]")
            obj = obj.replace(urllib.parse.quote(secret, safe=""), "[private]")
        obj = re.sub(r'https?://[^\s<>"\x27]+', '[private URL]', obj)
        obj = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', '[private address]', obj)
        obj = re.sub(r'(?i)\b[a-z]:[\\/][^\s<>"\x27]*', '[private path]', obj)
        obj = re.sub(r'\\\\[^\s]+', '[private path]', obj)
        obj = re.sub(r'\b[\w.-]+\.(?:local|lan|internal)\b', '[private host]', obj, flags=re.I)
        obj = re.sub(r'\[?[a-fA-F0-9]*:[a-fA-F0-9:]*:[a-fA-F0-9:]+\]?', '[private address]', obj)
        obj = re.sub(r'(?<!\w)/(?:[^\s/]+/)+[^\s]*', '[private path]', obj)
        return obj
    return clean(copy.deepcopy(value))


def validate_config(cfg):
    if not isinstance(cfg, dict) or not isinstance(cfg.get("services"), dict):
        raise ValueError("Configuration must contain a services object.")
    if len(cfg["services"]) > 100:
        raise ValueError("At most 100 service instances are supported.")
    for name, svc in cfg["services"].items():
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name) or not isinstance(svc, dict):
            raise ValueError("Invalid service instance.")
        app = service_app(name, svc)
        template = DEFAULT_CONFIG["services"].get(app)
        if not template or svc.get("type", template["type"]) != template["type"]:
            raise ValueError("Unknown service application or mismatched type.")
        for field in ("url", "label", "api_key", "token", "username", "password", "containers"):
            if field in svc and not isinstance(svc[field], str):
                raise ValueError(f"{name}: {field} must be text.")
        url = svc.get("url", "")
        scheme = urllib.parse.urlsplit(url).scheme
        if url and scheme not in (("http", "https", "unix") if template["type"] == "docker" else ("http", "https")):
            raise ValueError(f"{name}: enter an HTTP(S) service URL.")
    return _merge_defaults(cfg)


def main():
    global PAGE
    cfg = load_config()
    with CONFIG_LOCK:
        CONFIG.clear()
        CONFIG.update(cfg)
    save_config(get_config())  # write back any merged defaults
    # load embedded page (PyInstaller unpacks bundled data into sys._MEIPASS)
    base_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    page_path = os.path.join(base_dir, "webpage.html")
    if os.path.exists(page_path):
        with open(page_path, encoding="utf-8") as f:
            PAGE = f.read()
    else:
        PAGE = "<h1>webpage.html missing</h1>"

    # Port precedence: explicit env var (Docker) wins; otherwise the in-app setting.
    if os.environ.get("GUARDTOWARR_PORT"):
        port = PORT
    else:
        port = int(cfg.get("port", PORT) or PORT)
    # poller in the background
    threading.Thread(target=poll_loop, daemon=True).start()
    # optional restricted public server (reverse-proxy target), if enabled + token set
    _maybe_start_public_server()

    # In Docker (or any headless/server context) run the web server in the foreground
    # with no tray. The GUARDTOWARR_DOCKER env var forces this explicitly.
    in_docker = os.environ.get("GUARDTOWARR_DOCKER", "").strip() not in ("", "0", "false", "False")
    if in_docker:
        print(f"[*] GuardTowarr running (container mode) on port {port}")
        try:
            run_server(port)
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
        return

    # web server in the background so the tray icon can own the main thread
    threading.Thread(target=run_server, args=(port,), daemon=True).start()
    # If a tray icon is available (pystray installed), run in the background with it.
    # Otherwise stay in the console foreground as before.
    if run_tray(port):
        return
    print(f"[*] Running in console mode (system tray unavailable).")
    print(f"[*] Open http://localhost:{port} (press Ctrl+C to stop).")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")


if __name__ == "__main__":
    main()
