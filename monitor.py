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
import hashlib
import hmac
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
CURRENT_VERSION = "v1.4.1"
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
        "pushover_user": ""           # Pushover user (or group) key
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
CONFIG_LOCK = threading.Lock()
CONFIG = {}

# shared state, written by poller, read by webserver
STATE_LOCK = threading.Lock()
STATE = {"last_poll": None, "services": {}}


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
        svc.setdefault("enabled", True)
        svc.setdefault("disabled", False)
        svc.setdefault("hidden", False)
    return cfg


def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"[*] Created {CONFIG_FILE}.")
    # Read and merge. If the file is empty, corrupt, or not valid JSON (which can
    # happen with a hand-edited or half-written mounted config), don't crash --
    # fall back to defaults via _merge_defaults, which tolerates a non-dict input.
    try:
        with open(CONFIG_FILE) as f:
            raw = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print(f"[!] {CONFIG_FILE} was empty or invalid JSON; starting from defaults.")
        raw = {}
    except Exception as e:
        print(f"[!] Couldn't read {CONFIG_FILE} ({e}); starting from defaults.")
        raw = {}
    return _merge_defaults(raw)


def save_config(cfg):
    with CONFIG_LOCK:
        with open(CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=2)


def get_config():
    with CONFIG_LOCK:
        return json.loads(json.dumps(CONFIG))  # deep copy for safe reads


def missing_credentials(svc):
    """Return list of required fields that are blank for an enabled service."""
    req = REQUIRED_FIELDS.get(svc.get("type"), [])
    return [f for f in req if not str(svc.get(f, "")).strip()]


def http_get(url, headers=None, timeout=10, auth_cookie=None):
    req = urllib.request.Request(url, headers=headers or {})
    if auth_cookie:
        req.add_header("Cookie", auth_cookie)
    with urllib.request.urlopen(req, timeout=timeout) as r:
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
    api = "v1" if name in ("prowlarr", "readarr", "lidarr") else "v3"
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
        with urllib.request.urlopen(req, timeout=10) as r:
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
                seen_hashes.add(h)
            is_stalled = (st == "stalledDL")
            held = _stall_held(_QBIT_STALL_SINCE, h, is_stalled)
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
            if k not in seen_hashes:
                del _QBIT_STALL_SINCE[k]
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
            entry = {"enabled": True, "disabled": True, "hidden": False,
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
    with urllib.request.urlopen(req, timeout=timeout) as r:
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


def media_search(cfg, kind, term):
    """Search a media service for something to add. Which service and endpoint
    to use comes from MEDIA_KINDS. Only works if that service is set up (has a
    url + api key) and isn't disabled -- otherwise it returns a friendly error
    and the frontend just won't show that option."""
    spec = MEDIA_KINDS.get(kind)
    if not spec:
        return {"ok": False, "error": f"Don't know how to search for '{kind}'."}
    svc_name = spec["service"]
    svc = cfg["services"].get(svc_name, {})
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


def media_profiles(cfg, kind):
    """Return the quality profiles for Radarr (movie) or Sonarr (series)."""
    svc_name = "radarr" if kind == "movie" else "sonarr"
    svc = cfg["services"].get(svc_name, {})
    if svc.get("disabled") or not svc.get("url") or not svc.get("api_key"):
        return {"ok": False, "error": f"{svc_name.title()} is not configured."}
    base = svc["url"].rstrip("/")
    key = svc["api_key"]
    try:
        _, body = http_get(f"{base}/api/v3/qualityprofile", {"X-Api-Key": key})
        profiles = json.loads(body) if body.strip() else []
        default = (cfg.get("default_profiles") or {}).get("movie" if kind == "movie" else "series")
        return {
            "ok": True,
            "profiles": [{"id": p.get("id"), "name": p.get("name", "")} for p in profiles],
            "default": default,
        }
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"ok": False, "error": f"Couldn't load profiles: {e}"}


def media_add(cfg, kind, item, profile_id=None):
    """Add a movie (Radarr) or series (Sonarr). Uses the first root folder; quality
    profile is the chosen profile_id, or the first available if none given."""
    svc_name = "radarr" if kind == "movie" else "sonarr"
    svc = cfg["services"].get(svc_name, {})
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
        root_path = roots[0].get("path", "")
        _, qp_body = http_get(f"{base}/api/v3/qualityprofile", {"X-Api-Key": key})
        profiles = json.loads(qp_body) if qp_body.strip() else []
        if not profiles:
            return {"ok": False, "error": f"No quality profile in {svc_name.title()}."}
        valid_ids = {p.get("id") for p in profiles}
        qid = profile_id if profile_id in valid_ids else profiles[0].get("id", 1)

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
    with urllib.request.urlopen(req, timeout=10) as r:
        cookie = r.headers.get("Set-Cookie", "")
    return base, (cookie.split(";")[0] if cookie else None)


# qBittorrent states grouped into the two tabs
_DOWNLOADING_STATES = {"downloading", "stalledDL", "metaDL", "queuedDL", "forcedDL", "checkingDL", "allocating", "pausedDL"}
_SEEDING_STATES = {"uploading", "stalledUP", "queuedUP", "forcedUP", "checkingUP", "pausedUP"}


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
    """Active torrents. Uses qBittorrent when configured (full data, downloading+seeding);
    otherwise falls back to the Radarr/Sonarr download queue (downloading only)."""
    if _qbit_configured(cfg):
        try:
            return _get_torrents_qbit(cfg)
        except Exception as e:
            # qBit set up but unreachable, so surface the error rather than silently falling back
            return {"ok": False, "error": f"Couldn't load torrents: {e}"}
    # no qBittorrent configured → client-agnostic fallback via the *arr queue
    if cfg["services"].get("radarr", {}).get("api_key") or cfg["services"].get("sonarr", {}).get("api_key"):
        return _get_torrents_arr_queue(cfg)
    return {"ok": False, "error": "Configure qBittorrent, or Radarr/Sonarr, to see downloads."}


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
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def _arr_testall(svc_name, svc, endpoint, label):
    """Shared body for the download-client / indexer 'test all' actions."""
    base = svc.get("url", "").rstrip("/"); key = svc.get("api_key", "")
    if not base or not key:
        return {"ok": False, "error": "Service isn't configured."}
    ver = _arr_api_ver(svc_name)
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
    if not hashes:
        return {"ok": False, "error": "No torrent specified."}
    try:
        base, cookie = _qbit_login(svc)
        if not cookie:
            return {"ok": False, "error": "Couldn't log in to qBittorrent."}
        data = urllib.parse.urlencode({"hashes": "|".join(hashes)}).encode()
        req = urllib.request.Request(f"{base}/api/v2/torrents/{op}", data=data,
                                     headers={"Referer": base, "Cookie": cookie}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
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
    """Remove a stuck/failed Radarr/Sonarr queue item, delete it from the client,
    blocklist the release so it isn't grabbed again, then start a fresh search."""
    base = svc.get("url", "").rstrip("/"); key = svc.get("api_key", "")
    if not base or not key:
        return {"ok": False, "error": "Service isn't configured."}
    qid = params.get("queue_id")
    if not qid:
        return {"ok": False, "error": "No queue item specified."}
    headers = {"X-Api-Key": key, "Content-Type": "application/json"}
    try:
        q = urllib.parse.urlencode({"removeFromClient": "true", "blocklist": "true"})
        _http_request("DELETE", f"{base}/api/v3/queue/{qid}?{q}", headers=headers, timeout=20)
        search_name = params.get("search_name")
        ids_field = params.get("ids_field")
        ids = params.get("ids") or []
        searched = False
        if search_name and ids_field and ids:
            payload = json.dumps({"name": search_name, ids_field: ids}).encode()
            _http_request("POST", f"{base}/api/v3/command", headers=headers, data=payload, timeout=20)
            searched = True
        return {"ok": True, "message": "Removed and blocklisted"
                + (", new search started." if searched else ".")}
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"ok": False, "error": f"Couldn't fix the queue item: {e}"}


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
    """Count how many blocklisted releases each item already has, by reading the
    *arr's own blocklist once. Best-effort: any failure just returns {} so the
    caller falls back to the normal (non-escalated) warning. No local state."""
    wanted = set(i for i in item_ids if i)
    counts = {}
    if not wanted:
        return counts
    plural = {"episodeId": "episodeIds"}.get(id_key)   # Sonarr season packs list episodeIds
    try:
        q = urllib.parse.urlencode({"page": 1, "pageSize": 200,
                                    "sortKey": "date", "sortDirection": "descending"})
        _, body = http_get(f"{base}/api/v3/blocklist?{q}", {"X-Api-Key": key}, timeout=15)
        data = json.loads(body) if body.strip() else {}
        for rec in (data.get("records", []) if isinstance(data, dict) else []):
            for iid in wanted:
                if rec.get(id_key) == iid or (plural and iid in (rec.get(plural) or [])):
                    counts[iid] = counts.get(iid, 0) + 1
    except Exception:
        pass
    return counts


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
    qbit_res = results.get("qbittorrent") or {}
    qbit_by_hash = {}
    for qe in qbit_res.get("errors", []):
        h = (qe.get("hash") or "").lower()
        if h:
            qbit_by_hash[h] = qe
    arr_seen_stalls = set()   # downloadIds currently stalling, for grace-timer pruning

    for name, (search_name, ids_field, id_key) in _QUEUE_ARR.items():
        svc = cfg["services"].get(name, {})
        if svc.get("disabled") or not svc.get("url") or not svc.get("api_key"):
            continue
        res = results.get(name)
        if not res:
            continue
        base = svc["url"].rstrip("/"); key = svc["api_key"]
        try:
            q = urllib.parse.urlencode({"pageSize": 200,
                                        "includeUnknownMovieItems": "true",
                                        "includeUnknownSeriesItems": "true"})
            _, body = http_get(f"{base}/api/v3/queue?{q}", {"X-Api-Key": key}, timeout=15)
            data = json.loads(body) if body.strip() else {}
            records = data.get("records", []) if isinstance(data, dict) else []
        except Exception:
            continue
        # Collect the stuck/failed records first, then fetch the blocklist ONCE
        # (only if there's something stuck) to see how many releases we've already
        # burned per item -- the signal for "you're in a loop".
        stuck = [r for r in records if _queue_is_problem(r)]
        if not stuck:
            continue
        blockcounts = _arr_blocklist_counts(base, key, id_key, [r.get(id_key) for r in stuck])
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
            qe = qbit_by_hash.get(dlid)                      # matching qBit torrent, if any
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
            doc = _ARR_WIKI.get(name, "https://wiki.servarr.com/")

            # Stall grace: a transient connectivity stall still shows, but stays
            # provisional (no alert) until it's been stalled past the grace window.
            # A correlated item (qe set) is governed by the qBit checker's own
            # grace, so only handle the non-correlated case here.
            stalling = (not failed and not manual and
                        (qstate == "stalleddl"
                         or any(w in low for w in ("stalled", "no connection", "no peers"))))
            provisional = False
            if stalling and dlid and qe is None:
                arr_seen_stalls.add(dlid)
                if not _stall_held(_ARR_STALL_SINCE, dlid, True):
                    provisional = True

            # Import-scan grace: "No files found are eligible for import" is usually
            # transient (the *arr is still finishing, or extraction hasn't completed)
            # and clears on the next import pass. Hold off entirely until it has
            # persisted past the grace window, then flag it as a real stuck import.
            if (not failed and not manual and not stalling and dlid
                    and ("eligible for import" in low or "no files found" in low)):
                arr_seen_stalls.add(dlid)   # shares the transient grace timer + pruning
                if not _stall_held(_ARR_STALL_SINCE, dlid, True):
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
                              "destructive": True, "confirm": confirm,
                              "params": {"queue_id": rec.get("id"), "search_name": search_name,
                                         "ids_field": ids_field, "ids": [rec.get(id_key)]}}

            # Gentle client-side fixes, only when we can target the qBit torrent
            # (and not for manual-import, where the torrent isn't the problem).
            gentle = []
            if not manual and qe and dlid:
                gentle = [{"label": "Force re-check", "action": "qbit_recheck",
                           "destructive": False, "params": {"hashes": [dlid]}},
                          {"label": "Re-announce", "action": "qbit_reannounce",
                           "destructive": False, "params": {"hashes": [dlid]}}]

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
    """Scan Radarr/Sonarr torrents for blocked file types. Flags a match as an
    error with a remove+blocklist+re-search action; auto-removes instead when
    malware_autoremove is on (capped by the blocklist loop guard)."""
    svcs = cfg["services"]
    qbit = svcs.get("qbittorrent", {})
    if qbit.get("disabled") or not qbit.get("url") or not qbit.get("username"):
        return   # need qBittorrent to read file lists
    beta = cfg.get("beta", {})
    exts = []
    for e in beta.get("malware_extensions", _DEFAULT_BLOCKED_EXTS):
        e = str(e).strip().lower().lstrip(".")
        if e:
            exts.append("." + e)
    if not exts:
        return
    autoremove = bool(beta.get("malware_autoremove"))
    try:
        base, cookie = _qbit_login(qbit)
        if not cookie:
            return
        _, body = http_get(f"{base}/api/v2/torrents/info", auth_cookie=cookie)
        qhashes = {(t.get("hash") or "").lower() for t in (json.loads(body) if body.strip() else [])}
    except Exception:
        return

    seen = set()
    for name, (search_name, ids_field, id_key) in _QUEUE_ARR.items():
        svc = svcs.get(name, {})
        if svc.get("disabled") or not svc.get("url") or not svc.get("api_key"):
            continue
        res = results.get(name)
        if not res:
            continue
        base_arr = svc["url"].rstrip("/"); key = svc["api_key"]
        try:
            q = urllib.parse.urlencode({"pageSize": 200, "includeUnknownMovieItems": "true",
                                        "includeUnknownSeriesItems": "true"})
            _, body = http_get(f"{base_arr}/api/v3/queue?{q}", {"X-Api-Key": key}, timeout=15)
            records = (json.loads(body) if body.strip() else {}).get("records", [])
        except Exception:
            continue
        for rec in records:
            dlid = (rec.get("downloadId") or "").lower()
            if not dlid or dlid not in qhashes:
                continue   # only torrents qBittorrent actually holds
            seen.add(dlid)
            found = _MALWARE_SCANNED.get(dlid)
            if found is None:
                found = _qbit_scan_files(base, cookie, dlid, exts)
                if found is None:
                    continue   # no metadata yet; try again next poll
                _MALWARE_SCANNED[dlid] = found
            if not found:
                continue   # clean

            title = (rec.get("title") or "Unknown release")[:80]
            badlist = ", ".join(found[:3])
            item_id = rec.get(id_key)
            can_fix = bool(rec.get("id") and item_id)

            # auto-remove (opt-in), but stop if we've already burned through several
            # releases for this item, to avoid an endless remove/re-search loop
            looping = False
            if autoremove and can_fix:
                cnt = _arr_blocklist_counts(base_arr, key, id_key, [item_id]).get(item_id, 0)
                looping = cnt >= _LOOP_BLOCKLIST_THRESHOLD

            if autoremove and can_fix and not looping:
                action_queue_fix(name, svc, {"queue_id": rec.get("id"), "search_name": search_name,
                                             "ids_field": ids_field, "ids": [item_id]})
                _MALWARE_SCANNED.pop(dlid, None)
                iss = _issue("warning", title,
                             f"Blocked file type ({badlist}) found; removed, blocklisted, and searching for a clean release."[:300], "")
            else:
                msg = f"Blocked file type in download: {badlist}. Likely a fake or malware release."
                if looping:
                    msg += " Auto-remove paused after repeated bad releases; remove manually if you're sure."
                iss = _issue("error", title, msg[:300], "")
                if can_fix:
                    iss["actions"] = [{
                        "label": "Remove + blocklist + re-search", "action": "queue_fix", "destructive": True,
                        "confirm": (f"This download contains a blocked file type ({badlist}), which usually "
                                    "means a fake or malware release. Remove it, blocklist it, and search "
                                    "for a clean one?"),
                        "params": {"queue_id": rec.get("id"), "search_name": search_name,
                                   "ids_field": ids_field, "ids": [item_id]},
                    }]
            iss["id"] = _issue_id(name, iss)
            iss["service"] = name
            res.setdefault("errors", []).append(iss)
            lvl = iss["level"]
            if lvl == "error" and res.get("level") != "error":
                res["level"] = "error"
            elif lvl == "warning" and res.get("level") == "ok":
                res["level"] = "warning"

    for h in list(_MALWARE_SCANNED):   # forget torrents that are gone
        if h not in seen:
            del _MALWARE_SCANNED[h]


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
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ct = r.headers.get("Content-Type", "image/jpeg")
            data = r.read()
            if data and ct.startswith("image"):
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
    """The unified now-playing stream list, in the same stable order get_stats
    uses (Plex first, then Jellyfin). Centralized so /api/poster indexes into
    exactly the same list the dashboard shows."""
    svcs = cfg["services"]
    streams = []
    if not svcs.get("plex", {}).get("disabled"):
        ps = _plex_sessions(svcs.get("plex", {}))
        if ps: streams.extend(ps.get("streams", []))
    if not svcs.get("jellyfin", {}).get("disabled"):
        js = _jellyfin_sessions(svcs.get("jellyfin", {}))
        if js: streams.extend(js.get("streams", []))
    return streams


def get_poster(cfg, idx):
    """Resolve a poster image for now-playing stream #idx (index into the
    combined Plex+Jellyfin list). Tries the Plex thumb first (server-side, with
    token), then falls back to a Radarr/Sonarr poster lookup by title. Jellyfin
    streams have no thumb, so they go straight to the arr fallback.
    Returns (bytes, content_type) or (None, None)."""
    streams = _combined_now_playing(cfg)
    if idx >= len(streams):
        return None, None
    s = streams[idx]

    # 1) Plex thumbnail (only Plex streams carry one), proxied server-side so the
    # token never reaches the browser
    thumb = s.get("thumb")
    plex = cfg["services"].get("plex", {})
    token = plex.get("token", "")
    if thumb and token and s.get("source") == "Plex":
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
    """30-day uptime % per service, derived from the history log."""
    events = _prune_history(load_history())
    # crude but reasonable: % of logged transitions that are 'recover' vs 'down'
    # better: time-weighted, but keep it light. Use down-count to estimate.
    now = datetime.now().timestamp()
    span = 30 * 86400
    per = {}
    # build down intervals per service
    by_svc = {}
    for e in events:
        by_svc.setdefault(e["service"], []).append(e)
    for svc, evs in by_svc.items():
        evs.sort(key=lambda e: e["ts"])
        downtime = 0.0
        down_since = None
        for e in evs:
            if e["kind"] == "down" and down_since is None:
                down_since = e["ts"]
            elif e["kind"] == "recover" and down_since is not None:
                downtime += e["ts"] - down_since
                down_since = None
        if down_since is not None:
            downtime += now - down_since
        pct = max(0.0, min(100.0, (1 - downtime / span) * 100))
        per[svc] = round(pct, 2)
    return per


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
    svcs = cfg["services"]
    out = {"ok": True}

    # Lite stats mode (beta): serve only the data we already have locally: the
    # 30-day uptime/downtime figures (from history.json) and the in-memory stream
    # graph, and skip every upstream fan-out (library counts, now-playing,
    # storage). This caps the server cost of an open dashboard. It touches ONLY
    # the stats panel: health checks, warnings/errors, history and notifications
    # all run in the poll loop and are completely unaffected.
    if cfg.get("beta", {}).get("lite_stats"):
        out["lite"] = True
        out["uptime"] = uptime_percentages()
        # No stream history in lite mode: nothing records stream counts while it's
        # on, so the "streams · last 24h" graph would just show stale data. Omit it
        # so the frontend hides the graph entirely.
        return out

    plex_svc = svcs.get("plex", {})
    jelly_svc = svcs.get("jellyfin", {})
    radarr_svc = svcs.get("radarr", {})
    sonarr_svc = svcs.get("sonarr", {})

    radarr_on = not radarr_svc.get("disabled")
    sonarr_on = not sonarr_svc.get("disabled")
    # Media servers expose cheap library totals (Plex via totalSize headers,
    # Jellyfin via /Items/Counts), so prefer them for the headline movie/episode
    # counts. The traditional *arr count fetches the WHOLE /movie and /series
    # arrays just to measure length, so we only fall back to it when neither
    # media server is configured to answer.
    plex_active = bool((not plex_svc.get("disabled")) and plex_svc.get("token"))
    jelly_active = bool((not jelly_svc.get("disabled")) and jelly_svc.get("api_key"))
    have_media_server = plex_active or jelly_active
    both_servers = plex_active and jelly_active

    # Fan out every independent network call at once. Each underlying helper
    # already swallows its own errors (returns None/[] on failure), so a single
    # slow or unreachable service degrades to an empty panel rather than blocking
    # or crashing the whole stats response.
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        # headline library counts: cheap media-server totals when available,
        # otherwise (and only otherwise) the expensive full-array *arr grab.
        if plex_active:
            tasks["plex_lib"] = ex.submit(_plex_library_counts, plex_svc)
        if jelly_active:
            tasks["jelly_lib"] = ex.submit(_jellyfin_library_counts, jelly_svc)
        if not have_media_server:
            if radarr_on:
                tasks["arr_movies"] = ex.submit(_arr_count, radarr_svc, "movie")
            if sonarr_on:
                tasks["arr_episodes"] = ex.submit(_arr_count, sonarr_svc, "series")
        # storage still comes from the *arr diskspace endpoint regardless
        if radarr_on:
            tasks["radarr_disk"] = ex.submit(_arr_diskspace, radarr_svc)
        if sonarr_on:
            tasks["sonarr_disk"] = ex.submit(_arr_diskspace, sonarr_svc)
        tasks["torrents"] = ex.submit(get_torrents, cfg)
        # now-playing: gate on disabled only (matches _combined_now_playing, which
        # /api/poster indexes into, so keep this in lockstep so poster indices line up)
        if not plex_svc.get("disabled"):
            tasks["plex_np"] = ex.submit(_plex_sessions, plex_svc)
        if not jelly_svc.get("disabled"):
            tasks["jelly_np"] = ex.submit(_jellyfin_sessions, jelly_svc)
        # disk-based (no network) but cheap to run alongside the rest
        tasks["uptime"] = ex.submit(uptime_percentages)

    def _res(key, default=None):
        f = tasks.get(key)
        if f is None:
            return default
        try:
            return f.result()
        except Exception:
            return default

    # ---- headline movie / episode totals ----
    pc = _res("plex_lib")
    jc = _res("jelly_lib")
    if pc is not None or jc is not None:
        # Plex and Jellyfin almost always mirror the same underlying library, so
        # the larger of the two IS the true total, so take the max per metric
        # rather than summing, which would double-count shared titles. (e.g. Plex
        # 257 / Jellyfin 248 movies -> 257, not 505.)
        def _bigger(metric):
            vals = [c.get(metric) for c in (pc, jc)
                    if isinstance(c, dict) and c.get(metric) is not None]
            return max(vals) if vals else None
        m, e = _bigger("movies"), _bigger("episodes")
        if m is not None: out["movies"] = m
        if e is not None: out["episodes"] = e
    else:
        # no media server configured -> fall back to the *arr counts (canonical
        # "what you own"). Key present (possibly None) whenever the app is on.
        if "arr_movies" in tasks:
            out["movies"] = _res("arr_movies")
        if "arr_episodes" in tasks:
            out["episodes"] = _res("arr_episodes")

    # When BOTH media servers are active, also break the library out per server
    # so the dashboard can show each one next to the (max) headline total.
    if both_servers:
        per_server = []
        if pc is not None: per_server.append({"server": "Plex", **pc})
        if jc is not None: per_server.append({"server": "Jellyfin", **jc})
        if per_server:
            out["library_by_server"] = per_server

    t = _res("torrents")
    if isinstance(t, dict) and t.get("ok"):
        out["torrents"] = len(t.get("downloading", [])) + len(t.get("seeding", []))

    # per-drive storage: merge diskspace from radarr+sonarr, dedupe by path
    # (radarr first, so its entry wins on a shared path; order preserved)
    drives = {}
    for key in ("radarr_disk", "sonarr_disk"):
        for d in (_res(key) or []):
            dkey = d["path"] or d["label"]
            if dkey not in drives:
                drives[dkey] = d
    out["drives"] = sorted(drives.values(), key=lambda d: d["pct"], reverse=True)

    # plex / jellyfin now-playing. Build ONE combined stream list from every
    # enabled media server (capability "stats") so the view works with Plex,
    # Jellyfin, both, or neither. Keep this order stable (Plex first, then
    # Jellyfin) to match the list /api/poster indexes into.
    np_sources = []   # (label, sessions-dict)
    ps = _res("plex_np")
    if ps is not None:
        np_sources.append(("Plex", ps))
    js = _res("jelly_np")
    if js is not None:
        np_sources.append(("Jellyfin", js))

    if np_sources:
        combined = []
        for _, sess in np_sources:
            combined.extend(sess.get("streams", []))
        transcoding = sum(1 for s in combined if s.get("mode") == "transcode")
        out["now_playing"] = {
            "count": len(combined),
            "streams": combined,
            "transcoding": transcoding,
            "direct": len(combined) - transcoding,
            # which servers contributed, so the UI can label a combined view
            "sources": [label for label, _ in np_sources],
        }
        _record_stream_count(len(combined))
        # keep the old single-source "plex" key populated when Plex is the only
        # source, so nothing that still reads it breaks.
        if [l for l, _ in np_sources] == ["Plex"]:
            out["plex"] = np_sources[0][1]

    # uptime % + stream history graph
    out["uptime"] = _res("uptime") or {}
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
    r, l = _parse_version(remote), _parse_version(local)
    # pad to equal length
    n = max(len(r), len(l))
    r = r + (0,) * (n - len(r))
    l = l + (0,) * (n - len(l))
    return r > l


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
        with urllib.request.urlopen(req, timeout=10) as r:
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
        with open(DISMISS_FILE, "w") as f:
            json.dump(d, f, indent=2)


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
    cutoff = (datetime.now() - timedelta(days=HISTORY_RETENTION_DAYS)).timestamp()
    return [e for e in events if e.get("ts", 0) >= cutoff]


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
        with open(HISTORY_FILE, "w") as f:
            json.dump(events, f, indent=2)


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
        with urllib.request.urlopen(req, timeout=10) as r:
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
        with urllib.request.urlopen(req, timeout=10) as r:
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
        with urllib.request.urlopen(req, timeout=10) as r:
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


def send_alert(notif, title, message, priority="default", tags="", level="info", fix_url=""):
    """Fan out a single alert to every enabled channel (ntfy, Discord, Pushover).
    Returns (ok, error) where ok is True if at least one channel accepted it."""
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
    if not results:
        return False, "No notification channel configured."
    ok = any(r[0] for r in results)
    err = next((r[1] for r in results if not r[0]), None)
    return ok, (None if ok else err)


def any_channel_ready(notif):
    """True if at least one delivery channel is configured (ntfy topic, Discord webhook, or Pushover keys)."""
    has_ntfy = bool(notif.get("ntfy_enabled", True) and (notif.get("topic") or "").strip())
    has_discord = bool(notif.get("discord_enabled") and (notif.get("discord_webhook") or "").strip())
    has_pushover = bool(notif.get("pushover_enabled") and (notif.get("pushover_token") or "").strip() and (notif.get("pushover_user") or "").strip())
    return has_ntfy or has_discord or has_pushover


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
    """Map a download name -> clean 'Title (year)' using the Radarr/Sonarr queues.
    Cheap: only called when a torrent actually completes."""
    titles = {}
    for sname, kind in (("radarr", "movie"), ("sonarr", "series")):
        svc = cfg["services"].get(sname, {})
        if svc.get("disabled") or not svc.get("url") or not svc.get("api_key"):
            continue
        base = svc["url"].rstrip("/"); key = svc["api_key"]
        try:
            q = urllib.parse.urlencode({"pageSize": 200})
            _, body = http_get(f"{base}/api/v3/queue?{q}", {"X-Api-Key": key}, timeout=12)
            data = json.loads(body) if body.strip() else {}
            for r in data.get("records", []):
                dl = (r.get("downloadId") or "").lower()       # qBittorrent hash
                title = r.get("title", "")
                if dl and title:
                    titles[dl] = title
        except Exception:
            continue
    return titles


def check_torrent_completions(cfg):
    """Detect torrents that just finished downloading and notify (respecting quiet hours)."""
    global _TORRENT_DONE_SEEDED
    notif = cfg.get("notifications", {})
    if not notif.get("enabled") or not notif.get("torrent_done"):
        return
    if not any_channel_ready(notif):
        return
    qbit = cfg["services"].get("qbittorrent", {})
    if qbit.get("disabled") or not qbit.get("url") or not qbit.get("username"):
        return

    try:
        base, cookie = _qbit_login(qbit)
        _, body = http_get(f"{base}/api/v2/torrents/info", auth_cookie=cookie)
        torrents = json.loads(body) if body.strip() else []
    except Exception:
        return

    newly_done = []
    seen = set()
    for t in torrents:
        h = t.get("hash", "")
        if not h:
            continue
        seen.add(h)
        done = (t.get("progress", 0) or 0) >= 1.0
        was = _TORRENT_DONE_STATE.get(h)
        _TORRENT_DONE_STATE[h] = done
        # fire only on a transition from not-done to done (skip the first seed pass)
        if done and was is False:
            newly_done.append(t)
    # drop torrents that disappeared
    for h in list(_TORRENT_DONE_STATE.keys()):
        if h not in seen:
            del _TORRENT_DONE_STATE[h]

    if not _TORRENT_DONE_SEEDED:
        _TORRENT_DONE_SEEDED = True
        return  # first run just establishes the baseline; don't alert on existing torrents

    if not newly_done:
        return

    # look up clean titles only when something actually finished
    titles = _arr_queue_titles(cfg) if newly_done else {}
    quiet = in_quiet_hours(notif)
    for t in newly_done:
        h = t.get("hash", "").lower()
        clean = titles.get(h) or t.get("name", "Download")
        msg = f"{clean} finished downloading"
        if quiet:
            _QUIET_QUEUE.append({"service": "qbittorrent", "kind": "torrent", "summary": msg})
        else:
            send_alert(notif, "Download complete", msg, priority="default", tags="white_check_mark", level="ok")


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


def run_poll_once():
    cfg = get_config()
    results = {}
    for name, svc in cfg["services"].items():
        # skip services the user turned off (disabled) entirely
        if svc.get("disabled", False):
            continue
        # skip services not enabled for monitoring
        if not svc.get("enabled", True):
            continue
        checker = CHECKERS.get(svc.get("type"))
        if not checker:
            continue
        try:
            results[name] = checker(name, svc)
        except Exception as e:
            results[name] = svc_result(name, "error", f"Check crashed: {e}", [])
    # Stuck-queue detection is part of the remediation feature: only scan the
    # *arr queues when it's enabled, so turning it off removes the extra calls.
    if cfg.get("beta", {}).get("remediation", True):
        try:
            augment_queue_issues(cfg, results)
        except Exception as e:
            print(f"[queue] error: {e}")
    # Blocked-file scan (beta): flag/auto-remove arr torrents carrying risky file types.
    if cfg.get("beta", {}).get("malware_scan"):
        try:
            scan_blocked_files(cfg, results)
        except Exception as e:
            print(f"[scan] error: {e}")
    with STATE_LOCK:
        STATE["services"] = results
        STATE["last_poll"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        maybe_notify(results)
    except Exception as e:
        print(f"[notify] error: {e}")
    try:
        check_torrent_completions(cfg)
    except Exception as e:
        print(f"[torrent-notify] error: {e}")
    print(f"[{STATE['last_poll']}] polled {len(results)} services")


def poll_loop():
    while True:
        run_poll_once()
        interval = get_config().get("poll_interval", POLL_INTERVAL)
        # wake early if a manual refresh is requested
        if REFRESH_NOW.wait(timeout=max(5, interval)):
            REFRESH_NOW.clear()


# ----------------------------------------------------------------------------
# WEB SERVER
# ----------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):

    # Endpoints the restricted public port is allowed to serve (everything else
    # is 404'd there). Admin/credential/destructive routes are deliberately absent.
    _PUBLIC_GET = {"/api/status", "/api/stats", "/api/history", "/api/update"}
    _PUBLIC_POST = {"/api/search", "/api/profiles", "/api/add", "/api/action", "/api/torrents"}

    def log_message(self, *a):
        pass  # quiet

    def _json(self, obj, code=200):
        payload = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode())
        except Exception:
            return {}

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
        return bool(supplied) and hmac.compare_digest(str(supplied), str(token))

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

    def do_GET(self):
        if self._is_public() and not self._public_get_ok():
            return
        if self.path == "/api/status":
            with STATE_LOCK:
                state = json.loads(json.dumps(STATE))
            state["dismissed"] = load_dismissed()
            cfg = get_config()
            # surface display-relevant flags + onboarding needs
            svc_meta = {}
            onboarding = []
            for name, svc in cfg["services"].items():
                miss = [] if svc.get("disabled") else missing_credentials(svc)
                svc_meta[name] = {
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
                s = cfg["services"].get(spec["service"], {})
                ready = (not s.get("disabled")) and s.get("url") and s.get("api_key")
                if ready and _can_search(spec["service"]):
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
            self._json({"ok": True, "uptime": uptime_percentages(), **history_summary()})

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
                self.send_header("Cache-Control", "max-age=300")
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
            self.end_headers()
            self.wfile.write(page.encode())

    def do_POST(self):
        body = self._read_body()

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
            new_cfg = _merge_defaults(new_cfg)
            with CONFIG_LOCK:
                CONFIG.clear()
                CONFIG.update(new_cfg)
            with _STATS_LOCK:
                _STATS_CACHE["ts"] = 0.0  # force a fresh stats compute (e.g. lite_stats toggled)
            save_config(get_config())
            REFRESH_NOW.set()  # apply immediately
            return self._json({"ok": True})

        if self.path == "/api/search":
            kind = body.get("kind", "movie")
            term = (body.get("term") or "").strip()
            if not term:
                return self._json({"ok": False, "error": "empty search"}, 400)
            return self._json(media_search(get_config(), kind, term))

        if self.path == "/api/profiles":
            kind = body.get("kind", "movie")
            return self._json(media_profiles(get_config(), kind))

        if self.path == "/api/add":
            kind = body.get("kind", "movie")
            item = body.get("item", {})
            profile_id = body.get("profile_id")
            result = media_add(get_config(), kind, item, profile_id)
            # remember the chosen profile as the default for next time
            if result.get("ok") and profile_id is not None:
                with CONFIG_LOCK:
                    CONFIG.setdefault("default_profiles", {})[kind] = profile_id
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
                result = fn(service, svc, params)
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
