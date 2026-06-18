<div align="center">

# ![image](https://github.com/tonytrawl/GuardTowarr/blob/main/icon-4.png?raw=true) GuardTowarr

**The watchtower for your media stack. It doesn't just tell you what broke, it helps you fix it.**

Monitors **Radarr · Sonarr · Prowlarr · Readarr · Lidarr · Plex · Jellyfin · qBittorrent · Ombi · Seerr  · Tunarr** in one place.

[![Docker Link](https://img.shields.io/badge/Docker-repo-blue?logo=docker)](https://hub.docker.com/r/tonytrawl/guardtowarr)
[![Download](https://img.shields.io/badge/download-latest%20release-e5a00d)](../../releases/latest)
[![Reddit](https://img.shields.io/badge/Reddit-Reddit?logo=reddit)](https://www.reddit.com/r/guardtowarr/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Buy me a Coffee](https://img.shields.io/badge/Support%20My%20Work-Buy%20me%20a%20coffee%20%E2%98%95-chocolate?style=plastic)](https://buymeacoffee.com/tonytrawl)

<table>
  <!-- First Row of Images -->
  <tr>
    <td align="center" width="50%">
      <img src="https://github.com/tonytrawl/GuardTowarr/blob/main/screenshots/Dashboard%20clear.png?raw=true" alt="" width="100%">
    </td>
     <td align="center" width="50%">
      <img src="https://github.com/tonytrawl/GuardTowarr/blob/main/screenshots/Dashboard%20Error.png?raw=true" alt="" width="100%">
    </td>
  </tr>

  <!-- Second Row of Images -->
  <tr>
     <td align="center" width="35%">
      <img src="https://github.com/tonytrawl/GuardTowarr/blob/main/screenshots/Mobile%20error%20view.png?raw=true" alt="" width="35%">
    </td>
    <td align="center" width="50%">
      <img src="https://github.com/tonytrawl/GuardTowarr/blob/main/screenshots/Quick%20Fix.png?raw=true" alt="" width="100%">
    </td>
  </tr>
</table>

</div>

---

<div align="left">

## Why GuardTowarr?

There are plenty of dashboards that show your services as green or red dots. GuardTowarr is built to do the part that actually saves you time: figure out what's wrong and help you fix it.

- **It diagnoses, it doesn't just ping.** It logs into each app and reads that app's own health, so it catches things that are technically "up" but quietly broken (no indexers, a dead download client, a stalled or failed download, so much more).
- **It fixes, not just reports.** Common problems get one-click actions right on the card: test download clients, re-test indexers, re-check or re-announce a stalled torrent, or remove and re-search a genuinely bad download. Nothing happens on its own; every fix is a button you press.
- **It understands the whole stack, not one app.** The full *arr lineup, Plex and Jellyfin, qBittorrent, the request apps, and Tunarr, all in one screen instead of a tab per tool.
- **It runs off your server on purpose.** Put it on your everyday PC and it can tell you when the server itself goes down, not just when an app does.
- **It's genuinely lightweight.** Two files and the Python standard library. No database, no heavy dependencies.
- **Its alerts respect your time.** Edge-triggered (no spam while something stays down), with quiet hours, a grace period so brief blips stay quiet, and one summary instead of a flood when the whole stack reboots.
- **You can check it from anywhere, safely.** An optional, token-protected remote view that never exposes your credentials or internal addresses.

---

## What is it?

GuardTowarr is a single dashboard for your self-hosted media stack. It watches every service, surfaces the real problems (including downloads stuck in your queue), lets you fix the common ones in place, and pings your phone when something actually breaks.

The whole app is two files: a standard-library Python server (`monitor.py`) and one HTML page (`webpage.html`). State lives in flat JSON files, so there's nothing to install and nothing to maintain. Run it from the Windows build or in Docker.

---

## Install

### Windows

Grab the latest **`GuardTowarr.exe`** from the [**Releases**](../../releases/latest) page. That's it: no install, no dependencies, no Python required. It runs in your system tray.

> **Heads up:** Because the `.exe` isn't code-signed, Windows SmartScreen may warn you on first launch. Click **More info → Run anyway**.

### Docker (compose)

GuardTowarr is on Docker Hub as **`tonytrawl/guardtowarr`**. This is the cross-platform way to run it: anywhere Docker runs, **including Linux servers, NAS devices (Synology / unRAID / etc.), Windows, and macOS**. You do **not** need Windows for the container.

```yaml
services:
  guardtowarr:
    image: tonytrawl/guardtowarr:latest
    container_name: guardtowarr
    ports:
      - "9595:9595"
      # - "9596:9596"   # optional: only if you enable Remote access (see below)
    volumes:
      - ./config:/config
    restart: unless-stopped
```

Then `docker compose up -d` and open `http://<host>:9595`.

> **Note:** if you later add the `9596` line, a `docker compose restart` is not enough to publish a new port. Run `docker compose up -d` to recreate the container.

### Docker Desktop (GUI)

If you pull and run the image from the Docker Desktop app instead of compose:

1. **Images** tab, find `tonytrawl/guardtowarr`, click **Run**.
2. Expand **Optional settings**.
3. **Ports:** set the host port for **9595**. If you plan to use Remote access, also set the host port for **9596**.
4. **Volumes:** map a host folder to **`/config`** so your settings, dismissed issues, and history persist.
5. **Run**, then open `http://localhost:9595`.

> Ports are fixed when a container is created; you can't add one to a running container. If you need to add `9596` later, delete the container and run the image again with both ports mapped (your `/config` volume keeps your settings).

### Networking note (all Docker users)

If your Radarr/Sonarr/Plex/etc. run on the **same machine**, the container **cannot** reach them at `localhost` (inside a container that means the container itself). Either:

- put your host's LAN IP in each service URL, e.g. `http://192.168.1.50:7878`, or
- run with `network_mode: host` (and drop the `ports` block).

The system-tray feature is desktop-only and isn't part of the Docker image; the container just runs in the background like any other service.

---

## Features

### 🩺 Monitoring
- One clean view of every service: **healthy**, **warning**, or **error**.
- Surfaces each app's own internal health, not just whether it's online.
- Checks on a timer (**every 30 seconds by default**, adjustable) with a manual refresh anytime.
- When everything's fine you get a calm **all-clear** screen; the moment something needs attention, only the cards that matter take over.
- **Don't use a service?** Disable it and it disappears from the dashboard and stops being checked.

### 🛠️ Diagnose & Fix
This is the part that sets GuardTowarr apart: it helps you clear the most common *arr headaches without leaving the dashboard.

- **Catches stuck downloads** the basic checks miss: it reads your Radarr/Sonarr queues and flags **stalled torrents, downloads with no seeds, and failed imports**.
- **One-click fixes** appear right on the issue:
  - **Test download clients** and **Re-test indexers** on the matching health warnings.
  - **Force re-check** and **Re-announce** on a stalled qBittorrent torrent.
  - **Remove + blocklist + re-search** for a genuinely bad download.
- **It's smart about which fix to suggest.** It tells a stall (your client, connection, or a lack of seeds) apart from a genuinely bad release, and leads with the right action for each. Mere stalls lead with the gentle fixes; the destructive remove is a clearly-warned last resort.
- **Loop guard.** If you've already blocklisted a pile of releases for the same item and it's *still* failing, it warns you that the releases probably aren't the problem (it's your client or connection), so you don't get stuck in an endless remove-and-research loop.
- **No noise.** It ignores normal pipeline states (like an archive waiting to be extracted), and "manual import required" is flagged for you to handle without a destructive button.
- **Nothing happens on its own.** Every fix is a button you press, and anything that deletes a download asks you to confirm first.
- Lives in the **Stability** tab and can be turned off entirely (which also stops the extra queue checks). Your core up/down monitoring and alerts are unaffected either way.

### 📖 Always linked to the fix
GuardTowarr never leaves you searching for which doc explains an error.

- Every warning and error carries a **direct link to the right documentation**: the matching Servarr wiki page for an *arr health issue, the qBittorrent FAQ for a connection problem, the correct Tunarr config page for an ffmpeg or transcode warning, and so on.
- Links are **matched to the specific problem**, not just dropped on a generic homepage, so one click takes you to the section that actually covers what you're seeing.
- Alerts to your phone include the same link, so you can read up on a fix before you're back at your desk.

### 🧪 Blocked-file scan _(beta)_
An optional check that scans the files inside your Radarr/Sonarr torrents for risky or unwanted extensions (like `.exe` or `.scr` hiding in a release).

- **Off by default**, lives in the **Stability** tab, and the list of blocked extensions is fully editable.
- By default it just **flags** anything it finds with a one-click remove, so you stay in control. There's an opt-in to have it remove and re-search automatically instead.


### 📱 Phone & chat alerts
- Get pinged when something breaks (and again when it recovers) via any mix of **[ntfy](https://ntfy.sh)** (free phone push, no account needed), **Discord** (channel webhook), or **[Pushover](https://pushover.net)**. Turn on one channel or several.
- Only alerts on **real changes**, so no spam while something stays down.
- Choose **errors only** or **warnings too**, and **mute** specific services.
- **Quiet hours** so it won't wake you at 3am; anything overnight arrives as one tidy summary in the morning.
- **No startup floods.** When GuardTowarr or your server restarts, it holds alerts during a short settle window and sends a single summary of whatever is still wrong, instead of blasting you while everything boots.
- **No false alarms on blips.** A torrent that briefly stalls gets a grace period to recover before it alerts you (it still shows on the dashboard right away).
- **Burst summaries.** When several services drop or recover together, you get one summary ("all services except Plex came back, down ~4m"), not a notification per service.
- **Torrent finished alerts** (beta): a ping like "Dune: Part Two finished downloading", using the clean title from Radarr/Sonarr.
- Send a **test notification** to confirm each channel.

### 🔎 Search & add movies, shows, books & music
- Built-in search with **poster previews**.
- Search **movies** (Radarr), **shows** (Sonarr), **books** (Readarr), and **music** (Lidarr).
- Pick something, confirm the **quality profile**, and it's sent to the right app to grab.
- Search options only appear for the apps you've set up and enabled, and it remembers your usual quality profile.
- No extra API keys needed; it reuses the apps you've already connected.

### 📊 History & uptime
- Logs every time a service goes down and recovers, kept for **30 days**.
- Per-service **30-day uptime** with a small inline bar, plus outage counts for the last day, week, and month.
- See real numbers like *"Radarr has gone down 4 times this week"* instead of guessing.

### 📈 Live stats
- When everything's healthy, the all-clear screen shows live stats right below it.
- **Library counts** (movies, episodes), pulled from Plex/Jellyfin when you have them and never double-counted when you run both, plus **active torrents** and **uptime %** at a glance.
- **Now playing on Plex and/or Jellyfin**: who's watching what, direct play vs transcode, with progress and a tag showing which server it's on.
- **Per-drive storage** bars that turn amber then red as a drive fills up, and a 24-hour **streams** graph.
- **Lite stats mode** (in the Stability tab): running everything on a low-power box like a Pi or NAS? Switch the panel to a lightweight uptime-only view to cut background load on your servers. Monitoring, warnings, and alerts are completely unaffected.

### 🌀 Active torrents
- A view of what's **downloading** and **seeding**, switchable between the two.
- Full detail (live speeds, ratio, ETA) if you use **qBittorrent**.
- No qBittorrent? It falls back to the **Radarr/Sonarr download queue**, so it still works with whatever client you use (Transmission, Deluge, etc.).

### 🌐 Remote access (advanced)
Watch your stack (and optionally request content) from outside your network, safely. GuardTowarr can serve a **second, restricted port** designed to sit behind a reverse proxy.

- Shows your live **service status, stats, history, and active torrents** from anywhere. It **never** exposes your API keys, passwords, or internal addresses.
- Protected by a **shared access token** you set, and **off by default**.
- **Monitor-only out of the box.** Two independent opt-in toggles let you also allow **content requests** (search + add) and/or **remediation actions** (the one-click fixes), each off by default.
- See [Remote access setup](#remote-access-setup) below, and read the in-app disclaimer before enabling it.

### 🎨 Customization
- **Light and dark mode**: dark is a clean Plex-style grey, not harsh black.
- **Hide** services from view without fully disabling them.
- **Dismiss** issues you already know about so they stop nagging; restore them anytime.
- **Click any service** to jump straight to its web UI.
- **Keyboard shortcuts**: `/` search · `r` refresh · `s` settings · `h` history.
- Optional **sound + on-screen flash** when something newly breaks.

---

## What gets checked

GuardTowarr doesn't just ping a port. For each service it logs in with your credentials and reads that app's own status and health endpoints, so it catches things that are technically "up" but quietly broken.

| Service | What it watches |
|---|---|
| **Radarr / Sonarr / Prowlarr / Readarr / Lidarr** | Reachability plus the app's own internal health checks (missing root folders, no indexers, download-client problems, update notices, etc.), each linked to the right fix. With **Diagnose & Fix** on, Radarr/Sonarr queues are also watched for stuck and failed downloads. |
| **Plex** | Server reachability, token validity, and whether libraries respond (distinguishes "down" from "up but libraries not responding"). Feeds the live now-playing view. |
| **Jellyfin** _(beta)_ | Server reachability plus API key validity. Also feeds the live now-playing view. |
| **qBittorrent** | Online status, bad-credential detection, and torrents stuck in error / missing-files / stalled states (with a grace period so brief stalls don't cry wolf). |
| **Ombi / Overseerr / Jellyseerr** | Reachability plus API key validity via the status endpoint. |
| **Tunarr** _(beta)_ | Reachability plus Tunarr's own health checks (ffmpeg version, hardware acceleration, transcode directory, etc.), each surfaced as a warning or error with a link to the relevant Tunarr docs page. |

Every service reports one of three states (healthy, warning, or error), with real outages kept separate from minor warnings. Any issue can be dismissed and stays hidden until it recurs.

> **A note on Readarr:** the original Readarr project has been retired. GuardTowarr still monitors it, and it should work with community forks that keep the same API; treat ongoing support as best-effort. There's an info button next to it in Settings explaining this.

---

## Remote access setup

This opens a second port meant to be reached from outside your network. Set it up carefully:

1. **Enable it** in **Settings → General → Remote access**. It's off by default, and turning it on shows a disclaimer you'll need to acknowledge.
2. **Set a strong token.** Use the **Generate** button for a long random one. Anyone with the token can use the endpoint, so treat it like a password.
3. **Choose what it allows.** It's monitor-only by default. Optionally enable **content requests** (remote search + add) and/or **remediation actions** (remote one-click fixes, including destructive ones, gated behind their own confirmation).
4. **Put it behind a reverse proxy with HTTPS and its own login.** The token travels with each request, so plain HTTP is not safe. Use Authelia, Authentik, Cloudflare Access, or Caddy / Nginx Proxy Manager basic auth in front of it. **Never forward the raw port straight to the internet.**
5. **Restart GuardTowarr** to apply (the remote port only starts at launch). In Docker, also publish the port (`9596`), and recreate the container if you're adding it.

What it never exposes, even to a token-holder: your API keys, passwords, internal service addresses, or any admin/settings routes. Those stay on the private port only.

---

## Good to know

- **Runs quietly in the system tray** (desktop build). Right-click the icon to open the dashboard or quit.
- **Settings live in the app**, organized into tabs (**General · Services · Alerts · Stability**), remembered across restarts.
- **Update notices.** It checks GitHub about once a day and shows a quiet, dismissible card when a new release is out. Nothing downloads automatically; turn it off in settings.
- **Check it from your phone or another device** on the same network: just browse to your PC's address on port `9595`.
- **Your data stays local.** GuardTowarr talks only to your own services and, if you turn on alerts, the notification service you choose. Pushover and Discord use your own account/webhook, so nothing routes through us.

---

## Platform

- **Docker image:** runs anywhere Docker does (**Linux, NAS (Synology / unRAID), Windows, macOS**). Recommended for running on a server.
- **Standalone `.exe`:** **Windows only.** The desktop build with the system-tray icon, for your everyday Windows PC.

A native macOS build may follow if there's interest. Either way, open an issue and let me know what you're running.

---

## Contributing

Bug reports, fixes, and new service integrations are welcome. The whole app is driven by one service registry, so adding a monitored service is two small steps. See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/adding-a-service.md](docs/adding-a-service.md).

## Feedback

Found a bug or have an idea? [Open an issue](../../issues). Feature and service suggestions are genuinely welcome; a lot of what's shipped came straight from them.

## License

GuardTowarr is released under the **GNU General Public License v3.0**. You're free to use, study, modify, and share it; derivative works must stay open under the same license. See [LICENSE](LICENSE) for the full text.

</div>
