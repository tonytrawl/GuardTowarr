# GuardTowarr 2.0

This one's for the bigger stacks, and for making the everyday stuff a little less
of a headache.

## What's new

- **Multiple instances.** Run separate Radarr or Sonarr libraries? Give each one a
  name, check them in one place, and choose where your requests go.
- **Choose your root folder.** Movie and show requests now let you pick the folder
  as well as the quality profile.
- **SABnzbd queues.** Active downloads and recent failures sit alongside torrents
  in the downloads view.
- **Cleanuparr monitoring.** Health checks and unresolved items that need your
  attention, without triggering cleanup jobs.
- **Docker monitoring.** Watch selected containers for stopped, unhealthy, or
  missing states through a socket or a restricted socket proxy.
- **Connection tests in Settings.** Check the address and credentials before saving.
- **Action history.** See whether a fix succeeded, failed, or only partly finished.

## Fixes and polish

- Failed download removal no longer gets reported as a success. Queue fixes check
  the current item before removing it, and keep track of which instance owns it.
- Blocked-file checks pick up rule changes and pause automatic removal when the
  blocklist safety check isn't available.
- Config saves use atomic replacement. Damaged config files are kept for recovery.
- Services are checked concurrently. Stale results are marked, and unreachable
  services stay visible even when there isn't a separate issue message.
- Health percentages use time the monitor actually observed. Time while it was
  switched off doesn't get counted as healthy.
- More mobile and keyboard polish, clearer instance labels, and explicit
  search-only labels for books and music.
- Remote responses filter nested credentials, internal addresses, and paths.
  Links are limited to HTTP(S), poster responses to supported image formats, and
  service requests won't carry credentials across redirects to another host.
- Cross-site writes and page framing are blocked. The existing Chart.js download
  is integrity-pinned. The main port is still for a trusted LAN; remote access
  still needs an HTTPS reverse proxy.
- Stable Docker releases publish the version tag and `latest` together.

## Updating

Back up your config folder first. Existing settings carry over; new services start
off until you enable them. Keep the whole config folder mounted in Docker, including
the new `actions.json` and `observations.json` files.

Windows: download **GuardTowarr.exe** below. Docker: pull
**tonytrawl/guardtowarr:2.0.0** or **tonytrawl/guardtowarr:latest**.

Maintainerr isn't part of this release. Books and music remain search-only.

See [2.0 setup notes](docs/2.0.md) and [validation details](docs/VALIDATION.md).
