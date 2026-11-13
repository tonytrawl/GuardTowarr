# Adding a new service

GuardTowarr is driven by one registry in `monitor.py`, so adding a service is two
steps: write a check function, then add a registry entry. The setup screen,
credential prompts, troubleshooting links, and default config all derive from
that entry.

## Step 1: write a check function

Each service has one function that talks to it and reports whether it's healthy.
`check_ombi` is the simplest to copy. The contract:

```python
def check_myservice(name, cfg):
    base = cfg["url"].rstrip("/")
    key = cfg.get("api_key", "")          # or token / username+password
    if not key:
        return svc_result(name, "warning", "No API key configured", [])
    try:
        status, body = http_get(f"{base}/api/health", {"X-Api-Key": key})
        if status != 200:
            return svc_result(name, "error", f"Returned HTTP {status}",
                [_issue("error", "Connection", "Something is wrong, here is a hint.",
                        DOC_LINKS.get("myservice_http", ""))])
        return svc_result(name, "ok", "Online", [])
    except Exception as e:
        return svc_result(name, "error", f"Unreachable: {e}",
            [_issue("error", "Unreachable", "Couldn't reach it. Check the address.",
                    DOC_LINKS.get("myservice_unreachable", ""))])
```

Rules:

- It takes `(name, cfg)` and returns `svc_result(name, level, summary, issues)`.
- `level` is `"ok"`, `"warning"`, or `"error"`.
- `issues` is a list of `_issue(level, source, message, fix_url)`, one per problem.
  `fix_url` is optional and shows up as a "View documentation" link next to the
  error and in alerts.
- Never let it throw. Wrap network calls in try/except and turn failures into an
  error result, as in the example.

## Step 2: add a registry entry

Find `SERVICE_REGISTRY` in `monitor.py` and add a block:

```python
"myservice": {
    "label": "My Service",
    "blurb": "What it does",              # one-liner on the setup tile
    "fields": ["url", "api_key"],         # what the user must fill in
    "checker": check_myservice,
    "capabilities": ["monitor"],          # see below
    "docs": {                             # optional troubleshooting links
        "http":        "https://...",
        "unreachable": "https://...",
    },
    "instances": {                        # the named service(s) of this type
        "myservice": "http://localhost:1234",
    },
},
```

Restart the app. The service then appears in setup, gets a config entry, prompts
for its credentials, and is polled on the normal schedule.

In 2.0, `name` is an instance ID and may be user-created (for example,
`radarr_4k`). Use `service_app(name, cfg)` to identify its application and
`cfg.get("label", name)` for display. Iterate with `active_instances` rather than
assuming a single default ID exists. Any mutation must retain the selected
instance ID through validation and execution.

## Capabilities

Every service supports `"monitor"` automatically. That is the uptime/health check
the check function provides, and it is all most services need.

Anything beyond uptime is opt-in. Add the flag to `capabilities` and write the
matching hook:

- `"search"` / `"add"`: search for and add media (how the *arr apps work)
- `"queue"`: feed the active-downloads view
- `"stats"`: feed the stats panel

The flag does two jobs: it switches the feature on for that service, and it
records what has actually been wired up. A service at `["monitor"]` is
uptime-only; raise it when you add a hook.

When writing a capability-aware feature, use these instead of hard-coding service
names, so it lights up for any future service that opts into the same capability:

- `service_capabilities(svc)`: what can this one service do?
- `services_with_capability(cfg, "stats")`: which services support X?

## Note

`monitor` is the only capability that comes free from the registry. The richer
ones still need their hook written; the flag just keeps that work isolated and
obvious. For a service you only want to keep an eye on, none of that applies:
write the check function, add the entry with `["monitor"]`, done.
