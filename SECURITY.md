# Security policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/tonytrawl/GuardTowarr/security/advisories/new)
(Security tab on the repo), or open a minimal issue asking for a private contact
and avoid posting details publicly until it's fixed.

Include what you found, how to reproduce it, and the impact. You'll get a reply as
soon as reasonably possible.

## Scope and expectations

GuardTowarr is meant to run on your own network. A few things are intentional and
worth knowing before you report them:

- The **main dashboard (port 9595) has no login** and shows full config including
  credentials. It is designed for a trusted LAN. Do not expose it to the internet.
  Open it by server IP, `localhost`, or the machine hostname. Arbitrary DNS names
  are rejected to protect against DNS rebinding. Trusted custom domains can be
  added to `allowed_hosts` or the comma-separated `GUARDTOWARR_ALLOWED_HOSTS`
  environment variable. This does not provide authentication. Use the
  token-protected remote port for outside access.
- The optional **remote-access port** is the only part meant to be reachable from
  outside. It strips credentials and internal addresses except browser links explicitly
  opted into remote sharing, requires a token, and is
  intended to sit behind an HTTPS reverse proxy with its own authentication. It
  has no transport security or rate limiting of its own by design; those are the
  proxy's job.

Reports about the main port being unauthenticated, or the remote port being
unsafe when exposed without a proxy, describe documented behavior rather than
bugs. Genuine issues (for example, the remote port leaking a credential it should
strip, or the token check being bypassable) are very much in scope.

Remote shortcuts block query strings, fragments, and known configured credentials
by default. A per-link override, off by default, allows the full URL to be shared
after a risk warning. Anyone with remote access can copy that URL and any secrets
it contains. The override does not enable remote visibility by itself or allow
non-HTTP(S) URLs or embedded username/password login URLs.
