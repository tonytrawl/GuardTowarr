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
  are rejected to protect against DNS rebinding. Use the token-protected remote
  port for a reverse-proxy domain.
- The optional **remote-access port** is the only part meant to be reachable from
  outside. It strips credentials and internal addresses, requires a token, and is
  intended to sit behind an HTTPS reverse proxy with its own authentication. It
  has no transport security or rate limiting of its own by design; those are the
  proxy's job.

Reports about the main port being unauthenticated, or the remote port being
unsafe when exposed without a proxy, describe documented behavior rather than
bugs. Genuine issues (for example, the remote port leaking a credential it should
strip, or the token check being bypassable) are very much in scope.
