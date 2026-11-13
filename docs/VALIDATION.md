# 2.0 validation

The suite covers named instances, root/profile selection, combined downloads,
config recovery, atomic saves, action outcomes, duplicate prevention, blocked-file
safeguards, observed health, polling, and remote permissions and filtering.

HTTP simulations cover SABnzbd, Cleanuparr, and a Docker proxy: healthy responses,
authentication failures, unavailable endpoints, malformed JSON, failed downloads,
manual events, and stopped, unhealthy, or missing containers. These use local
servers and synthetic data. They do not prove compatibility with every release of
those applications. Docker was also checked against a real Engine through its
Unix socket with a disposable container.

Security regression checks cover cross-origin redirects, active poster content,
response size limits for posters, cross-site writes, and page security headers.
Browser checks cover setup, connection testing, instance and root selection,
remote access, and phone-sized layouts. Windows executable and Docker startup
checks use temporary configurations.

Run `python -B -m unittest discover -s tests -v` and
`python tools/check_frontend.py`. The Unix-socket test runs on Linux only.

This is a focused code review and regression suite, not an independent penetration
test. The main dashboard remains unauthenticated and belongs on a trusted network.
