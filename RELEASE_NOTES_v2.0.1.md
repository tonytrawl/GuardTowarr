# GuardTowarr 2.0.1

A quick patch for the things you found after 2.0. Thanks for reporting them.

- Fixed the oversized search posters in Safari. Posters now stay inside their cards, including on smaller screens.
- Added an exact hostname allowlist for custom domains and reverse proxies. Set **Allowed dashboard domains** in General settings, or use `GUARDTOWARR_ALLOWED_HOSTS=dashboard.example.com` if the dashboard is currently blocked. Multiple hostnames can be separated by commas. This does not add a login: keep the admin port on your trusted network or behind authentication.
- qBittorrent still works with your existing Web UI username and password. You can also use an API key on versions that support it. Leave the key blank to keep using your login; a key takes priority when both are filled in. No reconfiguration needed for existing installs.
- Improved qBittorrent session handling and authentication errors. Connections reuse the session, rejected logins get a short cooldown, and failed actions aren't automatically sent again.
- Storage now has All instances, Selected instances, and Off modes. Existing preferences carry over. Removing the last selected instance leaves storage empty instead of silently switching back to all sources.
- Allowed dashboard domains accepts pasted HTTP(S) URLs and saves only the hostname. This allows your proxy domain; it does not add authentication.
- Added optional dashboard shortcuts, separate browser URLs for services, and custom links. Remote links are off by default and require an explicit URL and opt-in.
- Shortcuts show the service name for a single instance, or your instance names when you run more than one. Custom links keep their own labels.
- History now shows your service names instead of internal instance IDs.
- Fixed setup reporting success after a failed save, preserved passwords exactly as entered, and kept long Settings dialogs positioned at the top when opened.

- Remote shortcuts block query strings, fragments, and known credentials by default. You can override protection for an individual link after accepting a warning that the full URL, including any secrets, will be shared with remote viewers.
- Fixed older profile requests overwriting a newer Add dialog.
- Storage choices now update when you add or remove instances.
- Restart reminders now survive other edits and connection tests before saving.

Back up your config folder before updating. Your existing settings carry over.
