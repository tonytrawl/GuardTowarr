GuardTowarr 2.0.2 fixes two login issues people reported after 2.0.1. Your saved settings carry over.

- Jellyfin now sends the API key in the Authorization header for health checks, active streams, and library counts. A rejected key now shows the HTTP error instead of telling you the server is unreachable.
- qBittorrent now recognizes both the old and new ways the Web UI confirms a login. API keys use Bearer authorization. I tested username and password on Hotio 4.6.7, 5.2.1, and 5.3.0, and API keys on 5.2.1 and 5.3.0.
- If qBit still rejects a request, Test connection tells you which request failed and how GuardTowarr tried to log in. It leaves out passwords, keys, and cookie values.

Thanks to everyone who tested and reported back. Knowing the qBit version helped pin this one down.
