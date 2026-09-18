# NetMon

A LAN-only Docker application for finding, documenting, identifying, and searching devices on a home network. The web interface is titled **Network Device Directory**.

## What it does

- Discovers devices on the local broadcast network with ARP scanning.
- Stores IP address, MAC address, hostname, manufacturer, online status, and last-seen time.
- Lets you add your own friendly name, device type, location, and notes.
- Imports eero friendly names, hostnames, connection information, DHCP reservation names, and available last-active timestamps.
- Creates or updates an eero DHCP reservation after an explicit confirmation.
- Performs an optional online MAC-vendor lookup only when you press the lookup button.
- Scans a selected device for open TCP ports, identifies likely services and versions, and saves the results.
- Deep-scans a selected device and combines MAC ownership, names, service fingerprints, safe service details, and OS hints into a cautious identity report with supporting evidence.
- Shows the saved identity on the main device list so it is searchable without reopening the device.
- Matches devices by MAC address with Home Assistant and imports their device name, model, area, firmware version, entities, and current states.
- Queries ESPHome mDNS advertisements and labels TCP port 6053 correctly as the ESPHome native API.
- Analyzes per-device DNS history from one or two Pi-hole 6 servers, merges duplicate records, and saves a cautious identity hypothesis with its supporting domains.
- Remembers each device's observed IP-address history so older Pi-hole records can still be associated with the same MAC address.
- Stores all application data in `./data` beside the Compose file.

## Install

Copy this complete folder to `/opt/docker/netmon` (or another directory) on your Docker host. From that directory run:

```bash
docker compose up -d --build
```

Open:

```text
http://YOUR_DOCKER_HOST:8088
```

The first automatic scan starts shortly after the container launches. You can also press **Scan network** at any time.

## eero connection

Press **Connect eero**, enter the email address or phone number used for the eero account, and then enter the one-time code eero sends. The application stores only the resulting eero session token in `./data/eero-session.json`, with restricted file permissions. It does not store an eero password.

The eero API is unofficial and may change. Network scanning, searching, notes, and saved device records do not depend on eero and continue working if the eero interface changes.

## Configuration

Edit `compose.yaml` if needed:

- `NETWORK_CIDR`: Network to validate and display. Default: `192.168.1.0/24`.
- `APP_PORT`: Web port. Default: `8088`.
- `AUTO_SCAN_MINUTES`: Automatic scan interval. Use `0` to disable automatic scans.
- `TZ`: Container time zone.

Because ARP scanning works at the local Ethernet layer, the container uses host networking plus `NET_RAW` and `NET_ADMIN`. The web application itself does not expose shell commands or accept a scan target from the browser.

## Port scanning

Open a device and press **Scan ports**. The scan checks Nmap's 5,000 most common TCP ports plus additional ports commonly used by Home Assistant, ESPHome, MQTT, Plex, Navidrome, printers, cameras, Docker dashboards, and other home-network services. Results include the port number, likely service, and any product/version information the service provides.

Port scans are manual, run one device at a time, and are restricted to `NETWORK_CIDR`. A completed scan is a useful snapshot, but it does not test UDP or guarantee that every possible custom TCP port is closed.

## Deep scanning

Open a device and press **Deep scan** to run the broad TCP scan with stronger service detection, safe web/TLS/SSH detail checks, an operating-system hint when Nmap can obtain one, and an automatic public MAC-vendor lookup for globally assigned MAC addresses. When eero is connected, Deep Scan also refreshes its device and reservation data and uses a reservation name matched to the same MAC address as identification evidence. The application then produces a device-type suggestion, confidence level, short explanation, and evidence list.

Identity results are informed suggestions, not proof. Many IoT products deliberately reveal very little, operating-system detection can be approximate, and a private/randomized MAC cannot be matched to a manufacturer. Deep scans remain manual to avoid continuously probing every IoT device on the network.

When a deep scan finds ESPHome on TCP port 6053, it also listens for the device's `_esphomelib._tcp.local` mDNS advertisement. If Home Assistant is connected, the scan refreshes Home Assistant's device and entity registries and uses the MAC address to find the matching device. This often reveals the device's purpose without requiring its ESPHome encryption key. If Home Assistant has no match, the directory attempts a direct ESPHome API query; it can list entities on an unencrypted device and reports when API encryption protects the details.

## Home Assistant connection

Press **Connect Home Assistant** and enter the local Home Assistant URL plus a long-lived access token. The initial suggestion is `http://homeassistant.local:8123`; replace it if your installation uses another hostname or address. Create a dedicated non-administrator Home Assistant user for the directory, sign in as that user, and generate its token from the Profile page.

The application uses the token only for read operations: validating the API, retrieving current states, and listing Home Assistant's device, entity, and area registries. The token is stored in `/data/home-assistant-token` with owner-only file permissions and is never returned to the browser after connection. Disconnecting removes the stored token. Home Assistant's supported API does not expose ESPHome encryption keys, and the directory does not attempt to extract them.

## Pi-hole DNS analysis

Press **Connect Pi-hole** and enter each local Pi-hole 6 URL plus its application password. The application tests both connections before saving them. Credentials are stored only in `/data/pihole-connections.json` with owner-only permissions, are never returned to the browser, and are used only to authenticate read-only query-history requests.

Open a device and use **DNS traffic analysis** to inspect the last hour, 24 hours, 7 days, or 30 days. The directory searches all current, reserved, and historically observed IP addresses for that MAC, merges duplicate results from both Pi-holes, ranks the requested domains, detects regular heartbeat patterns, and compares distinctive destinations with a local device-signature catalog. The saved hypothesis, confidence, explanation, evidence, source counts, and top domains remain available after the scan. A later Deep Scan can use a saved DNS conclusion as additional evidence, but does not automatically query Pi-hole.

DNS identity is evidence, not certainty. Devices using DNS-over-HTTPS/TLS may bypass Pi-hole, and clients behind another router or DNS proxy may appear under that intermediary's address. Shared cloud and CDN domains are deliberately treated as weak evidence.

## Backup

Back up the `data` directory. It contains the SQLite device database and, when connected, the eero session, Home Assistant token, and Pi-hole connection file. Treat that backup as sensitive.
