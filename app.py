import asyncio
import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from urllib.parse import urlparse
from xml.etree import ElementTree

import requests
import websocket
from aioesphomeapi import APIClient
from flask import Flask, jsonify, render_template, request
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

try:
    from eero import EeroClient
except ImportError:  # Allows basic development without the optional integration installed.
    EeroClient = None


DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "devices.db"
EERO_COOKIE_PATH = DATA_DIR / "eero-session.json"
HA_TOKEN_PATH = DATA_DIR / "home-assistant-token"
PIHOLE_CONFIG_PATH = DATA_DIR / "pihole-connections.json"
NETWORK_CIDR = os.getenv("NETWORK_CIDR", "192.168.1.0/24")
AUTO_SCAN_MINUTES = max(0, int(os.getenv("AUTO_SCAN_MINUTES", "5")))
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
NMAP_SERVICES_PATH = Path("/usr/share/nmap/nmap-services")
PORT_SCAN_COUNT = 5000
HOME_LAB_PORTS = {
    53, 67, 68, 80, 81, 88, 123, 135, 137, 138, 139, 161, 162, 389, 443, 445,
    500, 515, 548, 554, 631, 853, 1883, 1900, 2049, 3000, 3001, 3306, 3389,
    4000, 4533, 5000, 5001, 5353, 5432, 5683, 6053, 6379, 6667, 7000, 7001,
    1080, 8000, 8008, 8009, 8080, 8081, 8088, 8096, 8123, 8443, 8554, 8883, 8888, 9000,
    9001, 9090, 9100, 9443, 10000, 14000, 18888, 32400, 49152, 50000, 51820,
}

app = Flask(__name__)
DATA_DIR.mkdir(parents=True, exist_ok=True)


@app.before_request
def reject_cross_origin_writes():
    """Keep unrelated websites from issuing changes through a LAN browser."""
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return None
    origin = request.headers.get("Origin")
    if origin and urlparse(origin).netloc != request.host:
        return jsonify({"ok": False, "message": "Cross-origin changes are not allowed."}), 403
    return None


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_timestamp(value):
    """Convert common eero timestamp formats to a UTC ISO-8601 string."""
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)) or str(value).strip().isdigit():
            epoch = float(value)
            if epoch > 10_000_000_000:
                epoch /= 1000
            parsed = datetime.fromtimestamp(epoch, timezone.utc)
        else:
            text = str(value).strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = parsed.astimezone(timezone.utc)
        return parsed.replace(microsecond=0).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def normalize_mac(value):
    if not value:
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(value))
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).upper()


def private_mac(mac):
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0x02)
    except (ValueError, AttributeError, IndexError):
        return False


def db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with db_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL UNIQUE,
                ip TEXT,
                hostname TEXT,
                friendly_name TEXT,
                eero_name TEXT,
                eero_hostname TEXT,
                eero_device_id TEXT,
                manufacturer TEXT,
                online_lookup TEXT,
                online_lookup_at TEXT,
                is_private_mac INTEGER NOT NULL DEFAULT 0,
                online INTEGER NOT NULL DEFAULT 0,
                connection_type TEXT,
                frequency TEXT,
                eero_node TEXT,
                signal TEXT,
                reserved_ip TEXT,
                reservation_id TEXT,
                eero_reservation_name TEXT,
                device_type TEXT,
                location TEXT,
                notes TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT,
                last_scan_source TEXT,
                open_ports TEXT,
                ports_scanned_at TEXT,
                ports_scan_error TEXT,
                device_identity TEXT,
                identity_confidence TEXT,
                identity_summary TEXT,
                identity_evidence TEXT,
                os_hint TEXT,
                deep_scanned_at TEXT,
                deep_scan_error TEXT,
                mdns_name TEXT,
                mdns_info TEXT,
                mdns_scanned_at TEXT,
                ha_device_id TEXT,
                ha_name TEXT,
                ha_model TEXT,
                ha_manufacturer TEXT,
                ha_sw_version TEXT,
                ha_area TEXT,
                ha_entities TEXT,
                ha_synced_at TEXT,
                esphome_api_status TEXT,
                esphome_device_info TEXT,
                esphome_entities TEXT,
                dns_identity TEXT,
                dns_confidence TEXT,
                dns_summary TEXT,
                dns_evidence TEXT,
                dns_domains TEXT,
                dns_source_summary TEXT,
                dns_scanned_at TEXT,
                dns_scan_error TEXT,
                dns_lookback_hours INTEGER,
                dns_query_count INTEGER,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
            CREATE INDEX IF NOT EXISTS idx_devices_online ON devices(online);
            CREATE INDEX IF NOT EXISTS idx_devices_reserved_ip ON devices(reserved_ip);

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS device_ip_history (
                device_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (device_id, ip),
                FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_device_ip_history_ip ON device_ip_history(ip);
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(devices)")}
        for name, definition in (
            ("open_ports", "TEXT"),
            ("ports_scanned_at", "TEXT"),
            ("ports_scan_error", "TEXT"),
            ("device_identity", "TEXT"),
            ("identity_confidence", "TEXT"),
            ("identity_summary", "TEXT"),
            ("identity_evidence", "TEXT"),
            ("os_hint", "TEXT"),
            ("deep_scanned_at", "TEXT"),
            ("deep_scan_error", "TEXT"),
            ("mdns_name", "TEXT"),
            ("mdns_info", "TEXT"),
            ("mdns_scanned_at", "TEXT"),
            ("ha_device_id", "TEXT"),
            ("ha_name", "TEXT"),
            ("ha_model", "TEXT"),
            ("ha_manufacturer", "TEXT"),
            ("ha_sw_version", "TEXT"),
            ("ha_area", "TEXT"),
            ("ha_entities", "TEXT"),
            ("ha_synced_at", "TEXT"),
            ("esphome_api_status", "TEXT"),
            ("esphome_device_info", "TEXT"),
            ("esphome_entities", "TEXT"),
            ("eero_reservation_name", "TEXT"),
            ("dns_identity", "TEXT"),
            ("dns_confidence", "TEXT"),
            ("dns_summary", "TEXT"),
            ("dns_evidence", "TEXT"),
            ("dns_domains", "TEXT"),
            ("dns_source_summary", "TEXT"),
            ("dns_scanned_at", "TEXT"),
            ("dns_scan_error", "TEXT"),
            ("dns_lookback_hours", "INTEGER"),
            ("dns_query_count", "INTEGER"),
        ):
            if name not in columns:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {name} {definition}")
        now = utc_now()
        conn.execute(
            """INSERT OR IGNORE INTO device_ip_history(device_id, ip, first_seen, last_seen)
               SELECT id, ip, COALESCE(first_seen, ?), COALESCE(last_seen, updated_at, ?)
               FROM devices WHERE ip IS NOT NULL AND ip <> ''""",
            (now, now),
        )
        conn.execute("PRAGMA optimize")


def row_to_dict(row):
    item = dict(row)
    item["online"] = bool(item["online"])
    item["is_private_mac"] = bool(item["is_private_mac"])
    try:
        item["open_ports"] = json.loads(item.get("open_ports") or "[]")
    except (TypeError, json.JSONDecodeError):
        item["open_ports"] = []
    try:
        item["identity_evidence"] = json.loads(item.get("identity_evidence") or "[]")
    except (TypeError, json.JSONDecodeError):
        item["identity_evidence"] = []
    for field, default in (
        ("dns_evidence", []), ("dns_domains", []), ("dns_source_summary", []),
    ):
        try:
            item[field] = json.loads(item.get(field) or json.dumps(default))
        except (TypeError, json.JSONDecodeError):
            item[field] = default
    for field, default in (
        ("mdns_info", {}), ("ha_entities", []),
        ("esphome_device_info", {}), ("esphome_entities", []),
    ):
        try:
            item[field] = json.loads(item.get(field) or json.dumps(default))
        except (TypeError, json.JSONDecodeError):
            item[field] = default
    item["display_name"] = (
        item.get("friendly_name")
        or item.get("ha_name")
        or item.get("eero_reservation_name")
        or item.get("eero_name")
        or item.get("eero_hostname")
        or item.get("hostname")
        or item.get("mac")
    )
    return item


def practical_tcp_ports():
    """Return Nmap's 5,000 most common TCP ports plus useful home-lab ports."""
    ranked = []
    try:
        for line in NMAP_SERVICES_PATH.read_text(errors="ignore").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3 or not parts[1].endswith("/tcp"):
                continue
            port = int(parts[1].split("/", 1)[0])
            frequency = float(parts[2])
            ranked.append((frequency, port))
    except (OSError, ValueError):
        # Nmap still ships a useful default list; these cover the local-service additions.
        ranked = []
    ranked.sort(reverse=True)
    ports = {port for _, port in ranked[:PORT_SCAN_COUNT]}
    ports.update(HOME_LAB_PORTS)
    return sorted(ports)


def get_setting(key, default=None):
    with db_connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    with db_connection() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def resolve_hostname(ip):
    try:
        name = socket.gethostbyaddr(ip)[0].rstrip(".")
        return name if name != ip else None
    except (socket.herror, socket.gaierror, TimeoutError, OSError):
        return None


def upsert_discovered_device(info, source):
    mac = normalize_mac(info.get("mac"))
    if not mac:
        return
    now = utc_now()
    fields = {
        "ip": info.get("ip"),
        "hostname": info.get("hostname"),
        "eero_name": info.get("eero_name"),
        "eero_hostname": info.get("eero_hostname"),
        "eero_device_id": info.get("eero_device_id"),
        "eero_reservation_name": info.get("eero_reservation_name"),
        "manufacturer": info.get("manufacturer"),
        "connection_type": info.get("connection_type"),
        "frequency": info.get("frequency"),
        "eero_node": info.get("eero_node"),
        "signal": info.get("signal"),
        "online": 1 if info.get("online", True) else 0,
        "last_seen": now if info.get("online", True) else info.get("last_seen"),
    }
    with db_connection() as conn:
        existing = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,)).fetchone()
        if not existing:
            cursor = conn.execute(
                """
                INSERT INTO devices (
                    mac, ip, hostname, eero_name, eero_hostname, eero_device_id,
                    eero_reservation_name, manufacturer, is_private_mac, online, connection_type,
                    frequency, eero_node, signal, first_seen, last_seen,
                    last_scan_source, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mac,
                    fields["ip"],
                    fields["hostname"],
                    fields["eero_name"],
                    fields["eero_hostname"],
                    fields["eero_device_id"],
                    fields["eero_reservation_name"],
                    fields["manufacturer"],
                    1 if private_mac(mac) else 0,
                    fields["online"],
                    fields["connection_type"],
                    fields["frequency"],
                    fields["eero_node"],
                    fields["signal"],
                    now,
                    fields["last_seen"],
                    source,
                    now,
                ),
            )
            if fields["ip"]:
                conn.execute(
                    "INSERT OR REPLACE INTO device_ip_history(device_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                    (cursor.lastrowid, fields["ip"], now, fields["last_seen"] or now),
                )
            return

        assignments = []
        values = []
        for key, value in fields.items():
            if value is not None:
                assignments.append(f"{key} = ?")
                values.append(value)
        assignments.extend(["is_private_mac = ?", "last_scan_source = ?", "updated_at = ?"])
        values.extend([1 if private_mac(mac) else 0, source, now, mac])
        conn.execute(
            f"UPDATE devices SET {', '.join(assignments)} WHERE mac = ?",
            values,
        )
        if fields["ip"]:
            conn.execute(
                """INSERT INTO device_ip_history(device_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)
                   ON CONFLICT(device_id, ip) DO UPDATE SET last_seen=excluded.last_seen""",
                (existing["id"], fields["ip"], now, fields["last_seen"] or now),
            )


scan_lock = threading.Lock()
port_scan_lock = threading.Lock()


def scan_network():
    if not scan_lock.acquire(blocking=False):
        return {"ok": False, "message": "A scan is already running."}
    try:
        network = ipaddress.ip_network(NETWORK_CIDR, strict=False)
        started = utc_now()
        command = ["arp-scan", "--localnet", "--ignoredups", "--retry=2", "--timeout=250"]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
        if completed.returncode not in (0, 1):
            error = (completed.stderr or completed.stdout or "arp-scan failed").strip()
            raise RuntimeError(error)

        found = []
        for line in completed.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            try:
                ip = str(ipaddress.ip_address(parts[0].strip()))
            except ValueError:
                continue
            mac = normalize_mac(parts[1].strip())
            if not mac or ipaddress.ip_address(ip) not in network:
                continue
            vendor = parts[2].strip() if len(parts) > 2 else None
            if vendor and vendor.lower().startswith("(unknown"):
                vendor = None
            found.append({"ip": ip, "mac": mac, "manufacturer": vendor})

        with db_connection() as conn:
            conn.execute("UPDATE devices SET online = 0")
        for item in found:
            item["hostname"] = resolve_hostname(item["ip"])
            item["online"] = True
            upsert_discovered_device(item, "lan")

        set_setting("last_lan_scan", started)
        set_setting("last_lan_scan_count", str(len(found)))
        return {"ok": True, "count": len(found), "message": f"Found {len(found)} devices."}
    except Exception as exc:
        set_setting("last_lan_scan_error", str(exc))
        return {"ok": False, "message": str(exc)}
    finally:
        scan_lock.release()


def lookup_mac_vendor_value(mac):
    if private_mac(mac):
        raise RuntimeError("This is a private/randomized MAC address; no public manufacturer is encoded in it.")
    response = requests.get(f"https://api.macvendors.com/{mac}", timeout=12)
    if response.status_code == 404:
        raise RuntimeError("No public vendor record was found for this MAC address.")
    response.raise_for_status()
    vendor = response.text.strip()
    if not vendor:
        raise RuntimeError("The lookup service returned no vendor information.")
    return vendor


def discover_esphome_mdns(ip, timeout=4):
    """Find the ESPHome mDNS advertisement matching one local IP address."""
    matches = []
    matches_lock = threading.Lock()

    class Listener(ServiceListener):
        def update_service(self, zeroconf, service_type, name):
            self.add_service(zeroconf, service_type, name)

        def remove_service(self, zeroconf, service_type, name):
            return None

        def add_service(self, zeroconf, service_type, name):
            info = zeroconf.get_service_info(service_type, name, timeout=1200)
            if not info or ip not in info.parsed_addresses():
                return
            properties = {}
            for key, value in info.properties.items():
                decoded_key = key.decode(errors="replace") if isinstance(key, bytes) else str(key)
                decoded_value = value.decode(errors="replace") if isinstance(value, bytes) else str(value)
                properties[decoded_key] = decoded_value
            properties["service_name"] = name.removesuffix("._esphomelib._tcp.local.")
            properties["server"] = (info.server or "").rstrip(".")
            with matches_lock:
                matches.append(properties)

    zeroconf = Zeroconf()
    browser = ServiceBrowser(zeroconf, "_esphomelib._tcp.local.", Listener())
    try:
        time.sleep(timeout)
    finally:
        browser.cancel()
        zeroconf.close()
    return matches[0] if matches else {}


def _public_object_fields(value, names):
    result = {}
    for name in names:
        item = getattr(value, name, None)
        if item is None:
            continue
        if hasattr(item, "value"):
            item = item.value
        if isinstance(item, (str, int, float, bool)):
            result[name] = item
    return result


async def _probe_esphome_api(ip):
    client = APIClient(ip, 6053)
    try:
        await client.connect(login=True)
        device = await client.device_info()
        entities, services = await client.list_entities_services()
        device_info = _public_object_fields(
            device,
            (
                "name", "friendly_name", "model", "manufacturer", "esphome_version",
                "project_name", "project_version", "mac_address", "compilation_time",
            ),
        )
        entity_info = [
            _public_object_fields(
                entity,
                (
                    "name", "object_id", "unique_id", "icon", "device_class",
                    "unit_of_measurement", "entity_category", "disabled_by_default",
                ),
            )
            for entity in entities
        ]
        entity_info.extend(
            {"name": getattr(service, "name", None), "type": "service"}
            for service in services
            if getattr(service, "name", None)
        )
        return {"status": "Connected without an encryption key.", "device": device_info, "entities": entity_info}
    finally:
        try:
            await client.disconnect(force=True)
        except Exception:
            pass


def probe_esphome_api(ip):
    try:
        return asyncio.run(asyncio.wait_for(_probe_esphome_api(ip), timeout=15))
    except Exception as exc:
        message = str(exc).strip()
        if "encrypt" in message.lower() or "noise" in message.lower() or "psk" in message.lower():
            message = "API encryption is enabled; protected entity details were not requested."
        else:
            message = message or "The ESPHome API did not provide additional details."
        return {"status": message, "device": {}, "entities": []}


def identify_device(device, ports, os_hint=None):
    """Make conservative, explainable suggestions from local scan evidence."""
    port_numbers = {item["port"] for item in ports}
    text = " ".join(
        str(device.get(key) or "")
        for key in (
            "friendly_name", "device_type", "ha_name", "ha_model", "ha_area",
            "eero_reservation_name", "eero_name", "eero_hostname", "hostname", "mdns_name", "manufacturer", "online_lookup",
        )
    ).lower()
    evidence = []

    def result(name, confidence, explanation, facts):
        return {
            "device_identity": name,
            "identity_confidence": confidence,
            "identity_summary": explanation,
            "identity_evidence": facts,
        }

    vendor = device.get("manufacturer") or device.get("online_lookup")
    if vendor:
        evidence.append(f"MAC manufacturer: {vendor}")
    reservation_name = device.get("eero_reservation_name")
    if reservation_name:
        evidence.append(f"eero reservation name for this MAC: {reservation_name}")
    if os_hint:
        evidence.append(f"Operating-system hint: {os_hint}")
    if ports:
        evidence.append("Open TCP ports: " + ", ".join(str(port) for port in sorted(port_numbers)))

    ha_entities = device.get("ha_entities") or []
    if device.get("ha_name"):
        evidence.append(f"Home Assistant device: {device['ha_name']}")
    if device.get("ha_model"):
        evidence.append(f"Home Assistant model: {device['ha_model']}")
    if device.get("ha_area"):
        evidence.append(f"Home Assistant area: {device['ha_area']}")
    if ha_entities:
        entity_names = [entity.get("name") or entity.get("entity_id") for entity in ha_entities]
        evidence.append("Home Assistant entities: " + ", ".join(entity_names[:12]))
    mdns_info = device.get("mdns_info") or {}
    if device.get("mdns_name"):
        evidence.append(f"ESPHome mDNS name: {device['mdns_name']}")
    for key in ("friendly_name", "version", "platform", "board", "project_name", "project_version"):
        if mdns_info.get(key):
            evidence.append(f"mDNS {key.replace('_', ' ')}: {mdns_info[key]}")
    esphome_info = device.get("esphome_device_info") or {}
    esphome_entities = device.get("esphome_entities") or []
    if device.get("esphome_api_status"):
        evidence.append(f"ESPHome API: {device['esphome_api_status']}")
    if esphome_entities:
        api_names = [entity.get("name") or entity.get("object_id") for entity in esphome_entities]
        evidence.append("ESPHome API entities/services: " + ", ".join(name for name in api_names[:12] if name))
    dns_identity = device.get("dns_identity")
    dns_confidence = device.get("dns_confidence")
    if dns_identity:
        evidence.append(f"Saved DNS analysis: {dns_identity} ({dns_confidence or 'low'} confidence)")
        evidence.extend(f"DNS: {item}" for item in (device.get("dns_evidence") or [])[:4])

    if 6053 in port_numbers and device.get("ha_name"):
        return result(
            f"ESPHome: {device['ha_name']}",
            "high",
            "The ESPHome API is present and Home Assistant matched this MAC address to an existing device. Its Home Assistant entities describe what the device monitors or controls.",
            evidence,
        )
    if 6053 in port_numbers and reservation_name:
        return result(
            f"ESPHome: {reservation_name}",
            "high",
            "The ESPHome API is present and the eero DHCP reservation for this exact MAC address supplies a specific device name.",
            evidence,
        )
    if 6053 in port_numbers and esphome_info:
        api_name = esphome_info.get("friendly_name") or esphome_info.get("name")
        return result(
            f"ESPHome: {api_name}" if api_name else "ESPHome device",
            "high",
            "The directory connected directly to the ESPHome API without an encryption key and retrieved the device's declared entities and services.",
            evidence,
        )
    if 6053 in port_numbers:
        mdns_label = device.get("mdns_name") or mdns_info.get("friendly_name")
        return result(
            f"ESPHome: {mdns_label}" if mdns_label else "ESPHome device",
            "high",
            "TCP port 6053 is the ESPHome native API. mDNS details are included when the device advertises them; its exact sensors and controls require a Home Assistant match or access through the protected ESPHome API.",
            evidence,
        )

    if dns_identity and dns_confidence == "high":
        return result(
            dns_identity,
            "high",
            "A saved DNS traffic analysis found a distinctive service pattern for this device, supported by the network-scan evidence below.",
            evidence,
        )

    if "amazon" in text and {1080, 8888}.issubset(port_numbers):
        return result(
            "Likely Amazon Echo / Alexa device",
            "high",
            "Strong match for an Amazon Echo or Alexa-family device. Ports 1080 and 8888 are internal device services, so they are not expected to open as web pages.",
            evidence + ["Amazon hardware plus the 1080/8888 service pattern is a strong combined match."],
        )
    if "amazon" in text and port_numbers.intersection({8008, 8009, 8443, 8888}):
        return result(
            "Likely Amazon Echo or Fire TV device",
            "medium",
            "Amazon owns the MAC address and the exposed local services fit an Amazon smart-home or streaming device, but the exact model cannot be proven from the network alone.",
            evidence,
        )
    named_signatures = (
        (8123, "Home Assistant server", "high"),
        (32400, "Plex Media Server", "high"),
        (4533, "Navidrome music server", "high"),
    )
    for port, name, confidence in named_signatures:
        if port in port_numbers:
            return result(name, confidence, f"The service exposed on TCP port {port} is a strong match for {name}.", evidence)
    if port_numbers.intersection({515, 631, 9100}):
        return result("Likely network printer", "medium", "The device exposes one or more standard network-printing services.", evidence)
    if port_numbers.intersection({554, 8554}):
        return result("Likely IP camera or video device", "medium", "The device exposes a common real-time video streaming service.", evidence)
    if port_numbers.intersection({1883, 8883}):
        return result("Likely MQTT broker or IoT hub", "medium", "The device exposes an MQTT messaging port commonly used by home-automation systems.", evidence)
    if {445, 3389}.issubset(port_numbers):
        return result("Likely Windows computer or server", "medium", "The combination of SMB file sharing and Remote Desktop points to a Windows system.", evidence)
    if 445 in port_numbers or 139 in port_numbers:
        return result("Likely SMB file server or computer", "medium", "The device exposes Windows-compatible SMB file sharing.", evidence)
    if 53 in port_numbers and port_numbers.intersection({80, 443}):
        return result("Likely router or DNS appliance", "medium", "The device provides DNS along with a web-management service.", evidence)

    name_hints = (
        (("echo", "alexa"), "Likely Amazon Echo / Alexa device"),
        (("fire tv", "firetv"), "Likely Amazon Fire TV device"),
        (("printer",), "Likely network printer"),
        (("camera", "cam"), "Likely network camera"),
        (("home assistant", "homeassistant"), "Likely Home Assistant server"),
        (("esphome",), "Likely ESPHome device"),
        (("iphone", "ipad"), "Likely Apple mobile device"),
    )
    for terms, name in name_hints:
        if any(term in text for term in terms):
            return result(name, "medium", "The available device names and network evidence suggest this device type.", evidence)

    if dns_identity and dns_identity != "No distinctive DNS identity found":
        return result(
            dns_identity,
            dns_confidence or "low",
            "The best available identity clue comes from the device's saved DNS traffic analysis.",
            evidence,
        )

    if vendor:
        return result(
            f"{vendor} network device",
            "low",
            "The manufacturer is known, but the scan did not expose a distinctive enough service pattern to determine the exact device type.",
            evidence,
        )
    return result(
        "Unidentified network device",
        "low",
        "The device is reachable, but its MAC address, names, and exposed services do not provide a reliable identity yet.",
        evidence or ["No distinctive identity evidence was returned."],
    )


def scan_device_ports(device_id, deep=False):
    if not port_scan_lock.acquire(blocking=False):
        return {"ok": False, "message": "Another port scan is already running."}, 409
    try:
        with db_connection() as conn:
            row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not row:
            return {"ok": False, "message": "Device not found."}, 404

        ip = row["ip"]
        if not ip:
            return {"ok": False, "message": "This device does not have a current IP address."}, 400
        try:
            address = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(NETWORK_CIDR, strict=False)
            if address not in network:
                raise ValueError
        except ValueError:
            return {
                "ok": False,
                "message": f"For safety, port scans are limited to {NETWORK_CIDR}.",
            }, 400

        ports = practical_tcp_ports()
        if len(ports) < 1000:
            raise RuntimeError("Nmap's local service list is unavailable.")
        command = [
            "nmap",
            "-Pn",
            "-n",
            "-sT",
            "--open",
            "-T4",
            "--max-retries",
            "1",
            "--host-timeout",
            "180s" if deep else "120s",
            "-sV",
            "--version-intensity" if deep else "--version-light",
        ]
        if deep:
            command.extend([
                "5",
                "-O",
                "--osscan-limit",
                "--osscan-guess",
                "--script",
                "http-title,http-server-header,ssl-cert,ssh-hostkey",
                "--script-timeout",
                "15s",
            ])
        command.extend([
            "-p",
            ",".join(str(port) for port in ports),
            "-oX",
            "-",
            ip,
        ])
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=210 if deep else 150, check=False
        )
        if completed.returncode != 0:
            error = (completed.stderr or "Nmap could not complete the scan.").strip()
            raise RuntimeError(error)

        root = ElementTree.fromstring(completed.stdout)
        results = []
        for port_node in root.findall(".//port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue
            port = int(port_node.get("portid"))
            protocol = port_node.get("protocol") or "tcp"
            service_node = port_node.find("service")
            details = {
                "port": port,
                "protocol": protocol,
                "service": None,
                "product": None,
                "version": None,
                "extra": None,
                "device_type": None,
                "os_type": None,
                "scripts": [],
            }
            if service_node is not None:
                details.update(
                    {
                        "service": service_node.get("name"),
                        "product": service_node.get("product"),
                        "version": service_node.get("version"),
                        "extra": service_node.get("extrainfo"),
                        "device_type": service_node.get("devicetype"),
                        "os_type": service_node.get("ostype"),
                    }
                )
            details["scripts"] = [
                {"name": script.get("id"), "output": script.get("output")}
                for script in port_node.findall("script")
                if script.get("output")
            ]
            if not details["service"]:
                try:
                    details["service"] = socket.getservbyport(port, protocol)
                except OSError:
                    details["service"] = "unknown"
            if port == 6053:
                details["service"] = "esphome-api"
                details["product"] = details["product"] or "ESPHome native API"
            results.append(details)

        results.sort(key=lambda item: (item["protocol"], item["port"]))
        scanned_at = utc_now()
        os_hint = None
        os_match = root.find(".//osmatch")
        if os_match is not None:
            os_hint = os_match.get("name")
            if os_match.get("accuracy"):
                os_hint = f"{os_hint} ({os_match.get('accuracy')}% match)"

        identity = None
        if deep:
            current = row_to_dict(row)
            if not current.get("manufacturer") and not current.get("is_private_mac"):
                try:
                    vendor = lookup_mac_vendor_value(current["mac"])
                    current["manufacturer"] = vendor
                    current["online_lookup"] = vendor
                    with db_connection() as conn:
                        conn.execute(
                            "UPDATE devices SET manufacturer=?, online_lookup=?, online_lookup_at=? WHERE id=?",
                            (vendor, vendor, scanned_at, device_id),
                        )
                except (requests.RequestException, RuntimeError):
                    pass
            if any(item["port"] == 6053 for item in results):
                try:
                    mdns_info = discover_esphome_mdns(ip)
                except Exception:  # mDNS enrichment must not make the port scan fail.
                    mdns_info = {}
                mdns_name = (
                    mdns_info.get("friendly_name")
                    or mdns_info.get("service_name")
                    or mdns_info.get("server")
                )
                with db_connection() as conn:
                    conn.execute(
                        "UPDATE devices SET mdns_name=?, mdns_info=?, mdns_scanned_at=? WHERE id=?",
                        (mdns_name, json.dumps(mdns_info), scanned_at, device_id),
                    )
            if ha_service.connected():
                try:
                    ha_service.sync()
                except Exception:  # Home Assistant enrichment is optional during a scan.
                    pass
            if eero_service.authenticated():
                try:
                    eero_service.sync()
                except Exception:  # eero enrichment is optional during a scan.
                    pass
            with db_connection() as conn:
                current = row_to_dict(conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone())
            if any(item["port"] == 6053 for item in results) and not current.get("ha_device_id"):
                api_result = probe_esphome_api(ip)
                with db_connection() as conn:
                    conn.execute(
                        "UPDATE devices SET esphome_api_status=?, esphome_device_info=?, esphome_entities=? WHERE id=?",
                        (
                            api_result["status"], json.dumps(api_result["device"]),
                            json.dumps(api_result["entities"]), device_id,
                        ),
                    )
                    current = row_to_dict(conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone())
            identity = identify_device(current, results, os_hint)
        with db_connection() as conn:
            if deep:
                conn.execute(
                    """UPDATE devices SET open_ports=?, ports_scanned_at=?, ports_scan_error=NULL,
                       device_identity=?, identity_confidence=?, identity_summary=?, identity_evidence=?,
                       os_hint=?, deep_scanned_at=?, deep_scan_error=NULL, updated_at=? WHERE id=?""",
                    (
                        json.dumps(results), scanned_at, identity["device_identity"],
                        identity["identity_confidence"], identity["identity_summary"],
                        json.dumps(identity["identity_evidence"]), os_hint, scanned_at, scanned_at, device_id,
                    ),
                )
            else:
                conn.execute(
                    "UPDATE devices SET open_ports=?, ports_scanned_at=?, ports_scan_error=NULL, updated_at=? WHERE id=?",
                    (json.dumps(results), scanned_at, scanned_at, device_id),
                )
        return {
            "ok": True,
            "message": f"Found {len(results)} open TCP port{'s' if len(results) != 1 else ''}.",
            "ports": results,
            "scanned_at": scanned_at,
            "ports_checked": len(ports),
            "identity": identity,
            "os_hint": os_hint,
        }, 200
    except (subprocess.TimeoutExpired, ElementTree.ParseError, RuntimeError) as exc:
        message = "The port scan timed out." if isinstance(exc, subprocess.TimeoutExpired) else str(exc)
        with db_connection() as conn:
            conn.execute(
                "UPDATE devices SET ports_scan_error=?, ports_scanned_at=?, deep_scan_error=CASE WHEN ? THEN ? ELSE deep_scan_error END, updated_at=? WHERE id=?",
                (message, utc_now(), 1 if deep else 0, message, utc_now(), device_id),
            )
        return {"ok": False, "message": message}, 502
    finally:
        port_scan_lock.release()


def unwrap_list(response, keys):
    data = response.get("data", response) if isinstance(response, dict) else response
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def value_at(item, *paths):
    for path in paths:
        value = item
        for part in path.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        if value not in (None, ""):
            return value
    return None


class EeroService:
    def __init__(self):
        self.available = EeroClient is not None
        self.loop = None
        self.client = None
        self.thread = None
        if self.available:
            self.loop = asyncio.new_event_loop()
            self.thread = threading.Thread(target=self._run_loop, daemon=True)
            self.thread.start()
            self.run(self._initialize())

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def _initialize(self):
        self.client = EeroClient(cookie_file=str(EERO_COOKIE_PATH), use_keyring=False, cache_timeout=10)
        await self.client.__aenter__()

    def run(self, coroutine, timeout=90):
        if not self.available:
            raise RuntimeError("The eero integration is not installed.")
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop).result(timeout=timeout)

    def authenticated(self):
        return bool(self.available and self.client and self.client.is_authenticated)

    def login(self, identifier):
        return self.run(self.client.login(identifier))

    def verify(self, code):
        return self.run(self.client.verify(code))

    def logout(self):
        return self.run(self.client.logout())

    def sync(self):
        return self.run(self._sync())

    async def _network_id(self):
        configured = get_setting("eero_network_id")
        if configured:
            return configured
        response = await self.client.get_networks(refresh_cache=True)
        networks = unwrap_list(response, ("networks", "data"))
        if not networks:
            raise RuntimeError("No eero network was returned for this account.")
        network = networks[0]
        network_id = network.get("id")
        if not network_id and network.get("url"):
            network_id = network["url"].rstrip("/").split("/")[-1]
        if not network_id:
            raise RuntimeError("Could not determine the eero network ID.")
        set_setting("eero_network_id", str(network_id))
        set_setting("eero_network_name", str(network.get("name") or "eero network"))
        return str(network_id)

    async def _sync(self):
        network_id = await self._network_id()
        devices_response, reservations_response = await asyncio.gather(
            self.client.get_devices(network_id, refresh_cache=True),
            self.client.get_reservations(network_id),
        )
        devices = unwrap_list(devices_response, ("devices", "clients", "data"))
        reservations = unwrap_list(reservations_response, ("reservations", "data"))

        with db_connection() as conn:
            conn.execute(
                "UPDATE devices SET reserved_ip=NULL, reservation_id=NULL, eero_reservation_name=NULL"
            )

        reservation_by_mac = {}
        for reservation in reservations:
            mac = normalize_mac(value_at(reservation, "mac", "mac_address", "device.mac"))
            if mac:
                reservation_by_mac[mac] = reservation

        for item in devices:
            mac = normalize_mac(value_at(item, "mac", "mac_address"))
            if not mac:
                continue
            device_url = value_at(item, "url")
            device_id = value_at(item, "id") or (
                str(device_url).rstrip("/").split("/")[-1] if device_url else None
            )
            source = item.get("source") if isinstance(item.get("source"), dict) else {}
            connected = value_at(item, "connected", "online")
            eero_last_seen = normalize_timestamp(value_at(
                item,
                "last_active", "last_active_at", "last_seen", "last_seen_at",
                "last_connected", "last_connected_at", "connectivity.last_active",
                "connectivity.last_seen",
            ))
            reservation = reservation_by_mac.get(mac)
            reservation_name = value_at(reservation or {}, "name", "nickname", "display_name", "description")
            info = {
                "mac": mac,
                "ip": value_at(item, "ip", "ip_address", "ipv4", "ipv4_address"),
                "hostname": value_at(item, "hostname"),
                "eero_name": value_at(item, "nickname", "display_name", "name"),
                "eero_hostname": value_at(item, "hostname"),
                "eero_device_id": device_id,
                "eero_reservation_name": reservation_name,
                "manufacturer": value_at(item, "manufacturer", "vendor"),
                "online": True if connected is None else bool(connected),
                "last_seen": eero_last_seen,
                "connection_type": value_at(item, "connection_type", "connection"),
                "frequency": value_at(item, "frequency", "frequency_band"),
                "eero_node": value_at(item, "source.location", "eero.location", "connected_eero"),
                "signal": value_at(item, "signal", "signal_strength", "connectivity.signal"),
            }
            upsert_discovered_device(info, "eero")

            if reservation:
                reservation_url = value_at(reservation, "url")
                reservation_id = value_at(reservation, "id") or (
                    str(reservation_url).rstrip("/").split("/")[-1] if reservation_url else None
                )
                reserved_ip = value_at(reservation, "ip", "ip_address")
                with db_connection() as conn:
                    conn.execute(
                        "UPDATE devices SET reserved_ip=?, reservation_id=?, eero_reservation_name=?, updated_at=? WHERE mac=?",
                        (reserved_ip, reservation_id, reservation_name, utc_now(), mac),
                    )

        # Retain reservations for devices currently absent from eero's connected-device list.
        for mac, reservation in reservation_by_mac.items():
            with db_connection() as conn:
                existing = conn.execute("SELECT id FROM devices WHERE mac=?", (mac,)).fetchone()
            if not existing:
                upsert_discovered_device(
                    {
                        "mac": mac,
                        "ip": value_at(reservation, "ip", "ip_address"),
                        "eero_reservation_name": value_at(reservation, "name", "nickname", "display_name", "description"),
                        "online": False,
                    },
                    "eero",
                )
            reservation_url = value_at(reservation, "url")
            reservation_id = value_at(reservation, "id") or (
                str(reservation_url).rstrip("/").split("/")[-1] if reservation_url else None
            )
            with db_connection() as conn:
                conn.execute(
                    "UPDATE devices SET reserved_ip=?, reservation_id=?, eero_reservation_name=?, updated_at=? WHERE mac=?",
                    (
                        value_at(reservation, "ip", "ip_address"),
                        reservation_id,
                        value_at(reservation, "name", "nickname", "display_name", "description"),
                        utc_now(),
                        mac,
                    ),
                )

        set_setting("last_eero_sync", utc_now())
        return {"devices": len(devices), "reservations": len(reservations)}

    def reserve(self, device, ip):
        return self.run(self._reserve(device, ip))

    async def _reserve(self, device, ip):
        network_id = await self._network_id()
        payload = {
            "ip": ip,
            "mac": device["mac"],
            "name": device.get("friendly_name") or device.get("eero_name") or device.get("hostname") or device["mac"],
        }
        if device.get("reservation_id"):
            response = await self.client.update_reservation(
                device["reservation_id"], payload, network_id=network_id
            )
        else:
            response = await self.client.create_reservation(payload, network_id=network_id)
        await self._sync()
        return response


class HomeAssistantService:
    """Read-only Home Assistant inventory access using a user-provided token."""

    def connected(self):
        return HA_TOKEN_PATH.exists() and bool(get_setting("ha_url"))

    def _token(self):
        try:
            return HA_TOKEN_PATH.read_text().strip()
        except OSError:
            return ""

    def validate_url(self, value):
        parsed = urlparse(str(value or "").strip().rstrip("/"))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError("Enter a complete Home Assistant URL beginning with http:// or https://.")
        try:
            addresses = {ipaddress.ip_address(parsed.hostname)}
        except ValueError:
            try:
                addresses = {
                    ipaddress.ip_address(item[4][0])
                    for item in socket.getaddrinfo(parsed.hostname, parsed.port or 8123, type=socket.SOCK_STREAM)
                }
            except (socket.gaierror, ValueError, OSError) as exc:
                raise RuntimeError("The Home Assistant address could not be resolved.") from exc
        network = ipaddress.ip_network(NETWORK_CIDR, strict=False)
        if not addresses or any(address not in network for address in addresses):
            raise RuntimeError(f"Home Assistant must be inside {NETWORK_CIDR}.")
        return f"{parsed.scheme}://{parsed.netloc}"

    def headers(self, token=None):
        return {
            "Authorization": f"Bearer {token or self._token()}",
            "Content-Type": "application/json",
        }

    def connect(self, url, token):
        clean_url = self.validate_url(url)
        token = str(token or "").strip()
        if not token:
            raise RuntimeError("Enter a Home Assistant long-lived access token.")
        response = requests.get(f"{clean_url}/api/", headers=self.headers(token), timeout=12)
        if response.status_code == 401:
            raise RuntimeError("Home Assistant did not accept that access token.")
        response.raise_for_status()
        HA_TOKEN_PATH.write_text(token)
        os.chmod(HA_TOKEN_PATH, 0o600)
        set_setting("ha_url", clean_url)
        try:
            return self.sync()
        except Exception:
            HA_TOKEN_PATH.unlink(missing_ok=True)
            set_setting("ha_url", "")
            raise

    def disconnect(self):
        try:
            HA_TOKEN_PATH.unlink(missing_ok=True)
        finally:
            set_setting("ha_url", "")

    def _websocket_lists(self):
        base_url = self.validate_url(get_setting("ha_url"))
        parsed = urlparse(base_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws = websocket.create_connection(f"{ws_scheme}://{parsed.netloc}/api/websocket", timeout=20)
        try:
            hello = json.loads(ws.recv())
            if hello.get("type") != "auth_required":
                raise RuntimeError("Home Assistant returned an unexpected WebSocket greeting.")
            ws.send(json.dumps({"type": "auth", "access_token": self._token()}))
            auth = json.loads(ws.recv())
            if auth.get("type") != "auth_ok":
                raise RuntimeError("Home Assistant WebSocket authentication failed.")
            requests_by_id = {
                1: "config/device_registry/list",
                2: "config/entity_registry/list",
                3: "config/area_registry/list",
            }
            for request_id, request_type in requests_by_id.items():
                ws.send(json.dumps({"id": request_id, "type": request_type}))
            results = {}
            while len(results) < len(requests_by_id):
                message = json.loads(ws.recv())
                request_id = message.get("id")
                if request_id not in requests_by_id:
                    continue
                if not message.get("success"):
                    raise RuntimeError(f"Home Assistant could not provide {requests_by_id[request_id]}.")
                results[request_id] = message.get("result") or []
            return results[1], results[2], results[3]
        finally:
            ws.close()

    def sync(self):
        if not self.connected():
            raise RuntimeError("Connect Home Assistant first.")
        try:
            devices, entities, areas = self._websocket_lists()
            base_url = self.validate_url(get_setting("ha_url"))
            response = requests.get(f"{base_url}/api/states", headers=self.headers(), timeout=20)
            response.raise_for_status()
            states = {item.get("entity_id"): item for item in response.json()}
            area_names = {item.get("area_id"): item.get("name") for item in areas}
            entities_by_device = {}
            for entity in entities:
                device_id = entity.get("device_id")
                if not device_id or entity.get("disabled_by"):
                    continue
                state = states.get(entity.get("entity_id"), {})
                attributes = state.get("attributes") or {}
                entities_by_device.setdefault(device_id, []).append(
                    {
                        "entity_id": entity.get("entity_id"),
                        "name": attributes.get("friendly_name") or entity.get("name") or entity.get("original_name"),
                        "state": state.get("state"),
                        "unit": attributes.get("unit_of_measurement"),
                        "device_class": attributes.get("device_class"),
                    }
                )

            by_mac = {}
            for device in devices:
                candidates = []
                for pair in (device.get("connections") or []) + (device.get("identifiers") or []):
                    if not isinstance(pair, (list, tuple)) or len(pair) < 2:
                        continue
                    kind, value = str(pair[0]).lower(), pair[1]
                    if kind in {"mac", "esphome"}:
                        mac = normalize_mac(value)
                        if mac:
                            candidates.append(mac)
                for mac in candidates:
                    by_mac[mac] = device

            now = utc_now()
            matched = 0
            with db_connection() as conn:
                conn.execute(
                    """UPDATE devices SET ha_device_id=NULL, ha_name=NULL, ha_model=NULL,
                       ha_manufacturer=NULL, ha_sw_version=NULL, ha_area=NULL, ha_entities=NULL"""
                )
                local_devices = conn.execute("SELECT id, mac FROM devices").fetchall()
                for local in local_devices:
                    device = by_mac.get(local["mac"])
                    if not device:
                        continue
                    matched += 1
                    device_id = device.get("id")
                    entity_list = entities_by_device.get(device_id, [])
                    entity_list.sort(key=lambda item: item.get("entity_id") or "")
                    conn.execute(
                        """UPDATE devices SET ha_device_id=?, ha_name=?, ha_model=?, ha_manufacturer=?,
                           ha_sw_version=?, ha_area=?, ha_entities=?, ha_synced_at=?, updated_at=? WHERE id=?""",
                        (
                            device_id,
                            device.get("name_by_user") or device.get("name"),
                            device.get("model"),
                            device.get("manufacturer"),
                            device.get("sw_version"),
                            area_names.get(device.get("area_id")),
                            json.dumps(entity_list),
                            now,
                            now,
                            local["id"],
                        ),
                    )
            set_setting("last_ha_sync", now)
            set_setting("last_ha_sync_error", "")
            return {"matched": matched, "ha_devices": len(devices)}
        except Exception as exc:
            set_setting("last_ha_sync_error", str(exc))
            raise


DNS_SIGNATURES = (
    ("Amazon Echo / Alexa device", ("device-metrics-us.amazon.com", "alexa.amazon.com", "dp-gw-na.amazon.com", "amazonalexa.com"), 8),
    ("Ring camera or doorbell", ("ring.com", "ring.devices.a2z.com"), 9),
    ("Roku streaming device", ("roku.com", "rokutime.com", "sr.roku.com"), 9),
    ("Google Nest / Chromecast device", ("googlehomefoyer-pa.googleapis.com", "cast.google.com", "clients3.google.com"), 7),
    ("Tuya / Smart Life device", ("tuyaus.com", "tuya.com", "tuyaeu.com", "tuya-inc.com"), 9),
    ("TP-Link Kasa / Tapo device", ("tplinkcloud.com", "kasa-smart.com", "tapo.com"), 9),
    ("Reolink camera or NVR", ("reolink.com", "reolinkcloud.com"), 10),
    ("Eufy security device", ("eufylife.com", "eufy.com", "anker-in.com"), 8),
    ("Wyze smart-home device", ("wyze.com", "wyzeapi.com"), 10),
    ("ecobee thermostat", ("ecobee.com",), 10),
    ("Tesla energy or vehicle device", ("tesla.com", "teslamotors.com"), 8),
    ("Synology NAS or service", ("synology.com", "synology.me"), 9),
    ("Sonos speaker", ("sonos.com", "sonos.radio"), 10),
    ("Philips Hue device", ("meethue.com", "philips-hue.com"), 10),
    ("Samsung / SmartThings device", ("smartthings.com", "samsungiotcloud.com", "samsungcloud.com"), 8),
    ("Ubiquiti network device", ("ui.com", "ubnt.com"), 8),
    ("NETGEAR network device", ("netgear.com", "orbilogin.com"), 8),
    ("BirdNET / BirdWeather monitor", ("birdweather.com", "birdnet.cornell.edu", "birdnetpi.com"), 10),
)


def domain_matches(domain, suffix):
    domain = str(domain or "").lower().rstrip(".")
    suffix = suffix.lower().rstrip(".")
    return domain == suffix or domain.endswith("." + suffix)


class PiHoleService:
    """Read-only access to one or more Pi-hole v6 query-history APIs."""

    def connected(self):
        return bool(self.config())

    def config(self):
        try:
            value = json.loads(PIHOLE_CONFIG_PATH.read_text())
            return value if isinstance(value, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def public_sources(self):
        return [{"name": item["name"], "url": item["url"]} for item in self.config()]

    def validate_url(self, value):
        clean = str(value or "").strip().rstrip("/")
        for suffix in ("/admin", "/api"):
            if clean.lower().endswith(suffix):
                clean = clean[:-len(suffix)].rstrip("/")
        parsed = urlparse(clean)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError("Enter a complete Pi-hole URL beginning with http:// or https://.")
        try:
            addresses = {ipaddress.ip_address(parsed.hostname)}
        except ValueError:
            try:
                addresses = {
                    ipaddress.ip_address(item[4][0])
                    for item in socket.getaddrinfo(parsed.hostname, parsed.port or 80, type=socket.SOCK_STREAM)
                }
            except (socket.gaierror, ValueError, OSError) as exc:
                raise RuntimeError("The Pi-hole address could not be resolved.") from exc
        network = ipaddress.ip_network(NETWORK_CIDR, strict=False)
        if not addresses or any(address not in network for address in addresses):
            raise RuntimeError(f"Pi-hole must be inside {NETWORK_CIDR}.")
        return f"{parsed.scheme}://{parsed.netloc}"

    def _session(self, source):
        session = requests.Session()
        response = session.post(
            f"{source['url']}/api/auth",
            json={"password": source["password"]},
            timeout=15,
        )
        if response.status_code == 401:
            raise RuntimeError(f"{source['name']} did not accept its application password.")
        response.raise_for_status()
        sid = (response.json().get("session") or {}).get("sid")
        if not sid:
            raise RuntimeError(f"{source['name']} did not return an authenticated session.")
        session.headers.update({"X-FTL-SID": sid})
        return session

    def test_source(self, source):
        session = self._session(source)
        try:
            response = session.get(f"{source['url']}/api/queries", params={"length": 1}, timeout=20)
            response.raise_for_status()
            return True
        finally:
            try:
                session.delete(f"{source['url']}/api/auth", timeout=5)
            except requests.RequestException:
                pass
            session.close()

    def connect(self, raw_sources):
        sources = []
        for index, item in enumerate(raw_sources or [], start=1):
            url = str((item or {}).get("url") or "").strip()
            password = str((item or {}).get("password") or "").strip()
            if not url and not password:
                continue
            if not url or not password:
                raise RuntimeError(f"Enter both the URL and application password for DNS{index}.")
            sources.append({
                "name": str((item or {}).get("name") or f"DNS{index}").strip()[:40],
                "url": self.validate_url(url),
                "password": password,
            })
        if not sources:
            raise RuntimeError("Enter at least one Pi-hole connection.")
        for source in sources:
            self.test_source(source)
        PIHOLE_CONFIG_PATH.write_text(json.dumps(sources))
        os.chmod(PIHOLE_CONFIG_PATH, 0o600)
        set_setting("last_pihole_test", utc_now())
        set_setting("last_pihole_error", "")
        return self.public_sources()

    def test(self):
        sources = self.config()
        if not sources:
            raise RuntimeError("Connect Pi-hole first.")
        for source in sources:
            self.test_source(source)
        set_setting("last_pihole_test", utc_now())
        set_setting("last_pihole_error", "")
        return self.public_sources()

    def disconnect(self):
        PIHOLE_CONFIG_PATH.unlink(missing_ok=True)

    def queries(self, source, client_ip, started, ended, maximum=50000):
        session = self._session(source)
        collected = []
        cursor = None
        try:
            while len(collected) < maximum:
                params = {
                    "client_ip": client_ip,
                    "from": int(started),
                    "until": int(ended),
                    "length": min(10000, maximum - len(collected)),
                    "disk": "true",
                }
                if cursor is not None:
                    params["cursor"] = cursor
                response = session.get(f"{source['url']}/api/queries", params=params, timeout=45)
                response.raise_for_status()
                data = response.json()
                page = data.get("queries") or data.get("data") or []
                if not isinstance(page, list):
                    page = []
                collected.extend(page)
                new_cursor = data.get("cursor")
                if not page or not new_cursor or new_cursor == cursor or len(page) < params["length"]:
                    break
                cursor = new_cursor
            return collected[:maximum], len(collected) >= maximum
        finally:
            try:
                session.delete(f"{source['url']}/api/auth", timeout=5)
            except requests.RequestException:
                pass
            session.close()


def analyze_dns_queries(queries, source_counts, truncated=False):
    domain_counts = Counter()
    blocked_counts = Counter()
    domain_sources = defaultdict(set)
    domain_times = defaultdict(list)
    for item in queries:
        domain = str(item.get("domain") or "").lower().rstrip(".")
        if not domain:
            continue
        sources = item.get("_sources") or [item.get("_source") or "Pi-hole"]
        domain_counts[domain] += 1
        domain_sources[domain].update(str(source) for source in sources)
        status = str(item.get("status") or "").lower()
        if any(token in status for token in ("block", "gravity", "deny", "regex")):
            blocked_counts[domain] += 1
        try:
            domain_times[domain].append(float(item.get("time")))
        except (TypeError, ValueError):
            pass

    top_domains = [
        {
            "domain": domain,
            "count": count,
            "blocked": blocked_counts[domain],
            "sources": sorted(domain_sources[domain]),
        }
        for domain, count in domain_counts.most_common(25)
    ]
    score = Counter()
    matched = defaultdict(list)
    for identity, patterns, weight in DNS_SIGNATURES:
        for domain, count in domain_counts.items():
            if any(domain_matches(domain, pattern) for pattern in patterns):
                score[identity] += weight * min(count, 8)
                matched[identity].append((domain, count))

    periodic = []
    for domain, timestamps in domain_times.items():
        values = sorted(set(timestamps))
        if len(values) < 5:
            continue
        gaps = [later - earlier for earlier, later in zip(values, values[1:]) if later > earlier]
        if len(gaps) < 4:
            continue
        midpoint = median(gaps)
        deviation = median(abs(gap - midpoint) for gap in gaps)
        if 30 <= midpoint <= 86400 and deviation <= max(5, midpoint * .18):
            periodic.append((domain, midpoint, len(values)))
    periodic.sort(key=lambda item: item[2], reverse=True)

    evidence = []
    identity = "No distinctive DNS identity found"
    confidence = "low"
    if score:
        identity, best_score = score.most_common(1)[0]
        second_score = score.most_common(2)[1][1] if len(score) > 1 else 0
        confidence = "high" if best_score >= 30 and best_score >= second_score * 1.5 else "medium"
        for domain, count in sorted(matched[identity], key=lambda item: item[1], reverse=True)[:6]:
            evidence.append(f"{domain} was requested {count:,} time{'s' if count != 1 else ''}.")
        summary = f"DNS destinations strongly resemble a {identity}. This is a hypothesis based on domain patterns, not proof of the exact model."
    elif not queries:
        summary = "Neither Pi-hole returned DNS queries attributed to this device's known IP addresses during the selected period."
        evidence.append("The device may have been offline, may use encrypted DNS, or its traffic may appear under a router or access point instead.")
    else:
        unique = len(domain_counts)
        if periodic and unique <= 25:
            identity = "Likely always-on IoT or appliance device"
            confidence = "low"
            summary = "The DNS pattern is narrow and repetitive, which is common for an always-on appliance, sensor, or embedded device, but no vendor-specific destination was conclusive."
        else:
            summary = "The observed DNS traffic does not contain a distinctive enough vendor or service pattern for a reliable identity hypothesis."
        if top_domains:
            evidence.append("Most-requested domains: " + ", ".join(item["domain"] for item in top_domains[:5]) + ".")
    if periodic:
        domain, seconds, samples = periodic[0]
        evidence.append(f"{domain} shows a regular heartbeat about every {round(seconds / 60, 1):g} minutes across {samples} requests.")
    if truncated:
        evidence.append("At least one Pi-hole result reached the safety limit, so counts may be incomplete.")
    return {
        "identity": identity,
        "confidence": confidence,
        "summary": summary,
        "evidence": evidence,
        "domains": top_domains,
        "query_count": sum(domain_counts.values()),
        "unique_domains": len(domain_counts),
        "source_summary": source_counts,
    }


def analyze_device_dns(device_id, hours):
    if hours not in {1, 24, 168, 720}:
        raise RuntimeError("Choose a DNS history period of 1 hour, 24 hours, 7 days, or 30 days.")
    if not pihole_service.connected():
        raise RuntimeError("Connect at least one Pi-hole first.")
    with db_connection() as conn:
        device = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not device:
            raise LookupError("Device not found.")
        history = conn.execute(
            "SELECT ip, first_seen, last_seen FROM device_ip_history WHERE device_id=? ORDER BY last_seen DESC",
            (device_id,),
        ).fetchall()
    ended = time.time()
    started = ended - hours * 3600
    ips = []
    for value in (device["ip"], device["reserved_ip"]):
        if value and value not in ips:
            ips.append(value)
    for row in history:
        try:
            last_seen = datetime.fromisoformat(str(row["last_seen"]).replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError):
            last_seen = ended
        if last_seen >= started and row["ip"] not in ips:
            ips.append(row["ip"])
    if not ips:
        raise RuntimeError("This device has no IP address observed during the selected period.")
    merged = {}
    source_counts = []
    any_truncated = False
    for source in pihole_service.config():
        source_keys = set()
        source_truncated = False
        source_error = None
        try:
            for client_ip in ips:
                rows, truncated = pihole_service.queries(source, client_ip, started, ended)
                source_truncated = source_truncated or truncated
                for item in rows:
                    item = dict(item)
                    item["_source"] = source["name"]
                    key = (
                        round(float(item.get("time") or 0), 3),
                        str(item.get("domain") or "").lower(),
                        str(item.get("type") or ""),
                        str((item.get("client") or {}).get("ip") if isinstance(item.get("client"), dict) else item.get("client") or client_ip),
                    )
                    source_keys.add(key)
                    if key in merged:
                        merged[key].setdefault("_sources", []).append(source["name"])
                        merged[key]["_sources"] = sorted(set(merged[key]["_sources"]))
                    else:
                        item["_sources"] = [source["name"]]
                        merged[key] = item
        except (requests.RequestException, RuntimeError, ValueError) as exc:
            source_error = str(exc)
        any_truncated = any_truncated or source_truncated
        source_counts.append({"name": source["name"], "count": len(source_keys), "error": source_error, "truncated": source_truncated})
    if all(item["error"] for item in source_counts):
        raise RuntimeError("Neither Pi-hole could be queried: " + "; ".join(f"{item['name']}: {item['error']}" for item in source_counts))
    report = analyze_dns_queries(list(merged.values()), source_counts, any_truncated)
    now = utc_now()
    with db_connection() as conn:
        conn.execute(
            """UPDATE devices SET dns_identity=?, dns_confidence=?, dns_summary=?, dns_evidence=?,
               dns_domains=?, dns_source_summary=?, dns_scanned_at=?, dns_scan_error=NULL,
               dns_lookback_hours=?, dns_query_count=?, updated_at=? WHERE id=?""",
            (
                report["identity"], report["confidence"], report["summary"], json.dumps(report["evidence"]),
                json.dumps(report["domains"]), json.dumps(report["source_summary"]), now, hours,
                report["query_count"], now, device_id,
            ),
        )
    return report


init_db()
eero_service = EeroService()
ha_service = HomeAssistantService()
pihole_service = PiHoleService()


@app.get("/")
def index():
    return render_template("index.html", network_cidr=NETWORK_CIDR)


@app.get("/api/devices")
def devices():
    with db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM devices ORDER BY online DESC, COALESCE(friendly_name, ha_name, eero_reservation_name, eero_name, eero_hostname, hostname, mac) COLLATE NOCASE"
        ).fetchall()
    return jsonify({"devices": [row_to_dict(row) for row in rows], "status": status_payload()})


def status_payload():
    return {
        "network_cidr": NETWORK_CIDR,
        "last_lan_scan": get_setting("last_lan_scan"),
        "last_lan_scan_count": get_setting("last_lan_scan_count"),
        "last_lan_scan_error": get_setting("last_lan_scan_error"),
        "eero_available": eero_service.available,
        "eero_connected": eero_service.authenticated(),
        "eero_network_name": get_setting("eero_network_name"),
        "last_eero_sync": get_setting("last_eero_sync"),
        "ha_connected": ha_service.connected(),
        "ha_url": get_setting("ha_url") or "http://homeassistant.local:8123",
        "last_ha_sync": get_setting("last_ha_sync"),
        "last_ha_sync_error": get_setting("last_ha_sync_error"),
        "pihole_connected": pihole_service.connected(),
        "pihole_sources": pihole_service.public_sources(),
        "last_pihole_test": get_setting("last_pihole_test"),
        "last_pihole_error": get_setting("last_pihole_error"),
    }


@app.post("/api/scan")
def start_scan():
    result = scan_network()
    return jsonify(result), 200 if result["ok"] else 500


@app.put("/api/devices/<int:device_id>")
def update_device(device_id):
    payload = request.get_json(silent=True) or {}
    allowed = ("friendly_name", "device_type", "location", "notes")
    values = [str(payload.get(key, "")).strip() or None for key in allowed]
    with db_connection() as conn:
        result = conn.execute(
            "UPDATE devices SET friendly_name=?, device_type=?, location=?, notes=?, updated_at=? WHERE id=?",
            (*values, utc_now(), device_id),
        )
        if not result.rowcount:
            return jsonify({"ok": False, "message": "Device not found."}), 404
        row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    return jsonify({"ok": True, "device": row_to_dict(row)})


@app.post("/api/devices/manual")
def add_manual_device():
    payload = request.get_json(silent=True) or {}
    mac = normalize_mac(payload.get("mac"))
    if not mac:
        return jsonify({"ok": False, "message": "Enter a valid MAC address."}), 400
    ip = str(payload.get("ip") or "").strip() or None
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"ok": False, "message": "Enter a valid IP address."}), 400
    upsert_discovered_device(
        {"mac": mac, "ip": ip, "hostname": payload.get("hostname"), "online": False},
        "manual",
    )
    with db_connection() as conn:
        row = conn.execute("SELECT id FROM devices WHERE mac=?", (mac,)).fetchone()
    return update_device(row["id"])


@app.post("/api/devices/<int:device_id>/mac-lookup")
def mac_lookup(device_id):
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if not row:
        return jsonify({"ok": False, "message": "Device not found."}), 404
    mac = row["mac"]
    if private_mac(mac):
        return jsonify(
            {"ok": False, "message": "This is a private/randomized MAC address; no public manufacturer is encoded in it."}
        ), 400
    try:
        vendor = lookup_mac_vendor_value(mac)
        now = utc_now()
        with db_connection() as conn:
            conn.execute(
                "UPDATE devices SET online_lookup=?, online_lookup_at=?, manufacturer=COALESCE(manufacturer, ?), updated_at=? WHERE id=?",
                (vendor, now, vendor, now, device_id),
            )
        return jsonify({"ok": True, "vendor": vendor, "looked_up_at": now})
    except (requests.RequestException, RuntimeError) as exc:
        return jsonify({"ok": False, "message": str(exc)}), 502


@app.post("/api/devices/<int:device_id>/ports/scan")
def port_scan(device_id):
    result, status = scan_device_ports(device_id)
    return jsonify(result), status


@app.post("/api/devices/<int:device_id>/deep-scan")
def deep_scan(device_id):
    result, status = scan_device_ports(device_id, deep=True)
    return jsonify(result), status


@app.post("/api/devices/<int:device_id>/dns-analysis")
def dns_analysis(device_id):
    payload = request.get_json(silent=True) or {}
    try:
        hours = int(payload.get("hours", 24))
        report = analyze_device_dns(device_id, hours)
        return jsonify({
            "ok": True,
            "message": f"Analyzed {report['query_count']:,} DNS requests across {report['unique_domains']:,} domains.",
            "report": report,
        })
    except LookupError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 404
    except (requests.RequestException, RuntimeError, ValueError) as exc:
        message = str(exc)
        with db_connection() as conn:
            conn.execute(
                "UPDATE devices SET dns_scan_error=?, updated_at=? WHERE id=?",
                (message, utc_now(), device_id),
            )
        return jsonify({"ok": False, "message": message}), 502


@app.post("/api/pihole/connect")
def pihole_connect():
    payload = request.get_json(silent=True) or {}
    try:
        sources = pihole_service.connect(payload.get("sources"))
        return jsonify({"ok": True, "message": f"Connected and tested {len(sources)} Pi-hole server{'s' if len(sources) != 1 else ''}.", "sources": sources})
    except (requests.RequestException, OSError, RuntimeError, ValueError) as exc:
        set_setting("last_pihole_error", str(exc))
        return jsonify({"ok": False, "message": str(exc)}), 502


@app.post("/api/pihole/test")
def pihole_test():
    try:
        sources = pihole_service.test()
        return jsonify({"ok": True, "message": f"Both Pi-hole connections are working." if len(sources) == 2 else "The Pi-hole connection is working.", "sources": sources})
    except (requests.RequestException, OSError, RuntimeError) as exc:
        set_setting("last_pihole_error", str(exc))
        return jsonify({"ok": False, "message": str(exc)}), 502


@app.post("/api/pihole/disconnect")
def pihole_disconnect():
    pihole_service.disconnect()
    return jsonify({"ok": True, "message": "Pi-hole disconnected. Saved DNS reports were retained."})


@app.post("/api/home-assistant/connect")
def home_assistant_connect():
    payload = request.get_json(silent=True) or {}
    try:
        counts = ha_service.connect(payload.get("url"), payload.get("token"))
        return jsonify({
            "ok": True,
            "message": f"Home Assistant connected. Matched {counts['matched']} network devices.",
            **counts,
        })
    except (requests.RequestException, OSError, RuntimeError, websocket.WebSocketException) as exc:
        return jsonify({"ok": False, "message": str(exc)}), 502


@app.post("/api/home-assistant/sync")
def home_assistant_sync():
    try:
        counts = ha_service.sync()
        return jsonify({
            "ok": True,
            "message": f"Matched {counts['matched']} devices with Home Assistant.",
            **counts,
        })
    except (requests.RequestException, OSError, RuntimeError, websocket.WebSocketException) as exc:
        return jsonify({"ok": False, "message": str(exc)}), 502


@app.post("/api/home-assistant/disconnect")
def home_assistant_disconnect():
    ha_service.disconnect()
    return jsonify({"ok": True, "message": "Home Assistant disconnected. Imported device details were retained."})


@app.get("/api/eero/status")
def eero_status():
    return jsonify(status_payload())


@app.post("/api/eero/login")
def eero_login():
    identifier = str((request.get_json(silent=True) or {}).get("identifier") or "").strip()
    if not identifier:
        return jsonify({"ok": False, "message": "Enter the email address or phone number used by eero."}), 400
    try:
        ok = eero_service.login(identifier)
        return jsonify({"ok": bool(ok), "message": "Verification code sent." if ok else "eero did not accept the login request."})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 502


@app.post("/api/eero/verify")
def eero_verify():
    code = str((request.get_json(silent=True) or {}).get("code") or "").strip()
    if not code:
        return jsonify({"ok": False, "message": "Enter the verification code from eero."}), 400
    try:
        ok = eero_service.verify(code)
        if ok:
            eero_service.sync()
        return jsonify({"ok": bool(ok), "message": "eero connected." if ok else "The verification code was not accepted."})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 502


@app.post("/api/eero/sync")
def eero_sync():
    if not eero_service.authenticated():
        return jsonify({"ok": False, "message": "Connect the site to eero first."}), 401
    try:
        counts = eero_service.sync()
        return jsonify({"ok": True, "message": f"Imported {counts['devices']} eero devices and {counts['reservations']} reservations.", **counts})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 502


@app.post("/api/eero/logout")
def eero_logout():
    try:
        eero_service.logout()
        return jsonify({"ok": True, "message": "eero disconnected."})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 502


@app.post("/api/devices/<int:device_id>/reserve")
def reserve_device(device_id):
    if not eero_service.authenticated():
        return jsonify({"ok": False, "message": "Connect the site to eero first."}), 401
    payload = request.get_json(silent=True) or {}
    desired_ip = str(payload.get("ip") or "").strip()
    try:
        address = ipaddress.ip_address(desired_ip)
        network = ipaddress.ip_network(NETWORK_CIDR, strict=False)
        if address not in network or address in (network.network_address, network.broadcast_address):
            raise ValueError
    except ValueError:
        return jsonify({"ok": False, "message": f"Choose a usable address inside {NETWORK_CIDR}."}), 400

    with db_connection() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        conflict = conn.execute(
            "SELECT * FROM devices WHERE id<>? AND (ip=? OR reserved_ip=?) LIMIT 1",
            (device_id, desired_ip, desired_ip),
        ).fetchone()
    if not row:
        return jsonify({"ok": False, "message": "Device not found."}), 404
    if conflict:
        conflict_name = row_to_dict(conflict)["display_name"]
        return jsonify({"ok": False, "message": f"{desired_ip} is already associated with {conflict_name}."}), 409
    try:
        eero_service.reserve(row_to_dict(row), desired_ip)
        with db_connection() as conn:
            updated = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if updated["reserved_ip"] != desired_ip:
            return jsonify({"ok": False, "message": "eero accepted the request, but the new reservation could not be verified."}), 502
        return jsonify({"ok": True, "message": f"Reserved {desired_ip} in eero.", "device": row_to_dict(updated)})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 502


def background_scanner():
    time.sleep(8)
    while True:
        scan_network()
        time.sleep(AUTO_SCAN_MINUTES * 60)


if AUTO_SCAN_MINUTES:
    threading.Thread(target=background_scanner, daemon=True).start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("APP_PORT", "8088")), debug=False)
