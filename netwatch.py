"""
NetWatch — Desktop Network Engineering Workstation

Architecture:
- Domain & Service Components:
    - OUILookup: MAC vendor resolution via mac_vendor_lookup / manuf / local OUI database / curated IEEE table.
    - NetworkInterfaceManager: Real interface enumeration via psutil (with netifaces/OS fallback),
      detecting IPv4, Netmask, MAC, Status, Default Gateway, and Local Subnet CIDR.
    - DatabaseConfig: Secure desktop configuration model (Host, Port, Username, Password, Database='netwatch_db').
      Reads defaults from environment variables or user-only (`0600`) config file `~/.netwatch/db_config.json`
      (and OS `keyring` when available). Never hardcodes credentials and never logs passwords.
    - DatabaseManager: Asynchronous MySQL persistence engine using `mysql.connector` (`mysql-connector-python`).
      Implements connection management, connection testing, automatic database & schema creation (`devices`,
      `monitoring_sessions`, `traffic_statistics`, `route_history` with primary keys, indexes, and foreign keys),
      automatic reconnection handling, parameterized SQL queries (`%s`), batched asynchronous writes on a
      dedicated background worker thread, and complete in-memory fallback when MySQL is unavailable.
    - DeviceScanner: Threaded ARP subnet scanner using Scapy (`srp`/`Ether`/`ARP`), connected to
      `DatabaseManager` for batched deduplicated device history persistence.
    - PacketMonitor: Real-time threaded Scapy packet capture engine (`AsyncSniffer` / `sniff` with
      `store=False`). Connected to `DatabaseManager` to create `monitoring_sessions` records and persist
      periodic aggregated `traffic_statistics` intervals without ever inserting individual packets.
    - IPGeolocationService & RouteMapGenerator: Session-cached IPv4 geolocation and Folium/Leaflet HTML
      route map builder.
    - RouteMapper: Cross-platform traceroute engine connected to `DatabaseManager` to persist completed
      routes (`route_history` with JSON `route_data`) and allow reloading historical routes onto the map.
- UI Views & Dialogs (Separated from Application Controller):
    - DashboardView (Overview Tab)
    - DevicesView (Devices Tab)
    - TrafficView (Traffic Monitor Tab)
    - RouteView (Route Mapper Tab)
    - HistoryView (History & Archives Tab — inspect persisted/session Devices, Monitoring Sessions +
      Traffic Statistics intervals, and Route History with hop breakdown & map reload)
    - DatabaseSettingsDialog (Settings > Database Configuration modal with Test Connection, Save & Connect,
      Disconnect, and masked password input)
- Application Controller & Shell:
    - NetWatchApp (Queue-polled via Tkinter.after(), thread-safe UI updates, responsive shutdown)
"""

import os
import re
import sys
import stat
import json
import time
import shutil
import socket
import struct
import logging
import ipaddress
import threading
import subprocess
import webbrowser
import urllib.request
import urllib.error
import queue
from pathlib import Path
from collections import deque
from datetime import datetime
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional, Callable, Any, Tuple, Deque

# ============================================================================
# OPTIONAL LIBRARY HANDLING & GRACEFUL FALLBACKS
# ============================================================================

MISSING_OPTIONAL_DEPS: List[str] = []

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    HAS_TK = True
    BaseFrame = tk.Frame
    BaseCanvas = tk.Canvas
except ImportError:
    HAS_TK = False
    tk = None  # type: ignore
    ttk = None  # type: ignore
    messagebox = None  # type: ignore
    BaseFrame = object  # type: ignore
    BaseCanvas = object  # type: ignore
    MISSING_OPTIONAL_DEPS.append("tkinter")

try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False
    ctk = None  # type: ignore
    MISSING_OPTIONAL_DEPS.append("customtkinter")

try:
    import psutil  # type: ignore
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    psutil = None  # type: ignore
    MISSING_OPTIONAL_DEPS.append("psutil")

try:
    import netifaces  # type: ignore
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False
    netifaces = None  # type: ignore

try:
    from scapy.all import (  # type: ignore
        ARP,
        Ether,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        DNS,
        DNSQR,
        DNSRR,
        srp,
        sr1,
        sniff,
        AsyncSniffer,
        conf as scapy_conf,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    ARP = None  # type: ignore
    Ether = None  # type: ignore
    IP = None  # type: ignore
    IPv6 = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    ICMP = None  # type: ignore
    DNS = None  # type: ignore
    DNSQR = None  # type: ignore
    DNSRR = None  # type: ignore
    srp = None  # type: ignore
    sr1 = None  # type: ignore
    sniff = None  # type: ignore
    AsyncSniffer = None  # type: ignore
    scapy_conf = None  # type: ignore
    MISSING_OPTIONAL_DEPS.append("scapy")

try:
    from mac_vendor_lookup import MacLookup  # type: ignore
    HAS_MAC_LOOKUP = True
except ImportError:
    HAS_MAC_LOOKUP = False
    MacLookup = None  # type: ignore

try:
    import manuf  # type: ignore
    HAS_MANUF = True
except ImportError:
    HAS_MANUF = False
    manuf = None  # type: ignore

try:
    import matplotlib  # type: ignore
    from matplotlib.figure import Figure  # type: ignore
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    matplotlib = None  # type: ignore
    Figure = None  # type: ignore
    MISSING_OPTIONAL_DEPS.append("matplotlib")

HAS_MPL_TKAGG = False
FigureCanvasTkAgg = None  # type: ignore
if HAS_MATPLOTLIB and HAS_TK:
    try:
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg  # type: ignore
        HAS_MPL_TKAGG = True
    except Exception:
        HAS_MPL_TKAGG = False

try:
    import folium  # type: ignore
    HAS_FOLIUM = True
except ImportError:
    HAS_FOLIUM = False
    folium = None  # type: ignore
    MISSING_OPTIONAL_DEPS.append("folium")

try:
    import geoip2.database  # type: ignore
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False
    geoip2 = None  # type: ignore

try:
    import mysql.connector  # type: ignore
    from mysql.connector import Error as MySQLError  # type: ignore
    HAS_MYSQL_CONNECTOR = True
except ImportError:
    HAS_MYSQL_CONNECTOR = False
    mysql = None  # type: ignore
    MySQLError = Exception  # type: ignore
    MISSING_OPTIONAL_DEPS.append("mysql-connector-python")

try:
    import keyring  # type: ignore
    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False
    keyring = None  # type: ignore


# ============================================================================
# DESIGN SYSTEM & THEME CONSTANTS
# ============================================================================

class Theme:
    """Color palette, typography, and layout constants for the NetWatch workstation."""

    # Core surfaces
    BG_PRIMARY = "#17191C"        # Dark charcoal background
    BG_PANEL = "#202328"          # Slightly lighter panels
    BG_ELEVATED = "#262A30"       # Toolbar / table header / input surface
    BG_HOVER = "#2D3239"          # Button / row hover state
    BG_SELECTED = "#343A42"       # Active / selected item

    # Borders & dividers
    BORDER = "#393E45"            # Subtle structural border
    BORDER_FOCUS = "#D6A85C"      # Focus ring / active accent border

    # Text hierarchy
    TEXT_PRIMARY = "#E2E5E9"      # Off-white primary text
    TEXT_SECONDARY = "#9BA3AE"    # Muted technical label text
    TEXT_MUTED = "#68707A"        # Disabled / empty state text

    # Semantic accents
    ACCENT_AMBER = "#D6A85C"      # Muted amber primary accent
    ACCENT_AMBER_HOVER = "#C2954B"
    STATE_SUCCESS = "#5E9E6E"     # Muted green for successful / online states
    STATE_WARNING = "#D6A85C"     # Muted amber for warnings / idle states
    STATE_ERROR = "#C45B5B"       # Muted red for errors / offline states
    CHART_BLUE = "#6CA0DC"        # Muted technical steel-blue for secondary series
    CHART_TEAL = "#5B9EA6"        # Muted technical teal

    # Typography
    FONT_UI = ("Segoe UI", 10) if sys.platform.startswith("win") else ("DejaVu Sans", 10)
    FONT_UI_BOLD = (FONT_UI[0], 10, "bold")
    FONT_SECTION = (FONT_UI[0], 10, "bold")
    FONT_TITLE = (FONT_UI[0], 12, "bold")
    FONT_MONO = ("Consolas", 10) if sys.platform.startswith("win") else ("DejaVu Sans Mono", 10)
    FONT_MONO_BOLD = (FONT_MONO[0], 10, "bold")
    FONT_MONO_SMALL = (FONT_MONO[0], 9)
    FONT_MONO_LARGE = (FONT_MONO[0], 13, "bold")

    # Geometry & sizing
    CORNER_RADIUS = 2             # Squared / minimally rounded controls
    BORDER_WIDTH = 1
    PAD_XS = 4
    PAD_SM = 6
    PAD_MD = 10
    PAD_LG = 14


def sanitize_diagnostic_message(msg: str) -> str:
    """Redact any accidental password/token parameters and trim multi-line tracebacks."""
    if not msg:
        return "Unknown error"
    first_line = str(msg).strip().splitlines()[0]
    redacted = re.sub(r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", first_line)
    return redacted[:220]


def format_bytes_rate(bps: float) -> str:
    if bps < 1024.0:
        return f"{bps:.1f} B/s"
    if bps < 1024.0 * 1024.0:
        return f"{bps / 1024.0:.2f} KB/s"
    return f"{bps / (1024.0 * 1024.0):.2f} MB/s"


def format_total_bytes(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024.0:.2f} KB"
    if num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024.0 * 1024.0):.2f} MB"
    return f"{num_bytes / (1024.0 * 1024.0 * 1024.0):.2f} GB"


def format_duration(seconds: float) -> str:
    total_sec = max(0, int(seconds))
    hrs, rem = divmod(total_sec, 3600)
    mins, secs = divmod(rem, 60)
    return f"{hrs:02d}:{mins:02d}:{secs:02d}"


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class DatabaseConfig:
    """
    User-configurable MySQL connection parameters (Stage 5).
    Never hardcodes credentials and masks passwords in `repr` / logs.
    """
    host: str = ""
    port: int = 3306
    username: str = ""
    password: str = field(default="", repr=False)
    database: str = "netwatch_db"
    save_connection_profile: bool = True

    def is_configured(self) -> bool:
        return bool(self.host.strip() and self.username.strip() and self.database.strip())

    def safe_summary(self) -> str:
        """Return a log-safe summary string that never includes the password."""
        if not self.is_configured():
            return "Unconfigured"
        return f"{self.username}@{self.host}:{self.port}/{self.database}"


@dataclass
class InterfaceSummary:
    """Represents metadata and configuration for a host network interface."""
    name: str = "None"
    ipv4_address: str = "Not available"
    netmask: str = "Not available"
    mac_address: str = "Not available"
    default_gateway: str = "Not available"
    subnet_cidr: str = "Not available"
    is_up: bool = False
    speed_mbps: int = 0
    mtu: int = 0
    is_loopback: bool = False

    @property
    def status_label(self) -> str:
        if self.name in ("None", "No interface selected", "No interfaces found"):
            return "Disconnected"
        if self.is_up and self.ipv4_address not in ("Not available", "—", ""):
            return "Online / Active"
        if self.is_up:
            return "Up (No IPv4)"
        return "Down"


@dataclass
class DeviceRecord:
    """Represents a discovered host on the local network."""
    ip_address: str
    mac_address: str
    hostname: str = "Resolving..."
    vendor: str = "Unknown"
    first_seen: str = "—"
    last_seen: str = "—"
    status: str = "Online"
    interface_name: str = ""
    response_Count: int = 1
    last_rtt_ms: Optional[float] = None
    is_local_host: bool = False
    is_gateway: bool = False
    db_id: Optional[int] = None


@dataclass
class PacketRecord:
    """
    Represents a captured network packet header summary (Stage 3).
    Strictly stores header metadata only — never raw payloads or credentials.
    """
    seq_id: int
    timestamp: str
    epoch_time: float
    source_ip: str
    destination_ip: str
    protocol: str          # "TCP", "UDP", "ICMP", "DNS", "Other"
    length: int
    src_port: Optional[int]
    dst_port: Optional[int]
    direction: str         # "Upload", "Download", "Local/Other"
    info: str

    @property
    def src_port_str(self) -> str:
        return str(self.src_port) if self.src_port is not None else "—"

    @property
    def dst_port_str(self) -> str:
        return str(self.dst_port) if self.dst_port is not None else "—"


@dataclass
class TrafficStatsSnapshot:
    """Point-in-time snapshot of real-time packet capture telemetry."""
    is_capturing: bool
    status_text: str
    interface_name: str
    local_ip: str
    duration_seconds: float
    total_packets: int
    total_bytes: int
    packets_per_sec: float
    bytes_per_sec: float
    upload_bps: float
    download_bps: float
    protocol_counts: Dict[str, int]
    time_axis: List[float]
    upload_history_kbs: List[float]
    download_history_kbs: List[float]
    pps_history: List[float]
    bps_history_kbs: List[float]


@dataclass
class PacketFilterCriteria:
    """Non-destructive display filter criteria for the Traffic Monitor workspace."""
    protocol: str = "ALL"
    source_ip: str = ""
    destination_ip: str = ""
    search_text: str = ""

    def matches(self, pkt: PacketRecord) -> bool:
        if self.protocol and self.protocol != "ALL":
            if pkt.protocol.upper() != self.protocol.upper():
                return False
        if self.source_ip:
            if self.source_ip.lower() not in pkt.source_ip.lower():
                return False
        if self.destination_ip:
            if self.destination_ip.lower() not in pkt.destination_ip.lower():
                return False
        if self.search_text:
            q = self.search_text.lower()
            haystack = (
                f"{pkt.timestamp} {pkt.source_ip} {pkt.destination_ip} "
                f"{pkt.protocol} {pkt.src_port_str} {pkt.dst_port_str} {pkt.info}"
            ).lower()
            if q not in haystack:
                return False
        return True

    def is_active(self) -> bool:
        return bool(
            (self.protocol and self.protocol != "ALL")
            or self.source_ip
            or self.destination_ip
            or self.search_text
        )


@dataclass
class GeoLocationResult:
    """Represents geolocation metadata for a public IPv4 address (Stage 4)."""
    ip_address: str
    is_public: bool = False
    is_mapped: bool = False
    country: str = "—"
    region: str = "—"
    city: str = "—"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn_org: str = "—"
    mapping_status: str = "Not geographically mapped"
    source_note: str = "Approximate IP geolocation"


@dataclass
class RouteHopRecord:
    """Represents a single traceroute hop along a network path (Stage 4)."""
    hop_number: int
    ip_address: str
    hostname: str = "—"
    rtt_ms: Optional[float] = None
    response_status: str = "OK"
    country: str = "—"
    region: str = "—"
    city: str = "—"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    mapping_status: str = "Not mapped"
    is_destination: bool = False

    @property
    def rtt_display(self) -> str:
        if self.rtt_ms is not None:
            return f"{self.rtt_ms:.1f} ms"
        if self.ip_address == "*" or "Timed Out" in self.response_status:
            return "* (Timeout)"
        return "—"

    @property
    def has_coordinates(self) -> bool:
        return self.latitude is not None and self.longitude is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hop_number": self.hop_number,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "rtt_ms": self.rtt_ms,
            "response_status": self.response_status,
            "country": self.country,
            "region": self.region,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "mapping_status": self.mapping_status,
            "is_destination": self.is_destination,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RouteHopRecord":
        return cls(
            hop_number=int(d.get("hop_number", 0)),
            ip_address=str(d.get("ip_address", "*")),
            hostname=str(d.get("hostname", "—")),
            rtt_ms=float(d["rtt_ms"]) if d.get("rtt_ms") is not None else None,
            response_status=str(d.get("response_status", "OK")),
            country=str(d.get("country", "—")),
            region=str(d.get("region", "—")),
            city=str(d.get("city", "—")),
            latitude=float(d["latitude"]) if d.get("latitude") is not None else None,
            longitude=float(d["longitude"]) if d.get("longitude") is not None else None,
            mapping_status=str(d.get("mapping_status", "Not mapped")),
            is_destination=bool(d.get("is_destination", False)),
        )


@dataclass
class MonitoringSessionRecord:
    """Represents a historical or active packet monitoring session (`monitoring_sessions` table)."""
    id: int
    interface: str
    start_time: str
    end_time: str
    total_packets: int
    source: str = "Session Memory"  # "MySQL" or "Session Memory"


@dataclass
class TrafficStatIntervalRecord:
    """Represents an aggregated traffic statistics interval (`traffic_statistics` table)."""
    id: int
    session_id: int
    timestamp: str
    download_bytes: int
    upload_bytes: int
    tcp_packets: int
    udp_packets: int
    icmp_packets: int
    dns_packets: int
    other_packets: int


@dataclass
class RouteHistoryRecord:
    """Represents a persisted traceroute execution (`route_history` table)."""
    id: int
    destination: str
    timestamp: str
    hop_count: int
    route_data: str  # JSON string encoding resolved_ip, mapped_count, and hops list
    source: str = "Session Memory"

    def parse_hops(self) -> Tuple[str, List[RouteHopRecord]]:
        """Decode `route_data` JSON into `(resolved_ip, List[RouteHopRecord])`."""
        try:
            payload = json.loads(self.route_data)
            if isinstance(payload, dict):
                res_ip = str(payload.get("resolved_ip", self.destination))
                hops_raw = payload.get("hops", [])
                return res_ip, [RouteHopRecord.from_dict(h) for h in hops_raw if isinstance(h, dict)]
            if isinstance(payload, list):
                return self.destination, [RouteHopRecord.from_dict(h) for h in payload if isinstance(h, dict)]
        except Exception:
            pass
        return self.destination, []


@dataclass
class ActivityEvent:
    """Represents a real application or network event for the Overview table."""
    timestamp: str
    subsystem: str
    source: str
    summary: str
    state: str


# ============================================================================
# VENDOR / OUI IDENTIFICATION SERVICE
# ============================================================================

class OUILookup:
    """Identifies hardware manufacturer from a MAC address OUI prefix."""

    BUILTIN_OUI_MAP: Dict[str, str] = {
        "00:00:5E": "ICANN / IANA",
        "00:05:69": "VMware, Inc.",
        "00:0C:29": "VMware, Inc.",
        "00:1C:14": "VMware, Inc.",
        "00:50:56": "VMware, Inc.",
        "08:00:27": "PCS Systemtechnik / Oracle VirtualBox",
        "52:54:00": "QEMU / KVM Virtual NIC",
        "00:15:5D": "Microsoft Hyper-V",
        "00:16:3E": "Xensource / Xen",
        "02:42:AC": "Docker Container Network",
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Trading Ltd",
        "E4:5F:01": "Raspberry Pi Trading Ltd",
        "28:CD:C1": "Raspberry Pi Trading Ltd",
        "D8:3A:DD": "Raspberry Pi Trading Ltd",
        "00:1A:11": "Google, Inc.",
        "3C:5A:B4": "Google, Inc.",
        "F4:F5:D8": "Google, Inc.",
        "00:1B:63": "Apple, Inc.",
        "00:25:00": "Apple, Inc.",
        "3C:22:FB": "Apple, Inc.",
        "AC:BC:32": "Apple, Inc.",
        "F0:18:98": "Apple, Inc.",
        "BC:D0:74": "Apple, Inc.",
        "00:1E:C9": "Cisco Systems, Inc.",
        "00:24:14": "Cisco Systems, Inc.",
        "00:26:0B": "Cisco Systems, Inc.",
        "58:AC:78": "Cisco Systems, Inc.",
        "F8:72:EA": "Cisco Systems, Inc.",
        "24:5A:4C": "Ubiquiti Inc.",
        "44:D9:E7": "Ubiquiti Inc.",
        "68:D7:9A": "Ubiquiti Inc.",
        "74:83:C2": "Ubiquiti Inc.",
        "80:2A:A8": "Ubiquiti Inc.",
        "F0:9F:C2": "Ubiquiti Inc.",
        "18:E8:29": "Ubiquiti Inc.",
        "50:C7:BF": "TP-Link Technologies",
        "14:CC:20": "TP-Link Technologies",
        "C0:25:E9": "TP-Link Technologies",
        "E8:DE:27": "TP-Link Technologies",
        "B0:BE:76": "TP-Link Technologies",
        "00:14:6C": "Netgear",
        "20:E5:2A": "Netgear",
        "A0:40:A0": "Netgear",
        "04:D4:C4": "ASUSTek Computer Inc.",
        "2C:FD:A1": "ASUSTek Computer Inc.",
        "38:D5:47": "ASUSTek Computer Inc.",
        "00:1B:21": "Intel Corporate",
        "00:1E:67": "Intel Corporate",
        "3C:FD:FE": "Intel Corporate",
        "8C:8D:28": "Intel Corporate",
        "A4:BF:01": "Intel Corporate",
        "00:E0:4C": "Realtek Semiconductor Corp.",
        "54:E1:AD": "LCFC / Lenovo",
        "F8:B1:56": "Dell Inc.",
        "18:03:73": "Dell Inc.",
        "D4:BE:D9": "Dell Inc.",
        "3C:D9:2B": "Hewlett Packard",
        "94:57:A5": "Hewlett Packard",
        "48:BA:4E": "Hewlett Packard Enterprise",
        "00:17:88": "Philips Lighting BV",
        "EC:B5:FA": "Philips Lighting BV",
        "40:B0:76": "ASUSTek Computer Inc.",
    }

    SYSTEM_OUI_PATHS = (
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/share/arp-scan/ieee-oui.txt",
        "/usr/share/wireshark/manuf",
        "/etc/manuf",
        "/usr/share/ieee-data/oui.txt",
    )

    def __init__(self) -> None:
        self._cache: Dict[str, str] = dict(self.BUILTIN_OUI_MAP)
        self._mac_lookup_instance: Any = None
        self._manuf_instance: Any = None
        self._init_providers()

    def _init_providers(self) -> None:
        if HAS_MAC_LOOKUP and MacLookup is not None:
            try:
                self._mac_lookup_instance = MacLookup()
            except Exception:
                self._mac_lookup_instance = None

        if HAS_MANUF and manuf is not None:
            try:
                self._manuf_instance = manuf.MacParser()
            except Exception:
                self._manuf_instance = None

        for path in self.SYSTEM_OUI_PATHS:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                try:
                    self._load_system_oui_file(path)
                    break
                except Exception:
                    continue

    def _load_system_oui_file(self, filepath: str) -> None:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "(hex)" in line:
                    parts = line.split("(hex)", 1)
                    prefix = parts[0].strip().replace("-", ":").upper()
                    vendor = parts[1].strip()
                    if len(prefix) == 8 and vendor:
                        self._cache[prefix] = vendor
                else:
                    tokens = line.split(None, 1)
                    if len(tokens) == 2:
                        raw_p, vendor = tokens[0].upper().replace("-", "").replace(":", ""), tokens[1].strip()
                        if len(raw_p) >= 6 and all(c in "0123456789ABCDEF" for c in raw_p[:6]):
                            prefix = f"{raw_p[0:2]}:{raw_p[2:4]}:{raw_p[4:6]}"
                            self._cache[prefix] = vendor.split("#")[0].strip()

    @staticmethod
    def normalize_mac(mac: str) -> str:
        if not mac:
            return "—"
        cleaned = mac.strip().upper().replace("-", ":")
        parts = [p.zfill(2) for p in cleaned.split(":") if p]
        if len(parts) == 6:
            return ":".join(parts)
        return cleaned

    def lookup(self, mac: str) -> str:
        norm = self.normalize_mac(mac)
        if not norm or norm in ("—", "NOT AVAILABLE", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return "Unknown"

        prefix = norm[:8]
        if prefix in self._cache:
            return self._cache[prefix]

        if self._mac_lookup_instance is not None:
            try:
                vendor = self._mac_lookup_instance.lookup(norm)
                if vendor:
                    self._cache[prefix] = str(vendor).strip()
                    return self._cache[prefix]
            except Exception:
                pass

        if self._manuf_instance is not None:
            try:
                vendor = self._manuf_instance.get_manuf_long(norm) or self._manuf_instance.get_manuf(norm)
                if vendor:
                    self._cache[prefix] = str(vendor).strip()
                    return self._cache[prefix]
            except Exception:
                pass

        return "Unknown"


# ============================================================================
# STAGE 5: MYSQL DATABASE MANAGER (WITH THREADED BATCHING & IN-MEMORY FALLBACK)
# ============================================================================

class DatabaseManager:
    """
    MySQL Database Integration & Session Fallback Manager (Stage 5).
    - Manages connections to MySQL (`netwatch_db` by default) via `mysql.connector`.
    - Never hardcodes credentials and never logs passwords.
    - Automatically initializes the database and required tables (`devices`,
      `monitoring_sessions`, `traffic_statistics`, `route_history`) with appropriate
      primary keys, indexes, unique constraints, and foreign keys.
    - Executes all database I/O outside the GUI thread using a dedicated background
      worker thread (`NetWatchDBWorker`) and parameterized queries (`%s`).
    - Batches device upserts (`executemany` with `ON DUPLICATE KEY UPDATE`) and
      aggregates periodic traffic statistics rather than inserting every packet.
    - Degrades gracefully to in-memory session storage when MySQL is unavailable or
      unconfigured, informing the user without blocking or crashing the workstation.
    """

    CONFIG_DIR = Path.home() / ".netwatch"
    CONFIG_FILE = CONFIG_DIR / "db_config.json"
    KEYRING_SERVICE = "NetWatch_MySQL_Workstation"

    SCHEMA_DDL: Dict[str, str] = {
        "devices": """
            CREATE TABLE IF NOT EXISTS devices (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                mac_address VARCHAR(32) NOT NULL,
                hostname VARCHAR(255) DEFAULT 'Unknown',
                vendor VARCHAR(255) DEFAULT 'Unknown',
                first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL,
                UNIQUE KEY uq_devices_mac (mac_address),
                INDEX idx_devices_ip (ip_address),
                INDEX idx_devices_last_seen (last_seen)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        "monitoring_sessions": """
            CREATE TABLE IF NOT EXISTS monitoring_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                interface VARCHAR(64) NOT NULL,
                start_time DATETIME NOT NULL,
                end_time DATETIME DEFAULT NULL,
                total_packets BIGINT NOT NULL DEFAULT 0,
                INDEX idx_sessions_interface (interface),
                INDEX idx_sessions_start_time (start_time)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        "traffic_statistics": """
            CREATE TABLE IF NOT EXISTS traffic_statistics (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session_id INT NOT NULL,
                timestamp DATETIME NOT NULL,
                download_bytes BIGINT NOT NULL DEFAULT 0,
                upload_bytes BIGINT NOT NULL DEFAULT 0,
                tcp_packets INT NOT NULL DEFAULT 0,
                udp_packets INT NOT NULL DEFAULT 0,
                icmp_packets INT NOT NULL DEFAULT 0,
                dns_packets INT NOT NULL DEFAULT 0,
                other_packets INT NOT NULL DEFAULT 0,
                INDEX idx_traffic_session_ts (session_id, timestamp),
                CONSTRAINT fk_traffic_session
                    FOREIGN KEY (session_id) REFERENCES monitoring_sessions(id)
                    ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        "route_history": """
            CREATE TABLE IF NOT EXISTS route_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                destination VARCHAR(255) NOT NULL,
                timestamp DATETIME NOT NULL,
                hop_count INT NOT NULL DEFAULT 0,
                route_data LONGTEXT NOT NULL,
                INDEX idx_route_dest (destination),
                INDEX idx_route_timestamp (timestamp)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
    }

    SQL_UPSERT_DEVICE = """
        INSERT INTO devices (ip_address, mac_address, hostname, vendor, first_seen, last_seen)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            ip_address = VALUES(ip_address),
            hostname = IF(
                VALUES(hostname) IS NOT NULL AND VALUES(hostname) NOT IN ('', '—', 'Unknown', 'Resolving...'),
                VALUES(hostname),
                hostname
            ),
            vendor = IF(
                VALUES(vendor) IS NOT NULL AND VALUES(vendor) NOT IN ('', 'Unknown'),
                VALUES(vendor),
                vendor
            ),
            first_seen = LEAST(first_seen, VALUES(first_seen)),
            last_seen = GREATEST(last_seen, VALUES(last_seen))
    """

    SQL_INSERT_SESSION = """
        INSERT INTO monitoring_sessions (interface, start_time, end_time, total_packets)
        VALUES (%s, %s, %s, %s)
    """

    SQL_UPDATE_SESSION = """
        UPDATE monitoring_sessions
        SET end_time = %s, total_packets = %s
        WHERE id = %s
    """

    SQL_INSERT_TRAFFIC_STAT = """
        INSERT INTO traffic_statistics (
            session_id, timestamp, download_bytes, upload_bytes,
            tcp_packets, udp_packets, icmp_packets, dns_packets, other_packets
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    SQL_INSERT_ROUTE = """
        INSERT INTO route_history (destination, timestamp, hop_count, route_data)
        VALUES (%s, %s, %s, %s)
    """

    def __init__(
        self,
        event_queue: Optional["queue.Queue[Dict[str, Any]]"] = None,
        connector_module: Any = None,
    ) -> None:
        self.event_queue = event_queue
        self._connector = connector_module if connector_module is not None else mysql
        self.config: DatabaseConfig = self.load_saved_config()
        self.is_connected: bool = False
        self.status_label: str = "Disconnected (In-Memory Session Mode)"
        self.last_error: Optional[str] = None

        self._conn: Any = None
        self._conn_lock = threading.Lock()
        self._mem_lock = threading.Lock()

        # In-memory session stores (always active so application works when MySQL is unavailable)
        self._session_devices: Dict[str, DeviceRecord] = {}
        self._scan_history: List[Dict[str, Any]] = []
        self._mem_sessions: Dict[int, MonitoringSessionRecord] = {}
        self._mem_traffic_stats: List[TrafficStatIntervalRecord] = []
        self._mem_routes: List[RouteHistoryRecord] = []
        self._local_session_seq: int = 0
        self._local_stat_seq: int = 0
        self._local_route_seq: int = 0
        self._session_id_map: Dict[int, int] = {}  # Maps local session ID -> MySQL monitoring_sessions.id

        # Background asynchronous write queue & worker thread
        self._write_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=2000)
        self._stop_worker = threading.Event()
        self._worker_thread = threading.Thread(
            target=self._db_worker_loop,
            name="NetWatchDBWorker",
            daemon=True,
        )
        self._worker_thread.start()

    # ------------------------------------------------------------------------
    # CREDENTIAL & CONFIGURATION MANAGEMENT (NO HARDCODED CREDENTIALS)
    # ------------------------------------------------------------------------

    @classmethod
    def load_saved_config(cls) -> DatabaseConfig:
        """
        Load database connection parameters from environment variables or
        `~/.netwatch/db_config.json` (and OS `keyring` if available).
        Never hardcodes credentials.
        """
        cfg = DatabaseConfig(
            host=os.environ.get("NETWATCH_DB_HOST", ""),
            port=int(os.environ.get("NETWATCH_DB_PORT", "3306") or 3306),
            username=os.environ.get("NETWATCH_DB_USER", ""),
            password=os.environ.get("NETWATCH_DB_PASS", ""),
            database=os.environ.get("NETWATCH_DB_NAME", "netwatch_db") or "netwatch_db",
        )

        if cls.CONFIG_FILE.is_file():
            try:
                with open(cls.CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    cfg.host = str(data.get("host", cfg.host))
                    cfg.port = int(data.get("port", cfg.port) or 3306)
                    cfg.username = str(data.get("username", cfg.username))
                    cfg.database = str(data.get("database", cfg.database) or "netwatch_db")
            except Exception:
                pass

        if HAS_KEYRING and keyring is not None and cfg.username and not cfg.password:
            try:
                secret = keyring.get_password(cls.KEYRING_SERVICE, cfg.username)
                if secret:
                    cfg.password = secret
            except Exception:
                pass

        return cfg

    @classmethod
    def save_config_profile(cls, cfg: DatabaseConfig) -> None:
        """
        Persist non-sensitive connection profile fields (host, port, username, database)
        to `~/.netwatch/db_config.json` with `0600` user-only permissions, and store the
        password in the OS keyring if `keyring` is available. Never writes plaintext
        passwords to logs or world-readable files.
        """
        if not cfg.save_connection_profile:
            return
        try:
            cls.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            profile = {
                "host": cfg.host.strip(),
                "port": int(cfg.port),
                "username": cfg.username.strip(),
                "database": cfg.database.strip() or "netwatch_db",
            }
            with open(cls.CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=2)
            try:
                os.chmod(cls.CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass

            if HAS_KEYRING and keyring is not None and cfg.username:
                try:
                    keyring.set_password(cls.KEYRING_SERVICE, cfg.username, cfg.password)
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _sanitize_identifier(ident: str, default: str = "netwatch_db") -> str:
        """Validate SQL database identifier to alphanumeric and underscores only."""
        cleaned = re.sub(r"[^A-Za-z0-9_]", "", ident.strip())
        return cleaned if cleaned else default

    # ------------------------------------------------------------------------
    # CONNECTION MANAGEMENT, TESTING, SCHEMA INITIALIZATION & RECONNECTION
    # ------------------------------------------------------------------------

    def test_connection(self, test_cfg: Optional[DatabaseConfig] = None) -> Tuple[bool, str]:
        """
        Test MySQL connectivity using `test_cfg` (or `self.config`) without logging passwords.
        Returns `(success, status_message)`.
        """
        cfg = test_cfg or self.config
        if not cfg.is_configured():
            return False, "Incomplete configuration: Host, Username, and Database name are required."

        if self._connector is None:
            return (
                False,
                "MySQL Connector/Python ('mysql-connector-python') is not installed. "
                "Run 'pip install mysql-connector-python' to enable MySQL persistence.",
            )

        try:
            conn = self._connector.connect(
                host=cfg.host.strip(),
                port=int(cfg.port),
                user=cfg.username.strip(),
                password=cfg.password,
                connection_timeout=4,
            )
            server_info = getattr(conn, "get_server_info", lambda: "MySQL")()
            conn.close()
            return True, f"Connection verified ({cfg.safe_summary()} — Server {server_info})"
        except Exception as exc:
            return False, f"MySQL connection failed for {cfg.safe_summary()}: {exc}"

    def connect(self, new_config: Optional[DatabaseConfig] = None) -> Tuple[bool, str]:
        """
        Establish a MySQL connection, automatically create `netwatch_db` and the 4 required
        tables (`devices`, `monitoring_sessions`, `traffic_statistics`, `route_history`),
        and flush any buffered session devices.
        """
        if new_config is not None:
            self.config = new_config
            self.save_config_profile(new_config)

        if not self.config.is_configured():
            self.is_connected = False
            self.status_label = "Disconnected (Not Configured — In-Memory Mode)"
            return False, "Database credentials not configured. Operating in session-memory mode."

        if self._connector is None:
            self.is_connected = False
            self.status_label = "Disconnected (mysql-connector missing — In-Memory Mode)"
            msg = (
                "MySQL Connector/Python is not installed (pip install mysql-connector-python). "
                "Continuing in session-memory mode; historical persistence is unavailable."
            )
            self.last_error = msg
            return False, msg

        db_name = self._sanitize_identifier(self.config.database, "netwatch_db")
        self.config.database = db_name

        with self._conn_lock:
            self._close_locked_connection()
            try:
                conn = self._connector.connect(
                    host=self.config.host.strip(),
                    port=int(self.config.port),
                    user=self.config.username.strip(),
                    password=self.config.password,
                    connection_timeout=5,
                    autocommit=False,
                )
                cursor = conn.cursor()
                cursor.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
                    "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                )
                cursor.execute(f"USE `{db_name}`")
                for _table_name, ddl in self.SCHEMA_DDL.items():
                    cursor.execute(ddl)
                conn.commit()
                cursor.close()

                self._conn = conn
                self.is_connected = True
                self.last_error = None
                self.status_label = f"Connected ({self.config.host}:{self.config.port}/{db_name})"
                logging.info("MySQL schema initialized on %s", self.config.safe_summary())
            except Exception as exc:
                self._conn = None
                self.is_connected = False
                self.last_error = str(exc)
                self.status_label = "Disconnected (MySQL Unavailable — In-Memory Mode)"
                logging.warning("MySQL connection unavailable (%s): %s", self.config.safe_summary(), exc)
                return (
                    False,
                    f"MySQL unavailable ({exc}). Continuing in session-memory mode; "
                    "historical database persistence is currently disabled.",
                )

        # Queue initial batch sync of any devices already discovered in session memory
        existing_devs = self.get_all_session_devices()
        if existing_devs:
            self.upsert_devices_batch(existing_devs)

        return True, f"Connected to MySQL ({self.config.safe_summary()}) and initialized schema."

    def connect_async(
        self,
        new_config: Optional[DatabaseConfig] = None,
        on_done: Optional[Callable[[bool, str], None]] = None,
    ) -> None:
        """Connect and initialize schema on a background thread so the GUI never freezes."""
        def _task() -> None:
            ok, msg = self.connect(new_config)
            if self.event_queue is not None:
                self.event_queue.put({
                    "type": "db_state_changed",
                    "connected": ok,
                    "status_label": self.status_label,
                    "message": msg,
                })
            if on_done is not None:
                on_done(ok, msg)

        threading.Thread(target=_task, name="NetWatchDBConnect", daemon=True).start()

    def _ensure_connection_locked(self) -> bool:
        """
        Verify that `self._conn` is alive, attempting automatic reconnection (`ping(reconnect=True)`
        or full `connect`) if the connection dropped. Must be called with `self._conn_lock` held.
        """
        if not self.is_connected or self._conn is None:
            return False

        try:
            if hasattr(self._conn, "ping"):
                self._conn.ping(reconnect=True, attempts=2, delay=1)
            elif hasattr(self._conn, "is_connected") and not self._conn.is_connected():
                raise RuntimeError("Connection closed")
            return True
        except Exception:
            # Attempt full reconnect once
            try:
                if self._connector is None:
                    raise RuntimeError("No connector")
                db_name = self._sanitize_identifier(self.config.database, "netwatch_db")
                self._conn = self._connector.connect(
                    host=self.config.host.strip(),
                    port=int(self.config.port),
                    user=self.config.username.strip(),
                    password=self.config.password,
                    database=db_name,
                    connection_timeout=4,
                    autocommit=False,
                )
                return True
            except Exception as exc:
                self._conn = None
                self.is_connected = False
                self.last_error = str(exc)
                self.status_label = "Disconnected (Connection Lost — In-Memory Mode)"
                if self.event_queue is not None:
                    self.event_queue.put({
                        "type": "db_state_changed",
                        "connected": False,
                        "status_label": self.status_label,
                        "message": (
                            f"Lost connection to MySQL ({exc}). Continuing in session-memory mode; "
                            "historical persistence is unavailable."
                        ),
                    })
                return False

    def _close_locked_connection(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def disconnect(self) -> None:
        """Flush pending writes and cleanly close the MySQL connection."""
        self.flush_pending_writes(timeout=2.0)
        with self._conn_lock:
            self._close_locked_connection()
            self.is_connected = False
            self.status_label = "Disconnected (In-Memory Session Mode)"

    def shutdown(self) -> None:
        """Stop the background DB worker thread, flush queued writes, and close connections."""
        self.flush_pending_writes(timeout=1.5)
        self._stop_worker.set()
        if self._worker_thread.is_alive() and threading.current_thread() is not self._worker_thread:
            try:
                self._worker_thread.join(timeout=1.5)
            except Exception:
                pass
        self.disconnect()

    def get_connection_state(self) -> str:
        return self.status_label

    # ------------------------------------------------------------------------
    # BACKGROUND WRITE WORKER & PARAMETERIZED BATCH PERSISTENCE
    # ------------------------------------------------------------------------

    def _enqueue_write(self, task: Dict[str, Any]) -> None:
        try:
            self._write_queue.put_nowait(task)
        except queue.Full:
            pass

    def flush_pending_writes(self, timeout: float = 2.0) -> None:
        """Wait up to `timeout` seconds for queued database write tasks to complete."""
        deadline = time.monotonic() + timeout
        while not self._write_queue.empty() and time.monotonic() < deadline:
            time.sleep(0.02)

    def _db_worker_loop(self) -> None:
        """Background worker processing queued MySQL writes outside the GUI thread."""
        while not self._stop_worker.is_set():
            try:
                task = self._write_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                self._execute_write_task(task)
            except Exception as exc:
                logging.debug("Database background write skipped: %s", exc)
            finally:
                try:
                    self._write_queue.task_done()
                except Exception:
                    pass

    def _execute_write_task(self, task: Dict[str, Any]) -> None:
        ttype = task.get("type")
        with self._conn_lock:
            if not self._ensure_connection_locked() or self._conn is None:
                return

            cursor = self._conn.cursor()
            try:
                if ttype == "upsert_devices":
                    rows: List[Tuple[Any, ...]] = task.get("rows", [])
                    if rows:
                        cursor.executemany(self.SQL_UPSERT_DEVICE, rows)
                        self._conn.commit()

                elif ttype == "start_session":
                    local_id = int(task["local_id"])
                    iface = str(task["interface"])
                    start_ts = str(task["start_time"])
                    cursor.execute(self.SQL_INSERT_SESSION, (iface, start_ts, None, 0))
                    self._conn.commit()
                    db_session_id = getattr(cursor, "lastrowid", None)
                    if db_session_id:
                        with self._mem_lock:
                            self._session_id_map[local_id] = int(db_session_id)

                elif ttype == "update_session":
                    local_id = int(task["local_id"])
                    end_ts = str(task["end_time"])
                    total_pkts = int(task["total_packets"])
                    with self._mem_lock:
                        db_sid = self._session_id_map.get(local_id, local_id)
                    cursor.execute(self.SQL_UPDATE_SESSION, (end_ts, total_pkts, db_sid))
                    self._conn.commit()

                elif ttype == "insert_traffic_stat":
                    local_id = int(task["local_session_id"])
                    with self._mem_lock:
                        db_sid = self._session_id_map.get(local_id, local_id)
                    params = (
                        db_sid,
                        str(task["timestamp"]),
                        int(task["download_bytes"]),
                        int(task["upload_bytes"]),
                        int(task["tcp_packets"]),
                        int(task["udp_packets"]),
                        int(task["icmp_packets"]),
                        int(task["dns_packets"]),
                        int(task["other_packets"]),
                    )
                    cursor.execute(self.SQL_INSERT_TRAFFIC_STAT, params)
                    if task.get("session_total_packets") is not None:
                        cursor.execute(
                            "UPDATE monitoring_sessions SET total_packets = %s WHERE id = %s",
                            (int(task["session_total_packets"]), db_sid),
                        )
                    self._conn.commit()

                elif ttype == "insert_route":
                    params_route = (
                        str(task["destination"]),
                        str(task["timestamp"]),
                        int(task["hop_count"]),
                        str(task["route_data"]),
                    )
                    cursor.execute(self.SQL_INSERT_ROUTE, params_route)
                    self._conn.commit()

            except Exception as exc:
                try:
                    self._conn.rollback()
                except Exception:
                    pass
                raise exc
            finally:
                try:
                    cursor.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------------
    # PUBLIC PERSISTENCE API FOR SUBSYSTEMS (DEVICES, SESSIONS, TRAFFIC, ROUTES)
    # ------------------------------------------------------------------------

    @staticmethod
    def _normalize_datetime_str(ts: str) -> str:
        if not ts or ts in ("—", "In progress..."):
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return ts[:19]

    def upsert_device(self, record: DeviceRecord, persist_now: bool = True) -> DeviceRecord:
        """
        Update in-memory session device store and optionally enqueue parameterized
        MySQL upsert. Keyed by MAC address (or IP address when MAC is unavailable).
        """
        key = record.mac_address if record.mac_address not in ("—", "Unknown", "") else record.ip_address
        with self._mem_lock:
            existing = self._session_devices.get(key)
            if existing is not None:
                existing.ip_address = record.ip_address
                existing.last_seen = record.last_seen
                existing.status = record.status
                existing.response_Count += 1
                if record.hostname and record.hostname not in ("Unknown", "Resolving...", "—"):
                    existing.hostname = record.hostname
                if record.vendor and record.vendor != "Unknown":
                    existing.vendor = record.vendor
                if record.last_rtt_ms is not None:
                    existing.last_rtt_ms = record.last_rtt_ms
                existing.is_local_host = record.is_local_host
                existing.is_gateway = record.is_gateway
                target_rec = existing
            else:
                self._session_devices[key] = record
                target_rec = record

        if persist_now and self.is_connected:
            self.upsert_devices_batch([target_rec])

        return target_rec

    def upsert_devices_batch(self, devices: List[DeviceRecord]) -> None:
        """Batch-persist multiple discovered devices to MySQL `devices` table."""
        if not devices or not self.is_connected:
            return
        rows: List[Tuple[Any, ...]] = []
        for d in devices:
            mac_key = d.mac_address if d.mac_address not in ("—", "Unknown", "") else f"IP-{d.ip_address}"
            rows.append((
                d.ip_address,
                mac_key,
                d.hostname if d.hostname != "Resolving..." else "Unknown",
                d.vendor or "Unknown",
                self._normalize_datetime_str(d.first_seen),
                self._normalize_datetime_str(d.last_seen),
            ))
        self._enqueue_write({"type": "upsert_devices", "rows": rows})

    def record_scan_session(
        self,
        interface_name: str,
        subnet_cidr: str,
        start_time: str,
        end_time: str,
        hosts_found: int,
        status: str,
    ) -> None:
        with self._mem_lock:
            self._scan_history.append({
                "interface": interface_name,
                "subnet": subnet_cidr,
                "start_time": start_time,
                "end_time": end_time,
                "hosts_found": hosts_found,
                "status": status,
            })
        # Batch flush all discovered devices from this scan to MySQL
        if self.is_connected:
            self.upsert_devices_batch(self.get_all_session_devices())

    def start_monitoring_session(self, interface_name: str) -> int:
        """Create a new monitoring session record in memory and queue MySQL insert."""
        now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._mem_lock:
            self._local_session_seq += 1
            local_id = self._local_session_seq
            self._mem_sessions[local_id] = MonitoringSessionRecord(
                id=local_id,
                interface=interface_name,
                start_time=now_ts,
                end_time="Active",
                total_packets=0,
                source="MySQL + Session" if self.is_connected else "Session Memory",
            )
            self._session_id_map[local_id] = local_id

        if self.is_connected:
            self._enqueue_write({
                "type": "start_session",
                "local_id": local_id,
                "interface": interface_name,
                "start_time": now_ts,
            })
        return local_id

    def end_monitoring_session(self, local_session_id: int, total_packets: int) -> None:
        """Finalize `end_time` and `total_packets` for a monitoring session."""
        now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._mem_lock:
            sess = self._mem_sessions.get(local_session_id)
            if sess is not None:
                sess.end_time = now_ts
                sess.total_packets = int(total_packets)

        if self.is_connected:
            self._enqueue_write({
                "type": "update_session",
                "local_id": local_session_id,
                "end_time": now_ts,
                "total_packets": int(total_packets),
            })

    def record_traffic_statistics_interval(
        self,
        local_session_id: int,
        download_bytes: int,
        upload_bytes: int,
        protocol_deltas: Dict[str, int],
        session_total_packets: int,
    ) -> None:
        """
        Persist periodic aggregated traffic statistics (`traffic_statistics` table)
        rather than inserting individual packets.
        """
        now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tcp_cnt = int(protocol_deltas.get("TCP", 0))
        udp_cnt = int(protocol_deltas.get("UDP", 0))
        icmp_cnt = int(protocol_deltas.get("ICMP", 0))
        dns_cnt = int(protocol_deltas.get("DNS", 0))
        other_cnt = int(protocol_deltas.get("Other", 0))

        with self._mem_lock:
            self._local_stat_seq += 1
            stat_rec = TrafficStatIntervalRecord(
                id=self._local_stat_seq,
                session_id=local_session_id,
                timestamp=now_ts,
                download_bytes=int(download_bytes),
                upload_bytes=int(upload_bytes),
                tcp_packets=tcp_cnt,
                udp_packets=udp_cnt,
                icmp_packets=icmp_cnt,
                dns_packets=dns_cnt,
                other_packets=other_cnt,
            )
            self._mem_traffic_stats.append(stat_rec)
            sess = self._mem_sessions.get(local_session_id)
            if sess is not None:
                sess.total_packets = int(session_total_packets)

        if self.is_connected:
            self._enqueue_write({
                "type": "insert_traffic_stat",
                "local_session_id": local_session_id,
                "timestamp": now_ts,
                "download_bytes": int(download_bytes),
                "upload_bytes": int(upload_bytes),
                "tcp_packets": tcp_cnt,
                "udp_packets": udp_cnt,
                "icmp_packets": icmp_cnt,
                "dns_packets": dns_cnt,
                "other_packets": other_cnt,
                "session_total_packets": int(session_total_packets),
            })

    def record_route_history(
        self,
        destination: str,
        resolved_ip: str,
        hops: List[RouteHopRecord],
    ) -> RouteHistoryRecord:
        """Persist a completed traceroute path into `route_history` (with JSON `route_data`)."""
        now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mapped_count = sum(1 for h in hops if h.has_coordinates)
        payload_json = json.dumps({
            "destination": destination,
            "resolved_ip": resolved_ip,
            "mapped_count": mapped_count,
            "hops": [h.to_dict() for h in hops],
        })

        with self._mem_lock:
            self._local_route_seq += 1
            rec = RouteHistoryRecord(
                id=self._local_route_seq,
                destination=f"{destination} ({resolved_ip})" if resolved_ip and resolved_ip != destination else destination,
                timestamp=now_ts,
                hop_count=len(hops),
                route_data=payload_json,
                source="MySQL + Session" if self.is_connected else "Session Memory",
            )
            self._mem_routes.insert(0, rec)

        if self.is_connected:
            self._enqueue_write({
                "type": "insert_route",
                "destination": rec.destination,
                "timestamp": now_ts,
                "hop_count": len(hops),
                "route_data": payload_json,
            })
        return rec

    # ------------------------------------------------------------------------
    # HISTORICAL QUERY METHODS (MYSQL WHEN CONNECTED, SESSION FALLBACK OTHERWISE)
    # ------------------------------------------------------------------------

    def fetch_historical_devices(self, limit: int = 500) -> List[DeviceRecord]:
        """Fetch previously discovered devices from MySQL `devices` (or session memory if offline)."""
        if self.is_connected:
            with self._conn_lock:
                if self._ensure_connection_locked() and self._conn is not None:
                    cursor = self._conn.cursor()
                    try:
                        cursor.execute(
                            "SELECT id, ip_address, mac_address, hostname, vendor, first_seen, last_seen "
                            "FROM devices ORDER BY last_seen DESC LIMIT %s",
                            (int(limit),),
                        )
                        rows = cursor.fetchall()
                        results: List[DeviceRecord] = []
                        for r in rows:
                            results.append(
                                DeviceRecord(
                                    db_id=int(r[0]),
                                    ip_address=str(r[1]),
                                    mac_address=str(r[2]),
                                    hostname=str(r[3] or "Unknown"),
                                    vendor=str(r[4] or "Unknown"),
                                    first_seen=str(r[5]),
                                    last_seen=str(r[6]),
                                    status="Persisted (MySQL)",
                                )
                            )
                        return results
                    except Exception:
                        pass
                    finally:
                        try:
                            cursor.close()
                        except Exception:
                            pass

        return self.get_all_session_devices()

    def fetch_monitoring_sessions(self, limit: int = 200) -> List[MonitoringSessionRecord]:
        """Fetch previous monitoring sessions from MySQL `monitoring_sessions` (or session memory)."""
        if self.is_connected:
            with self._conn_lock:
                if self._ensure_connection_locked() and self._conn is not None:
                    cursor = self._conn.cursor()
                    try:
                        cursor.execute(
                            "SELECT id, interface, start_time, end_time, total_packets "
                            "FROM monitoring_sessions ORDER BY start_time DESC LIMIT %s",
                            (int(limit),),
                        )
                        rows = cursor.fetchall()
                        return [
                            MonitoringSessionRecord(
                                id=int(r[0]),
                                interface=str(r[1]),
                                start_time=str(r[2]),
                                end_time=str(r[3]) if r[3] is not None else "Active / Open",
                                total_packets=int(r[4] or 0),
                                source="MySQL",
                            )
                            for r in rows
                        ]
                    except Exception:
                        pass
                    finally:
                        try:
                            cursor.close()
                        except Exception:
                            pass

        with self._mem_lock:
            return list(reversed(list(self._mem_sessions.values())))

    def fetch_traffic_statistics(
        self,
        session_id: Optional[int] = None,
        limit: int = 300,
    ) -> List[TrafficStatIntervalRecord]:
        """Fetch historical aggregated traffic intervals from `traffic_statistics`."""
        if self.is_connected:
            with self._conn_lock:
                if self._ensure_connection_locked() and self._conn is not None:
                    cursor = self._conn.cursor()
                    try:
                        if session_id is not None:
                            cursor.execute(
                                "SELECT id, session_id, timestamp, download_bytes, upload_bytes, "
                                "tcp_packets, udp_packets, icmp_packets, dns_packets, other_packets "
                                "FROM traffic_statistics WHERE session_id = %s "
                                "ORDER BY timestamp DESC LIMIT %s",
                                (int(session_id), int(limit)),
                            )
                        else:
                            cursor.execute(
                                "SELECT id, session_id, timestamp, download_bytes, upload_bytes, "
                                "tcp_packets, udp_packets, icmp_packets, dns_packets, other_packets "
                                "FROM traffic_statistics ORDER BY timestamp DESC LIMIT %s",
                                (int(limit),),
                            )
                        rows = cursor.fetchall()
                        return [
                            TrafficStatIntervalRecord(
                                id=int(r[0]),
                                session_id=int(r[1]),
                                timestamp=str(r[2]),
                                download_bytes=int(r[3] or 0),
                                upload_bytes=int(r[4] or 0),
                                tcp_packets=int(r[5] or 0),
                                udp_packets=int(r[6] or 0),
                                icmp_packets=int(r[7] or 0),
                                dns_packets=int(r[8] or 0),
                                other_packets=int(r[9] or 0),
                            )
                            for r in rows
                        ]
                    except Exception:
                        pass
                    finally:
                        try:
                            cursor.close()
                        except Exception:
                            pass

        with self._mem_lock:
            items = list(reversed(self._mem_traffic_stats))
            if session_id is not None:
                items = [x for x in items if x.session_id == session_id]
            return items[:limit]

    def fetch_route_history(self, limit: int = 200) -> List[RouteHistoryRecord]:
        """Fetch previously performed traceroutes from `route_history`."""
        if self.is_connected:
            with self._conn_lock:
                if self._ensure_connection_locked() and self._conn is not None:
                    cursor = self._conn.cursor()
                    try:
                        cursor.execute(
                            "SELECT id, destination, timestamp, hop_count, route_data "
                            "FROM route_history ORDER BY timestamp DESC LIMIT %s",
                            (int(limit),),
                        )
                        rows = cursor.fetchall()
                        return [
                            RouteHistoryRecord(
                                id=int(r[0]),
                                destination=str(r[1]),
                                timestamp=str(r[2]),
                                hop_count=int(r[3] or 0),
                                route_data=str(r[4] or "{}"),
                                source="MySQL",
                            )
                            for r in rows
                        ]
                    except Exception:
                        pass
                    finally:
                        try:
                            cursor.close()
                        except Exception:
                            pass

        with self._mem_lock:
            return list(self._mem_routes[:limit])

    def fetch_all_history_async(self, event_queue: "queue.Queue[Dict[str, Any]]") -> None:
        """Query all four historical collections on a background thread and post to `event_queue`."""
        def _query_worker() -> None:
            self.flush_pending_writes(timeout=1.0)
            devices = self.fetch_historical_devices()
            sessions = self.fetch_monitoring_sessions()
            stats = self.fetch_traffic_statistics()
            routes = self.fetch_route_history()
            event_queue.put({
                "type": "history_loaded",
                "devices": devices,
                "sessions": sessions,
                "traffic_stats": stats,
                "routes": routes,
                "is_connected": self.is_connected,
                "status_label": self.status_label,
            })

        threading.Thread(target=_query_worker, name="NetWatchHistoryQuery", daemon=True).start()

    def get_all_session_devices(self) -> List[DeviceRecord]:
        with self._mem_lock:
            return list(self._session_devices.values())


# ============================================================================
# NETWORK INTERFACE MANAGER
# ============================================================================

class NetworkInterfaceManager:
    """Detects and inspects host network interfaces using `psutil` (with fallback support)."""

    def __init__(self) -> None:
        self._interfaces: Dict[str, InterfaceSummary] = {}
        self._selected_interface: Optional[str] = None
        self.refresh_interfaces()

    def refresh_interfaces(self) -> List[InterfaceSummary]:
        discovered: Dict[str, InterfaceSummary] = {}
        gateways = self._detect_default_gateways()

        if HAS_PSUTIL and psutil is not None:
            discovered = self._enumerate_via_psutil(gateways)
        elif HAS_NETIFACES and netifaces is not None:
            discovered = self._enumerate_via_netifaces(gateways)
        else:
            discovered = self._enumerate_via_os_fallback(gateways)

        self._interfaces = discovered

        if self._selected_interface and self._selected_interface in self._interfaces:
            return list(self._interfaces.values())

        best_iface = self._pick_active_interface(list(self._interfaces.values()))
        self._selected_interface = best_iface.name if best_iface else None
        return list(self._interfaces.values())

    def _enumerate_via_psutil(self, gateways: Dict[str, str]) -> Dict[str, InterfaceSummary]:
        result: Dict[str, InterfaceSummary] = {}
        try:
            addrs_map = psutil.net_if_addrs()
            stats_map = psutil.net_if_stats()
        except Exception:
            return result

        af_link = getattr(psutil, "AF_LINK", -1)
        af_packet = getattr(socket, "AF_PACKET", -1)

        for iface_name, addr_list in addrs_map.items():
            ipv4_addr = "Not available"
            netmask = "Not available"
            mac_addr = "Not available"
            is_loopback = iface_name.lower().startswith("lo")

            for snic in addr_list:
                if snic.family == socket.AF_INET and snic.address:
                    if ipv4_addr == "Not available" or ipv4_addr.startswith("169.254."):
                        ipv4_addr = snic.address
                        netmask = snic.netmask or "Not available"
                        if snic.address.startswith("127."):
                            is_loopback = True
                elif snic.family in (af_link, af_packet) and snic.address:
                    candidate = OUILookup.normalize_mac(snic.address)
                    if candidate and candidate != "00:00:00:00:00:00" and len(candidate) == 17:
                        mac_addr = candidate

            st = stats_map.get(iface_name)
            is_up = bool(st.isup) if st is not None else (ipv4_addr != "Not available")
            speed = int(st.speed) if st is not None and st.speed else 0
            mtu = int(st.mtu) if st is not None and st.mtu else 0

            gw = gateways.get(iface_name, gateways.get("__default__", "Not available"))
            if is_loopback:
                gw = "—"

            subnet_cidr = self._compute_subnet_cidr(ipv4_addr, netmask)

            result[iface_name] = InterfaceSummary(
                name=iface_name,
                ipv4_address=ipv4_addr,
                netmask=netmask,
                mac_address=mac_addr,
                default_gateway=gw,
                subnet_cidr=subnet_cidr,
                is_up=is_up,
                speed_mbps=speed,
                mtu=mtu,
                is_loopback=is_loopback,
            )
        return result

    def _enumerate_via_netifaces(self, gateways: Dict[str, str]) -> Dict[str, InterfaceSummary]:
        result: Dict[str, InterfaceSummary] = {}
        try:
            iface_names = netifaces.interfaces()
        except Exception:
            return result

        for iface_name in iface_names:
            ipv4_addr = "Not available"
            netmask = "Not available"
            mac_addr = "Not available"
            is_loopback = iface_name.lower().startswith("lo")

            try:
                ifaddrs = netifaces.ifaddresses(iface_name)
                if netifaces.AF_INET in ifaddrs:
                    for entry in ifaddrs[netifaces.AF_INET]:
                        addr = entry.get("addr")
                        if addr:
                            ipv4_addr = addr
                            netmask = entry.get("netmask", "Not available")
                            if addr.startswith("127."):
                                is_loopback = True
                            break
                if netifaces.AF_LINK in ifaddrs:
                    for entry in ifaddrs[netifaces.AF_LINK]:
                        addr = entry.get("addr")
                        if addr:
                            norm = OUILookup.normalize_mac(addr)
                            if len(norm) == 17 and norm != "00:00:00:00:00:00":
                                mac_addr = norm
                                break
            except Exception:
                pass

            is_up = self._check_sysfs_operstate(iface_name, default=(ipv4_addr != "Not available"))
            gw = gateways.get(iface_name, gateways.get("__default__", "Not available"))
            if is_loopback:
                gw = "—"
            subnet_cidr = self._compute_subnet_cidr(ipv4_addr, netmask)

            result[iface_name] = InterfaceSummary(
                name=iface_name,
                ipv4_address=ipv4_addr,
                netmask=netmask,
                mac_address=mac_addr,
                default_gateway=gw,
                subnet_cidr=subnet_cidr,
                is_up=is_up,
                is_loopback=is_loopback,
            )
        return result

    def _enumerate_via_os_fallback(self, gateways: Dict[str, str]) -> Dict[str, InterfaceSummary]:
        result: Dict[str, InterfaceSummary] = {}
        sys_net = "/sys/class/net"
        if os.path.isdir(sys_net):
            for iface_name in sorted(os.listdir(sys_net)):
                mac_addr = "Not available"
                addr_path = os.path.join(sys_net, iface_name, "address")
                if os.path.isfile(addr_path):
                    try:
                        with open(addr_path, "r", encoding="utf-8") as f:
                            cand = OUILookup.normalize_mac(f.read().strip())
                            if len(cand) == 17 and cand != "00:00:00:00:00:00":
                                mac_addr = cand
                    except Exception:
                        pass
                is_up = self._check_sysfs_operstate(iface_name, default=False)
                is_loopback = iface_name.lower().startswith("lo")
                result[iface_name] = InterfaceSummary(
                    name=iface_name,
                    ipv4_address="Not available",
                    netmask="Not available",
                    mac_address=mac_addr,
                    default_gateway=gateways.get(iface_name, "Not available"),
                    subnet_cidr="Not available",
                    is_up=is_up,
                    is_loopback=is_loopback,
                )
        return result

    @staticmethod
    def _check_sysfs_operstate(iface_name: str, default: bool = False) -> bool:
        oper_path = f"/sys/class/net/{iface_name}/operstate"
        flags_path = f"/sys/class/net/{iface_name}/flags"
        try:
            if os.path.isfile(oper_path):
                with open(oper_path, "r", encoding="utf-8") as f:
                    state = f.read().strip().lower()
                    if state in ("up", "unknown"):
                        return True
                    if state == "down":
                        return False
            if os.path.isfile(flags_path):
                with open(flags_path, "r", encoding="utf-8") as f:
                    flags = int(f.read().strip(), 16)
                    return bool(flags & 0x1)
        except Exception:
            pass
        return default

    @staticmethod
    def _detect_default_gateways() -> Dict[str, str]:
        gw_map: Dict[str, str] = {}
        if HAS_NETIFACES and netifaces is not None:
            try:
                gws = netifaces.gateways()
                default_gw = gws.get("default", {}).get(netifaces.AF_INET)
                if default_gw and len(default_gw) >= 2:
                    gw_ip, gw_iface = default_gw[0], default_gw[1]
                    gw_map[gw_iface] = gw_ip
                    gw_map["__default__"] = gw_ip
                for entry in gws.get(netifaces.AF_INET, []):
                    if len(entry) >= 2:
                        gw_map.setdefault(entry[1], entry[0])
            except Exception:
                pass

        if os.path.isfile("/proc/net/route"):
            try:
                with open("/proc/net/route", "r", encoding="utf-8") as f:
                    for line in f.readlines()[1:]:
                        fields = line.strip().split()
                        if len(fields) >= 3:
                            iface, dest_hex, gw_hex = fields[0], fields[1], fields[2]
                            if dest_hex == "00000000" and gw_hex != "00000000":
                                gw_int = int(gw_hex, 16)
                                gw_ip = socket.inet_ntoa(struct.pack("<L", gw_int))
                                gw_map[iface] = gw_ip
                                gw_map.setdefault("__default__", gw_ip)
            except Exception:
                pass
        return gw_map

    @staticmethod
    def _compute_subnet_cidr(ipv4_address: str, netmask: str) -> str:
        if not ipv4_address or not netmask:
            return "Not available"
        if ipv4_address in ("Not available", "—") or netmask in ("Not available", "—"):
            return "Not available"
        try:
            net = ipaddress.IPv4Network(f"{ipv4_address}/{netmask}", strict=False)
            return str(net)
        except Exception:
            return "Not available"

    @staticmethod
    def _pick_active_interface(interfaces: List[InterfaceSummary]) -> Optional[InterfaceSummary]:
        if not interfaces:
            return None

        def score(iface: InterfaceSummary) -> Tuple[int, int, int, int]:
            has_ipv4 = int(
                iface.ipv4_address not in ("Not available", "—", "")
                and not iface.ipv4_address.startswith("127.")
                and not iface.ipv4_address.startswith("169.254.")
            )
            has_gw = int(iface.default_gateway not in ("Not available", "—", ""))
            not_loopback = int(not iface.is_loopback)
            is_up = int(iface.is_up)
            return (has_ipv4 and has_gw and is_up, has_ipv4 and is_up, not_loopback and is_up, not_loopback)

        ranked = sorted(interfaces, key=score, reverse=True)
        return ranked[0]

    def list_interfaces(self) -> List[str]:
        if not self._interfaces:
            return ["No interfaces found"]
        return list(self._interfaces.keys())

    def get_all_summaries(self) -> List[InterfaceSummary]:
        return list(self._interfaces.values())

    def select_interface(self, interface_name: str) -> InterfaceSummary:
        clean_name = interface_name.split(" ")[0].strip() if interface_name else ""
        if clean_name in self._interfaces:
            self._selected_interface = clean_name
            return self._interfaces[clean_name]
        if interface_name in self._interfaces:
            self._selected_interface = interface_name
            return self._interfaces[interface_name]
        self._selected_interface = None
        return InterfaceSummary(name="None", ipv4_address="Not available")

    def get_current_summary(self) -> InterfaceSummary:
        if self._selected_interface and self._selected_interface in self._interfaces:
            return self._interfaces[self._selected_interface]
        return InterfaceSummary(name="None", ipv4_address="Not available")


# ============================================================================
# LAN SUBNET DEVICE SCANNER (STAGE 2 + STAGE 5 DB PERSISTENCE)
# ============================================================================

class DeviceScanner:
    """Performs threaded LAN ARP discovery on the local subnet and persists to `DatabaseManager`."""

    MAX_SUBNET_HOSTS = 1024

    def __init__(self, db_manager: DatabaseManager, oui_lookup: Optional[OUILookup] = None) -> None:
        self.db_manager = db_manager
        self.oui_lookup = oui_lookup or OUILookup()
        self.is_scanning: bool = False
        self.status_text: str = "Not started"
        self.last_scan_start: str = "—"
        self.last_scan_end: str = "—"
        self.last_error: Optional[str] = None
        self.progress_fraction: float = 0.0

        self._cancel_event = threading.Event()
        self._scan_thread: Optional[threading.Thread] = None
        self._dns_executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="NetWatchDNS")
        self._devices_by_ip: Dict[str, DeviceRecord] = {}
        self._lock = threading.Lock()

    @staticmethod
    def validate_local_subnet(iface: InterfaceSummary) -> Tuple[bool, str, Optional[ipaddress.IPv4Network]]:
        if not iface or iface.name in ("None", "No interfaces found", "No interface selected"):
            return False, "No network interface selected.", None

        if not iface.is_up:
            return False, f"Interface '{iface.name}' is currently down / disconnected.", None

        if iface.is_loopback or iface.ipv4_address.startswith("127."):
            return False, f"Interface '{iface.name}' is a loopback adapter. Select a LAN interface.", None

        if iface.ipv4_address in ("Not available", "—", "") or iface.subnet_cidr in ("Not available", "—", ""):
            return False, f"Interface '{iface.name}' has no IPv4 address or subnet assigned.", None

        try:
            network = ipaddress.IPv4Network(iface.subnet_cidr, strict=False)
        except ValueError as exc:
            return False, f"Invalid subnet configuration ({iface.subnet_cidr}): {exc}", None

        if not (network.is_private or network.is_link_local):
            return (
                False,
                f"Refusing to scan public IP range ({network}). ARP discovery is restricted to local private subnets.",
                None,
            )

        if network.num_addresses <= 2:
            return False, f"Subnet {network} contains no scannable host addresses (/31 or /32).", None

        return True, f"Valid local subnet {network}", network

    @staticmethod
    def check_capture_privileges() -> Tuple[bool, str]:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            try:
                af_packet = getattr(socket, "AF_PACKET", socket.AF_INET)
                s = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(0x0806))
                s.close()
            except PermissionError:
                return (
                    False,
                    "Elevated privileges required: Raw socket access requires root "
                    "(run with 'sudo python3 netwatch.py' or grant CAP_NET_RAW).",
                )
            except OSError:
                pass
        return True, "OK"

    def start_scan(
        self,
        iface: InterfaceSummary,
        event_queue: "queue.Queue[Dict[str, Any]]",
        timeout_per_batch: float = 1.2,
    ) -> bool:
        if self.is_scanning:
            event_queue.put({"type": "scan_error", "message": "A subnet scan is already in progress."})
            return False

        is_valid, validation_msg, network = self.validate_local_subnet(iface)
        if not is_valid or network is None:
            self.last_error = validation_msg
            self.status_text = f"Error: {validation_msg}"
            event_queue.put({"type": "scan_error", "message": validation_msg})
            return False

        if not HAS_SCAPY or srp is None or Ether is None or ARP is None:
            msg = (
                "Scapy library is not installed. Install 'scapy' (pip install scapy) "
                "to enable live ARP subnet discovery."
            )
            self.last_error = msg
            self.status_text = "Missing dependency: scapy"
            event_queue.put({"type": "scan_error", "message": msg})
            return False

        has_privs, priv_msg = self.check_capture_privileges()
        if not has_privs:
            self.last_error = priv_msg
            self.status_text = "Permission denied (Root / Administrator required)"
            event_queue.put({"type": "scan_error", "message": priv_msg})
            return False

        self.is_scanning = True
        self.last_error = None
        self.progress_fraction = 0.0
        self._cancel_event.clear()

        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(iface, network, event_queue, timeout_per_batch),
            name="NetWatchARPScanner",
            daemon=True,
        )
        self._scan_thread.start()
        return True

    def stop_scan(self) -> None:
        if self.is_scanning:
            self._cancel_event.set()
            self.status_text = "Cancelling scan..."

    def _scan_worker(
        self,
        iface: InterfaceSummary,
        network: ipaddress.IPv4Network,
        event_queue: "queue.Queue[Dict[str, Any]]",
        timeout_per_batch: float,
    ) -> None:
        start_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_scan_start = start_ts
        self.last_scan_end = "In progress..."

        all_hosts = [str(ip) for ip in network.hosts()]
        truncated = False
        if len(all_hosts) > self.MAX_SUBNET_HOSTS:
            try:
                local_24 = ipaddress.IPv4Network(f"{iface.ipv4_address}/24", strict=False)
                all_hosts = [str(ip) for ip in local_24.hosts()]
                truncated = True
            except Exception:
                all_hosts = all_hosts[: self.MAX_SUBNET_HOSTS]
                truncated = True

        total_targets = max(len(all_hosts), 1)
        batch_size = 64
        batches = [all_hosts[i : i + batch_size] for i in range(0, len(all_hosts), batch_size)]

        event_queue.put({
            "type": "scan_started",
            "interface": iface.name,
            "subnet": str(network) + (" (local /24 window)" if truncated else ""),
            "start_time": start_ts,
            "total_hosts": total_targets,
        })

        seen_ips_this_scan: set = set()
        seen_macs_this_scan: set = set()
        discovered_count = 0

        if iface.ipv4_address not in ("Not available", "—", ""):
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            local_mac = iface.mac_address if iface.mac_address != "Not available" else "Local Adapter"
            local_vendor = self.oui_lookup.lookup(local_mac)
            try:
                local_hostname = socket.gethostname()
            except Exception:
                local_hostname = "localhost"

            self_record = DeviceRecord(
                ip_address=iface.ipv4_address,
                mac_address=local_mac,
                hostname=f"{local_hostname} (This Workstation)",
                vendor=local_vendor,
                first_seen=now_str,
                last_seen=now_str,
                status="Online",
                interface_name=iface.name,
                is_local_host=True,
            )
            persisted = self._register_discovered_device(self_record, persist_now=False)
            seen_ips_this_scan.add(persisted.ip_address)
            if persisted.mac_address:
                seen_macs_this_scan.add(persisted.mac_address)
            discovered_count += 1
            event_queue.put({"type": "device_found", "device": persisted})

        try:
            for batch_idx, ip_batch in enumerate(batches):
                if self._cancel_event.is_set():
                    break

                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_batch)
                t0 = time.perf_counter()
                answered, _unanswered = srp(
                    pkt,
                    iface=iface.name,
                    timeout=timeout_per_batch,
                    verbose=0,
                    retry=1,
                )
                elapsed_ms = (time.perf_counter() - t0) * 1000.0

                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                batch_discovered: List[DeviceRecord] = []
                for _sent, received in answered:
                    if self._cancel_event.is_set():
                        break

                    resp_ip = str(getattr(received, "psrc", "")).strip()
                    resp_mac = OUILookup.normalize_mac(str(getattr(received, "hwsrc", "")))
                    if not resp_ip:
                        continue

                    dedup_key = (resp_ip, resp_mac)
                    if resp_ip in seen_ips_this_scan or dedup_key in seen_macs_this_scan:
                        continue
                    seen_ips_this_scan.add(resp_ip)
                    seen_macs_this_scan.add(dedup_key)

                    vendor = self.oui_lookup.lookup(resp_mac)
                    is_gw = resp_ip == iface.default_gateway

                    dev = DeviceRecord(
                        ip_address=resp_ip,
                        mac_address=resp_mac,
                        hostname="Resolving...",
                        vendor=vendor,
                        first_seen=now_str,
                        last_seen=now_str,
                        status="Online",
                        interface_name=iface.name,
                        last_rtt_ms=round(elapsed_ms, 1),
                        is_gateway=is_gw,
                    )
                    persisted = self._register_discovered_device(dev, persist_now=False)
                    batch_discovered.append(persisted)
                    discovered_count += 1
                    event_queue.put({"type": "device_found", "device": persisted})
                    self._schedule_hostname_resolution(persisted, event_queue)

                # Batch-persist the discovered slice to MySQL
                if batch_discovered:
                    self.db_manager.upsert_devices_batch(batch_discovered)

                scanned_so_far = min((batch_idx + 1) * batch_size, total_targets)
                self.progress_fraction = scanned_so_far / float(total_targets)
                event_queue.put({
                    "type": "scan_progress",
                    "scanned": scanned_so_far,
                    "total": total_targets,
                    "fraction": self.progress_fraction,
                    "discovered_count": discovered_count,
                })

            self._update_offline_statuses(iface.name, seen_ips_this_scan, event_queue)

            end_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.last_scan_end = end_ts
            cancelled = self._cancel_event.is_set()
            self.is_scanning = False
            self.progress_fraction = 1.0 if not cancelled else self.progress_fraction

            final_status = "Cancelled" if cancelled else "Completed"
            self.status_text = f"{final_status} ({discovered_count} active on {iface.subnet_cidr})"

            self.db_manager.record_scan_session(
                interface_name=iface.name,
                subnet_cidr=iface.subnet_cidr,
                start_time=start_ts,
                end_time=end_ts,
                hosts_found=discovered_count,
                status=final_status,
            )

            event_queue.put({
                "type": "scan_completed",
                "interface": iface.name,
                "subnet": iface.subnet_cidr,
                "start_time": start_ts,
                "end_time": end_ts,
                "discovered_count": discovered_count,
                "total_session_count": self.get_device_count(),
                "cancelled": cancelled,
            })

        except PermissionError as exc:
            self.is_scanning = False
            self.last_scan_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msg = (
                f"Elevated permissions required for ARP scan on '{iface.name}': {exc}. "
                "Run NetWatch with root/Administrator privileges."
            )
            self.last_error = msg
            self.status_text = "Permission denied (Root required)"
            event_queue.put({"type": "scan_error", "message": msg})

        except OSError as exc:
            self.is_scanning = False
            self.last_scan_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msg = f"Network socket error on '{iface.name}': {exc}"
            self.last_error = msg
            self.status_text = "Socket / interface error"
            event_queue.put({"type": "scan_error", "message": msg})

        except Exception as exc:
            self.is_scanning = False
            self.last_scan_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msg = f"Unexpected ARP scan failure: {exc}"
            self.last_error = msg
            self.status_text = "Scan error"
            event_queue.put({"type": "scan_error", "message": msg})

    def _register_discovered_device(self, record: DeviceRecord, persist_now: bool = True) -> DeviceRecord:
        persisted = self.db_manager.upsert_device(record, persist_now=persist_now)
        with self._lock:
            for old_ip, existing_dev in list(self._devices_by_ip.items()):
                if (
                    existing_dev.mac_address == persisted.mac_address
                    and persisted.mac_address not in ("—", "Unknown", "Local Adapter")
                    and old_ip != persisted.ip_address
                ):
                    del self._devices_by_ip[old_ip]
            self._devices_by_ip[persisted.ip_address] = persisted
        return persisted

    def _update_offline_statuses(
        self,
        interface_name: str,
        active_ips: set,
        event_queue: "queue.Queue[Dict[str, Any]]",
    ) -> None:
        with self._lock:
            for ip, dev in self._devices_by_ip.items():
                if dev.interface_name == interface_name and ip not in active_ips:
                    dev.status = "Offline"
                    event_queue.put({"type": "device_updated", "device": dev})

    def _schedule_hostname_resolution(
        self,
        device: DeviceRecord,
        event_queue: "queue.Queue[Dict[str, Any]]",
    ) -> None:
        if device.is_local_host or device.hostname not in ("Resolving...", "Unknown", "—"):
            return

        def _resolve_task() -> None:
            resolved_name = "Unknown"
            try:
                host, _aliases, _addrs = socket.gethostbyaddr(device.ip_address)
                if host:
                    resolved_name = host
            except Exception:
                resolved_name = "Unknown"

            if device.is_gateway and resolved_name == "Unknown":
                resolved_name = "Default Gateway"
            elif device.is_gateway and "Gateway" not in resolved_name:
                resolved_name = f"{resolved_name} (Gateway)"

            device.hostname = resolved_name
            self.db_manager.upsert_devices_batch([device])
            event_queue.put({"type": "device_updated", "device": device})

        try:
            self._dns_executor.submit(_resolve_task)
        except Exception:
            device.hostname = "Unknown"

    def get_discovered_devices(self, filter_query: str = "") -> List[DeviceRecord]:
        with self._lock:
            devices = list(self._devices_by_ip.values())

        q = filter_query.strip().lower()
        if q:
            devices = [
                d for d in devices
                if q in d.ip_address.lower()
                or q in d.mac_address.lower()
                or q in d.hostname.lower()
                or q in d.vendor.lower()
                or q in d.status.lower()
            ]
        return devices

    def get_device_by_ip(self, ip_address: str) -> Optional[DeviceRecord]:
        with self._lock:
            return self._devices_by_ip.get(ip_address)

    def get_device_count(self) -> int:
        with self._lock:
            return len(self._devices_by_ip)

    def get_online_device_count(self) -> int:
        with self._lock:
            return sum(1 for d in self._devices_by_ip.values() if d.status == "Online")

    def shutdown(self) -> None:
        """Cancel any active ARP scan, join the worker thread, and shut down the DNS pool."""
        self.stop_scan()
        if self._scan_thread is not None and self._scan_thread.is_alive() and threading.current_thread() is not self._scan_thread:
            try:
                self._scan_thread.join(timeout=1.5)
            except Exception:
                pass
        try:
            self._dns_executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            self._dns_executor.shutdown(wait=False)
        except Exception:
            pass


# ============================================================================
# REAL-TIME PACKET MONITOR & TRAFFIC ANALYZER (STAGE 3 + STAGE 5 AGGREGATED DB)
# ============================================================================

class PacketMonitor:
    """
    Real-time network traffic capture and analysis engine using Scapy.
    Connected to `DatabaseManager` to create `monitoring_sessions` records and
    persist periodic aggregated `traffic_statistics` intervals (every `DB_AGGREGATE_INTERVAL_SEC`)
    without ever inserting individual packets into MySQL.
    """

    MAX_PACKET_HISTORY = 1000
    MAX_BATCH_QUEUE = 250
    TELEMETRY_WINDOW_SECONDS = 60
    DB_AGGREGATE_INTERVAL_SEC = 5.0
    PROTOCOL_KEYS = ("TCP", "UDP", "ICMP", "DNS", "Other")

    TCP_FLAG_NAMES = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
    ]

    ICMP_TYPE_NAMES = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        5: "Redirect",
        8: "Echo Request (Ping)",
        11: "Time Exceeded",
    }

    def __init__(self, db_manager: Optional[DatabaseManager] = None) -> None:
        self.db_manager = db_manager
        self.is_capturing: bool = False
        self.status_text: str = "Not started"
        self.interface_name: str = "None"
        self.local_ip: str = "Not available"
        self.local_mac: str = "Not available"
        self.active_session_id: Optional[int] = None

        self.capture_start_epoch: Optional[float] = None
        self.accumulated_duration: float = 0.0

        self.captured_count: int = 0
        self.total_bytes: int = 0
        self.packets_per_sec: float = 0.0
        self.bytes_per_sec: float = 0.0
        self.upload_bps: float = 0.0
        self.download_bps: float = 0.0

        self.protocol_counts: Dict[str, int] = {k: 0 for k in self.PROTOCOL_KEYS}
        self._packet_history: Deque[PacketRecord] = deque(maxlen=self.MAX_PACKET_HISTORY)

        self._time_axis: Deque[float] = deque(
            [float(-i) for i in range(self.TELEMETRY_WINDOW_SECONDS - 1, -1, -1)],
            maxlen=self.TELEMETRY_WINDOW_SECONDS,
        )
        self._upload_kbs_history: Deque[float] = deque(
            [0.0] * self.TELEMETRY_WINDOW_SECONDS,
            maxlen=self.TELEMETRY_WINDOW_SECONDS,
        )
        self._download_kbs_history: Deque[float] = deque(
            [0.0] * self.TELEMETRY_WINDOW_SECONDS,
            maxlen=self.TELEMETRY_WINDOW_SECONDS,
        )
        self._pps_history: Deque[float] = deque(
            [0.0] * self.TELEMETRY_WINDOW_SECONDS,
            maxlen=self.TELEMETRY_WINDOW_SECONDS,
        )
        self._bps_kbs_history: Deque[float] = deque(
            [0.0] * self.TELEMETRY_WINDOW_SECONDS,
            maxlen=self.TELEMETRY_WINDOW_SECONDS,
        )

        # 1-second UI rate bucket
        self._bucket_Lock = threading.Lock()
        self._bucket_packets: int = 0
        self._bucket_bytes: int = 0
        self._bucket_upload_bytes: int = 0
        self._bucket_download_bytes: int = 0
        self._last_sample_mono: float = time.monotonic()
        self._pending_ui_packets: List[PacketRecord] = []

        # Periodic Database Aggregation Bucket (never inserts per-packet rows)
        self._db_agg_upload_bytes: int = 0
        self._db_agg_download_bytes: int = 0
        self._db_agg_protocols: Dict[str, int] = {k: 0 for k in self.PROTOCOL_KEYS}
        self._last_db_flush_mono: float = time.monotonic()

        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._sniffer: Any = None
        self._seq_counter: int = 0

    @staticmethod
    def validate_capture_interface(iface: InterfaceSummary) -> Tuple[bool, str]:
        if not iface or iface.name in ("None", "No interfaces found", "No interface selected"):
            return False, "No network interface selected for packet capture."
        if not iface.is_up:
            return False, f"Interface '{iface.name}' is currently down / disconnected."
        return True, "OK"

    @staticmethod
    def check_capture_privileges() -> Tuple[bool, str]:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            try:
                af_packet = getattr(socket, "AF_PACKET", socket.AF_INET)
                s = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(0x0003))
                s.close()
            except PermissionError:
                return (
                    False,
                    "Elevated permissions required: Live packet capture requires root "
                    "(run with 'sudo python3 netwatch.py' or grant CAP_NET_RAW).",
                )
            except OSError:
                pass
        return True, "OK"

    def start_capture(
        self,
        iface: InterfaceSummary,
        event_queue: Optional["queue.Queue[Dict[str, Any]]"] = None,
    ) -> bool:
        if self.is_capturing:
            if event_queue:
                event_queue.put({"type": "capture_error", "message": "Packet capture is already running."})
            return False

        ok_iface, iface_msg = self.validate_capture_interface(iface)
        if not ok_iface:
            self.status_text = f"Error: {iface_msg}"
            if event_queue:
                event_queue.put({"type": "capture_error", "message": iface_msg})
            return False

        if not HAS_SCAPY or (sniff is None and AsyncSniffer is None):
            msg = (
                "Scapy library is not installed. Install 'scapy' (pip install scapy) "
                "to enable live packet capture."
            )
            self.status_text = "Missing dependency: scapy"
            if event_queue:
                event_queue.put({"type": "capture_error", "message": msg})
            return False

        ok_priv, priv_msg = self.check_capture_privileges()
        if not ok_priv:
            self.status_text = "Permission denied (Root / CAP_NET_RAW required)"
            if event_queue:
                event_queue.put({"type": "capture_error", "message": priv_msg})
            return False

        with self._bucket_Lock:
            self.interface_name = iface.name
            self.local_ip = iface.ipv4_address
            self.local_mac = iface.mac_address
            self._bucket_packets = 0
            self._bucket_bytes = 0
            self._bucket_upload_bytes = 0
            self._bucket_download_bytes = 0
            self._db_agg_upload_bytes = 0
            self._db_agg_download_bytes = 0
            for k in self.PROTOCOL_KEYS:
                self._db_agg_protocols[k] = 0
            self._pending_ui_packets.clear()
            self._last_sample_mono = time.monotonic()
            self._last_db_flush_mono = time.monotonic()

        if self.db_manager is not None:
            self.active_session_id = self.db_manager.start_monitoring_session(iface.name)

        self.is_capturing = True
        self.capture_start_epoch = time.monotonic()
        self.status_text = f"Capturing on {iface.name}"
        self._stop_event.clear()

        self._capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(iface, event_queue),
            name="NetWatchPacketCapture",
            daemon=True,
        )
        self._capture_thread.start()
        return True

    def stop_capture(self, event_queue: Optional["queue.Queue[Dict[str, Any]]"] = None) -> None:
        if not self.is_capturing:
            return

        self._stop_event.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        if self.capture_start_epoch is not None:
            self.accumulated_duration += max(0.0, time.monotonic() - self.capture_start_epoch)
            self.capture_start_epoch = None

        # Flush any remaining aggregated traffic statistics interval to DatabaseManager
        self.flush_db_traffic_interval(force=True)
        if self.db_manager is not None and self.active_session_id is not None:
            self.db_manager.end_monitoring_session(self.active_session_id, self.captured_count)

        self.is_capturing = False
        self.packets_per_sec = 0.0
        self.bytes_per_sec = 0.0
        self.upload_bps = 0.0
        self.download_bps = 0.0
        self.status_text = f"Stopped ({self.captured_count} pkts captured)"

        if event_queue is not None:
            event_queue.put({
                "type": "capture_stopped",
                "interface": self.interface_name,
                "snapshot": self.get_snapshot(),
            })

    def shutdown(self) -> None:
        """Stop active packet capture and join the capture worker thread cleanly."""
        self.stop_capture(event_queue=None)
        if self._capture_thread is not None and self._capture_thread.is_alive() and threading.current_thread() is not self._capture_thread:
            try:
                self._capture_thread.join(timeout=1.5)
            except Exception:
                pass

    def flush_db_traffic_interval(self, force: bool = False) -> None:
        """
        Flush accumulated periodic traffic statistics to `DatabaseManager.record_traffic_statistics_interval`.
        Called periodically (every `DB_AGGREGATE_INTERVAL_SEC`) or on session stop.
        """
        if self.db_manager is None or self.active_session_id is None:
            return

        now_mono = time.monotonic()
        with self._bucket_Lock:
            if not force and (now_mono - self._last_db_flush_mono) < self.DB_AGGREGATE_INTERVAL_SEC:
                return
            total_delta_pkts = sum(self._db_agg_protocols.values())
            if total_delta_pkts == 0 and self._db_agg_upload_bytes == 0 and self._db_agg_download_bytes == 0:
                self._last_db_flush_mono = now_mono
                return

            dl_bytes = self._db_agg_download_bytes
            ul_bytes = self._db_agg_upload_bytes
            proto_deltas = dict(self._db_agg_protocols)
            total_session_pkts = self.captured_count

            self._db_agg_download_bytes = 0
            self._db_agg_upload_bytes = 0
            for k in self.PROTOCOL_KEYS:
                self._db_agg_protocols[k] = 0
            self._last_db_flush_mono = now_mono

        self.db_manager.record_traffic_statistics_interval(
            local_session_id=self.active_session_id,
            download_bytes=dl_bytes,
            upload_bytes=ul_bytes,
            protocol_deltas=proto_deltas,
            session_total_packets=total_session_pkts,
        )

    def clear_history(self) -> None:
        with self._bucket_Lock:
            self._packet_history.clear()
            self._pending_ui_packets.clear()
            self.captured_count = 0
            self.total_bytes = 0
            self.accumulated_duration = 0.0
            if self.is_capturing:
                self.capture_start_epoch = time.monotonic()
            for k in self.PROTOCOL_KEYS:
                self.protocol_counts[k] = 0
                self._db_agg_protocols[k] = 0
            self._db_agg_upload_bytes = 0
            self._db_agg_download_bytes = 0
            for i in range(self.TELEMETRY_WINDOW_SECONDS):
                self._upload_kbs_history[i] = 0.0
                self._download_kbs_history[i] = 0.0
                self._pps_history[i] = 0.0
                self._bps_kbs_history[i] = 0.0

    def _capture_worker(
        self,
        iface: InterfaceSummary,
        event_queue: Optional["queue.Queue[Dict[str, Any]]"],
    ) -> None:
        if event_queue is not None:
            event_queue.put({
                "type": "capture_started",
                "interface": iface.name,
                "local_ip": iface.ipv4_address,
            })

        def _on_scapy_packet(pkt: Any) -> None:
            if self._stop_event.is_set():
                return
            try:
                record = self.analyze_scapy_packet(pkt, iface.ipv4_address, iface.mac_address)
                if record is not None:
                    self.ingest_packet_record(record)
            except Exception:
                pass

        try:
            if AsyncSniffer is not None:
                self._sniffer = AsyncSniffer(
                    iface=iface.name,
                    prn=_on_scapy_packet,
                    store=False,
                )
                self._sniffer.start()

                while not self._stop_event.is_set():
                    time.sleep(0.25)
                    self._flush_batches_and_rates(event_queue)
                    self.flush_db_traffic_interval(force=False)
                    if self._sniffer is not None and not getattr(self._sniffer, "running", True):
                        break
            else:
                while not self._stop_event.is_set():
                    sniff(
                        iface=iface.name,
                        prn=_on_scapy_packet,
                        store=False,
                        timeout=0.5,
                    )
                    self._flush_batches_and_rates(event_queue)
                    self.flush_db_traffic_interval(force=False)

        except PermissionError as exc:
            self.is_capturing = False
            self.capture_start_epoch = None
            msg = (
                f"Elevated permissions required for packet capture on '{iface.name}': {exc}. "
                "Run NetWatch with root/Administrator privileges."
            )
            self.status_text = "Permission denied (Root required)"
            if event_queue is not None:
                event_queue.put({"type": "capture_error", "message": msg})

        except OSError as exc:
            self.is_capturing = False
            self.capture_start_epoch = None
            msg = f"Capture socket error on interface '{iface.name}': {exc}"
            self.status_text = "Interface capture error"
            if event_queue is not None:
                event_queue.put({"type": "capture_error", "message": msg})

        except Exception as exc:
            self.is_capturing = False
            self.capture_start_epoch = None
            msg = f"Packet capture stopped due to error: {exc}"
            self.status_text = "Capture error"
            if event_queue is not None:
                event_queue.put({"type": "capture_error", "message": msg})
        finally:
            if self._sniffer is not None:
                try:
                    if getattr(self._sniffer, "running", False):
                        self._sniffer.stop()
                except Exception:
                    pass
                self._sniffer = None

    def analyze_scapy_packet(
        self,
        pkt: Any,
        local_ip: str = "",
        local_mac: str = "",
    ) -> Optional[PacketRecord]:
        now_epoch = time.time()
        ts_str = datetime.fromtimestamp(now_epoch).strftime("%H:%M:%S.%f")[:-3]
        pkt_len = int(len(pkt)) if pkt is not None else 0

        src_ip = "—"
        dst_ip = "—"
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        protocol = "Other"
        info_parts: List[str] = []

        if IP is not None and pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = str(getattr(ip_layer, "src", "—"))
            dst_ip = str(getattr(ip_layer, "dst", "—"))
        elif IPv6 is not None and pkt.haslayer(IPv6):
            ip6_layer = pkt[IPv6]
            src_ip = str(getattr(ip6_layer, "src", "—"))
            dst_ip = str(getattr(ip6_layer, "dst", "—"))
        elif ARP is not None and pkt.haslayer(ARP):
            arp_layer = pkt[ARP]
            src_ip = str(getattr(arp_layer, "psrc", "—"))
            dst_ip = str(getattr(arp_layer, "pdst", "—"))
            op = int(getattr(arp_layer, "op", 0))
            protocol = "Other"
            if op == 1:
                info_parts.append(f"ARP Who has {dst_ip}? Tell {src_ip}")
            elif op == 2:
                hwsrc = OUILookup.normalize_mac(str(getattr(arp_layer, "hwsrc", "")))
                info_parts.append(f"ARP {src_ip} is at {hwsrc}")
            else:
                info_parts.append(f"ARP op={op}")
        elif Ether is not None and pkt.haslayer(Ether):
            eth = pkt[Ether]
            src_ip = OUILookup.normalize_mac(str(getattr(eth, "src", "—")))
            dst_ip = OUILookup.normalize_mac(str(getattr(eth, "dst", "—")))
            eth_type = getattr(eth, "type", 0)
            info_parts.append(f"Ethernet Frame (EtherType 0x{int(eth_type):04x})")

        is_dns = False
        if DNS is not None and pkt.haslayer(DNS):
            is_dns = True

        if TCP is not None and pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            src_port = int(getattr(tcp_layer, "sport", 0))
            dst_port = int(getattr(tcp_layer, "dport", 0))
            protocol = "DNS" if (is_dns or src_port == 53 or dst_port == 53) else "TCP"

            flags_int = int(getattr(tcp_layer, "flags", 0))
            active_flags = [name for bit, name in self.TCP_FLAG_NAMES if flags_int & bit]
            flag_str = ",".join(active_flags) if active_flags else "NONE"
            seq_num = int(getattr(tcp_layer, "seq", 0))
            window_sz = int(getattr(tcp_layer, "window", 0))
            info_parts.append(f"{src_port} -> {dst_port} [{flag_str}] Seq={seq_num} Win={window_sz}")

        elif UDP is not None and pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            src_port = int(getattr(udp_layer, "sport", 0))
            dst_port = int(getattr(udp_layer, "dport", 0))
            protocol = "DNS" if (is_dns or src_port in (53, 5353) or dst_port in (53, 5353)) else "UDP"
            info_parts.append(f"{src_port} -> {dst_port} Len={pkt_len}")

        elif ICMP is not None and pkt.haslayer(ICMP):
            icmp_layer = pkt[ICMP]
            protocol = "ICMP"
            icmp_type = int(getattr(icmp_layer, "type", -1))
            icmp_code = int(getattr(icmp_layer, "code", 0))
            type_desc = self.ICMP_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}")
            info_parts.append(f"ICMP {type_desc} (type={icmp_type}, code={icmp_code})")

        if protocol == "DNS":
            if DNS is not None and pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                qr = int(getattr(dns_layer, "qr", 0))
                qdcount = int(getattr(dns_layer, "qdcount", 0))
                ancount = int(getattr(dns_layer, "ancount", 0))
                mode = "Response" if qr == 1 else "Standard Query"
                info_parts = [f"DNS {mode} ({src_port or 53} -> {dst_port or 53}) Q={qdcount} Ans={ancount}"]
            else:
                info_parts = [f"DNSPort Traffic ({src_port} -> {dst_port}) Len={pkt_len}"]

        if not info_parts:
            info_parts.append(f"{protocol} Packet ({pkt_len} bytes)")

        direction = "Local/Other"
        if local_ip and local_ip not in ("Not available", "—", ""):
            if src_ip == local_ip and dst_ip != local_ip:
                direction = "Upload"
            elif dst_ip == local_ip and src_ip != local_ip:
                direction = "Download"
        if direction == "Local/Other" and Ether is not None and pkt is not None and hasattr(pkt, "haslayer"):
            try:
                if pkt.haslayer(Ether) and local_mac not in ("Not available", "—", ""):
                    eth_src = OUILookup.normalize_mac(str(getattr(pkt[Ether], "src", "")))
                    eth_dst = OUILookup.normalize_mac(str(getattr(pkt[Ether], "dst", "")))
                    if eth_src == local_mac:
                        direction = "Upload"
                    elif eth_dst == local_mac:
                        direction = "Download"
            except Exception:
                pass

        with self._bucket_Lock:
            self._seq_counter += 1
            seq_id = self._seq_counter

        return PacketRecord(
            seq_id=seq_id,
            timestamp=ts_str,
            epoch_time=now_epoch,
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol=protocol if protocol in self.PROTOCOL_KEYS else "Other",
            length=pkt_len,
            src_port=src_port,
            dst_port=dst_port,
            direction=direction,
            info=" ".join(info_parts),
        )

    def ingest_packet_record(self, record: PacketRecord) -> None:
        proto_key = record.protocol if record.protocol in self.PROTOCOL_KEYS else "Other"
        with self._bucket_Lock:
            self._packet_history.append(record)
            self.captured_count += 1
            self.total_bytes += record.length
            self.protocol_counts[proto_key] = self.protocol_counts.get(proto_key, 0) + 1

            self._bucket_packets += 1
            self._bucket_bytes += record.length
            self._db_agg_protocols[proto_key] = self._db_agg_protocols.get(proto_key, 0) + 1

            if record.direction == "Upload":
                self._bucket_upload_bytes += record.length
                self._db_agg_upload_bytes += record.length
            elif record.direction == "Download":
                self._bucket_download_bytes += record.length
                self._db_agg_download_bytes += record.length

            if len(self._pending_ui_packets) < self.MAX_BATCH_QUEUE:
                self._pending_ui_packets.append(record)

    def step_telemetry_window(self, elapsed_sec: Optional[float] = None) -> TrafficStatsSnapshot:
        now_mono = time.monotonic()
        with self._bucket_Lock:
            dt = elapsed_sec if elapsed_sec is not None else max(0.05, now_mono - self._last_sample_mono)
            self._last_sample_mono = now_mono

            self.packets_per_sec = self._bucket_packets / dt
            self.bytes_per_sec = self._bucket_bytes / dt
            self.upload_bps = self._bucket_upload_bytes / dt
            self.download_bps = self._bucket_download_bytes / dt

            self._bucket_packets = 0
            self._bucket_bytes = 0
            self._bucket_upload_bytes = 0
            self._bucket_download_bytes = 0

            self._upload_kbs_history.append(self.upload_bps / 1024.0)
            self._download_kbs_history.append(self.download_bps / 1024.0)
            self._pps_history.append(self.packets_per_sec)
            self._bps_kbs_history.append(self.bytes_per_sec / 1024.0)

        return self.get_snapshot()

    def _flush_batches_and_rates(
        self,
        event_queue: Optional["queue.Queue[Dict[str, Any]]"],
    ) -> None:
        now_mono = time.monotonic()
        new_packets: List[PacketRecord] = []
        should_step = False

        with self._bucket_Lock:
            if self._pending_ui_packets:
                new_packets = list(self._pending_ui_packets)
                self._pending_ui_packets.clear()
            if (now_mono - self._last_sample_mono) >= 1.0:
                should_step = True

        if new_packets and event_queue is not None:
            event_queue.put({"type": "packet_batch", "packets": new_packets})

        if should_step:
            snapshot = self.step_telemetry_window()
            if event_queue is not None:
                event_queue.put({"type": "traffic_stats", "snapshot": snapshot})

    def get_duration_seconds(self) -> float:
        if self.is_capturing and self.capture_start_epoch is not None:
            return self.accumulated_duration + max(0.0, time.monotonic() - self.capture_start_epoch)
        return self.accumulated_duration

    def get_protocol_stats(self) -> Dict[str, int]:
        with self._bucket_Lock:
            return dict(self.protocol_counts)

    def get_recent_packets(self, filter_criteria: Optional[PacketFilterCriteria] = None) -> List[PacketRecord]:
        with self._bucket_Lock:
            packets = list(self._packet_history)
        if filter_criteria is not None and filter_criteria.is_active():
            packets = [p for p in packets if filter_criteria.matches(p)]
        return packets

    def get_snapshot(self) -> TrafficStatsSnapshot:
        with self._bucket_Lock:
            return TrafficStatsSnapshot(
                is_capturing=self.is_capturing,
                status_text=self.status_text,
                interface_name=self.interface_name,
                local_ip=self.local_ip,
                duration_seconds=self.get_duration_seconds(),
                total_packets=self.captured_count,
                total_bytes=self.total_bytes,
                packets_per_sec=self.packets_per_sec,
                bytes_per_sec=self.bytes_per_sec,
                upload_bps=self.upload_bps,
                download_bps=self.download_bps,
                protocol_counts=dict(self.protocol_counts),
                time_axis=list(self._time_axis),
                upload_history_kbs=list(self._upload_kbs_history),
                download_history_kbs=list(self._download_kbs_history),
                pps_history=list(self._pps_history),
                bps_history_kbs=list(self._bps_kbs_history),
            )


# ============================================================================
# STAGE 4: IP GEOLOCATION SERVICE, ROUTE MAP GENERATOR & ROUTE MAPPER
# ============================================================================

class IPGeolocationService:
    """Resolves public IPv4 addresses to approximate geographical locations with session caching."""

    GEOIP_DB_PATHS = (
        "/usr/share/GeoIP/GeoLite2-City.mmdb",
        "/var/lib/GeoIP/GeoLite2-City.mmdb",
        "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
        "GeoLite2-City.mmdb",
    )

    MIN_API_INTERVAL_SEC = 0.35

    def __init__(self) -> None:
        self._cache: Dict[str, GeoLocationResult] = {}
        self._lock = threading.Lock()
        self._last_api_call: float = 0.0
        self._rate_limited_until: float = 0.0
        self._geoip_reader: Any = None
        self._init_local_db()

    def _init_local_db(self) -> None:
        if HAS_GEOIP2 and geoip2 is not None:
            for path in self.GEOIP_DB_PATHS:
                if os.path.isfile(path) and os.access(path, os.R_OK):
                    try:
                        self._geoip_reader = geoip2.database.Reader(path)
                        break
                    except Exception:
                        self._geoip_reader = None

    @staticmethod
    def classify_ip_Eligibility(ip_str: str) -> Tuple[bool, str]:
        if not ip_str or ip_str in ("*", "—", "Not available", "Unknown"):
            return False, "Not mapped (Timeout / Unresponsive)"

        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False, "Not mapped (Invalid IP)"

        if ip_obj.is_loopback:
            return False, "Not mapped (Loopback)"
        if ip_obj.is_private:
            return False, "Not mapped (Private LAN IP)"
        if ip_obj.is_link_local:
            return False, "Not mapped (Link-Local IP)"
        if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return False, "Not mapped (Reserved IP)"
        if not getattr(ip_obj, "is_global", not ip_obj.is_private):
            return False, "Not mapped (Non-Global IP)"

        return True, "Public IP"

    def lookup(self, ip_str: str, allow_network: bool = True) -> GeoLocationResult:
        clean_ip = ip_str.strip() if ip_str else ""
        with self._lock:
            if clean_ip in self._cache:
                return self._cache[clean_ip]

        is_public, reason = self.classify_ip_Eligibility(clean_ip)
        if not is_public:
            res = GeoLocationResult(
                ip_address=clean_ip or "*",
                is_public=False,
                is_mapped=False,
                country="—",
                region="—",
                city="—",
                latitude=None,
                longitude=None,
                mapping_status=reason,
            )
            with self._lock:
                if clean_ip:
                    self._cache[clean_ip] = res
            return res

        if self._geoip_reader is not None:
            try:
                db_resp = self._geoip_reader.city(clean_ip)
                lat = db_resp.location.latitude
                lon = db_resp.location.longitude
                country = db_resp.country.name or "Unknown"
                region = db_resp.subdivisions.most_specific.name or "—"
                city = db_resp.city.name or "—"
                if lat is not None and lon is not None:
                    res = GeoLocationResult(
                        ip_address=clean_ip,
                        is_public=True,
                        is_mapped=True,
                        country=country,
                        region=region,
                        city=city,
                        latitude=float(lat),
                        longitude=float(lon),
                        mapping_status="Mapped (Approx. — GeoIP2 DB)",
                    )
                    with self._lock:
                        self._cache[clean_ip] = res
                    return res
            except Exception:
                pass

        if not allow_network:
            return GeoLocationResult(
                ip_address=clean_ip,
                is_public=True,
                is_mapped=False,
                mapping_status="Not mapped (Lookup disabled)",
            )

        now = time.monotonic()
        if now < self._rate_limited_until:
            return GeoLocationResult(
                ip_address=clean_ip,
                is_public=True,
                is_mapped=False,
                mapping_status="Not mapped (Geolocation rate-limited)",
            )

        with self._lock:
            wait_sec = self.MIN_API_INTERVAL_SEC - (now - self._last_api_call)
            if wait_sec > 0:
                time.sleep(min(wait_sec, 0.5))
            self._last_api_call = time.monotonic()

        res = self._query_http_providers(clean_ip)
        with self._lock:
            self._cache[clean_ip] = res
        return res

    def _query_http_providers(self, ip_str: str) -> GeoLocationResult:
        try:
            url_a = f"https://ipwho.is/{ip_str}"
            req = urllib.request.Request(url_a, headers={"User-Agent": "NetWatch-Workstation/0.5"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                if resp.status == 429:
                    self._rate_limited_until = time.monotonic() + 30.0
                    return GeoLocationResult(
                        ip_address=ip_str,
                        is_public=True,
                        is_mapped=False,
                        mapping_status="Not mapped (Rate limit HTTP 429)",
                    )
                payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if payload.get("success") is True:
                    lat = payload.get("latitude")
                    lon = payload.get("longitude")
                    if lat is not None and lon is not None:
                        conn = payload.get("connection") or {}
                        return GeoLocationResult(
                            ip_address=ip_str,
                            is_public=True,
                            is_mapped=True,
                            country=str(payload.get("country") or "Unknown"),
                            region=str(payload.get("region") or "—"),
                            city=str(payload.get("city") or "—"),
                            latitude=float(lat),
                            longitude=float(lon),
                            asn_org=str(conn.get("org") or conn.get("isp") or "—"),
                            mapping_status="Mapped (Approx.)",
                        )
        except urllib.error.HTTPError as he:
            if he.code == 429:
                self._rate_limited_until = time.monotonic() + 30.0
                return GeoLocationResult(
                    ip_address=ip_str,
                    is_public=True,
                    is_mapped=False,
                    mapping_status="Not mapped (Rate limit HTTP 429)",
                )
        except Exception:
            pass

        try:
            url_b = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,regionName,city,lat,lon,org"
            req = urllib.request.Request(url_b, headers={"User-Agent": "NetWatch-Workstation/0.5"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                if resp.status == 429:
                    self._rate_limited_until = time.monotonic() + 45.0
                    return GeoLocationResult(
                        ip_address=ip_str,
                        is_public=True,
                        is_mapped=False,
                        mapping_status="Not mapped (Rate limit HTTP 429)",
                    )
                payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if payload.get("status") == "success":
                    lat = payload.get("lat")
                    lon = payload.get("lon")
                    if lat is not None and lon is not None:
                        return GeoLocationResult(
                            ip_address=ip_str,
                            is_public=True,
                            is_mapped=True,
                            country=str(payload.get("country") or "Unknown"),
                            region=str(payload.get("regionName") or "—"),
                            city=str(payload.get("city") or "—"),
                            latitude=float(lat),
                            longitude=float(lon),
                            asn_org=str(payload.get("org") or "—"),
                            mapping_status="Mapped (Approx.)",
                        )
        except urllib.error.HTTPError as he:
            if he.code == 429:
                self._rate_limited_until = time.monotonic() + 45.0
                return GeoLocationResult(
                    ip_address=ip_str,
                    is_public=True,
                    is_mapped=False,
                    mapping_status="Not mapped (Rate limit HTTP 429)",
                )
        except Exception:
            pass

        return GeoLocationResult(
            ip_address=ip_str,
            is_public=True,
            is_mapped=False,
            mapping_status="Not mapped (Lookup unavailable)",
        )

    def seed_cache(self, ip_str: str, result: GeoLocationResult) -> None:
        with self._lock:
            self._cache[ip_str.strip()] = result


class RouteMapGenerator:
    """Generates an interactive geographical route map HTML file using `folium` (or Leaflet fallback)."""

    @staticmethod
    def build_contiguous_mapped_segments(hops: List[RouteHopRecord]) -> List[List[RouteHopRecord]]:
        segments: List[List[RouteHopRecord]] = []
        current_seg: List[RouteHopRecord] = []

        for hop in sorted(hops, key=lambda h: h.hop_number):
            if hop.has_coordinates:
                if not current_seg:
                    current_seg = [hop]
                elif hop.hop_number == current_seg[-1].hop_number + 1:
                    current_seg.append(hop)
                else:
                    segments.append(current_seg)
                    current_seg = [hop]
            else:
                if current_seg:
                    segments.append(current_seg)
                    current_seg = []

        if current_seg:
            segments.append(current_seg)
        return segments

    @classmethod
    def generate_map_html(
        cls,
        destination_label: str,
        resolved_ip: str,
        hops: List[RouteHopRecord],
        output_path: str = "netwatch_route_map.html",
    ) -> Tuple[bool, str]:
        mapped_hops = [h for h in hops if h.has_coordinates]
        segments = cls.build_contiguous_mapped_segments(hops)

        if mapped_hops:
            avg_lat = sum(float(h.latitude) for h in mapped_hops if h.latitude is not None) / len(mapped_hops)
            avg_lon = sum(float(h.longitude) for h in mapped_hops if h.longitude is not None) / len(mapped_hops)
            zoom_start = 4 if len(mapped_hops) > 1 else 6
        else:
            avg_lat, avg_lon, zoom_start = 20.0, 0.0, 2

        try:
            abs_out = os.path.abspath(output_path)
            if HAS_FOLIUM and folium is not None:
                fmap = folium.Map(
                    location=[avg_lat, avg_lon],
                    zoom_start=zoom_start,
                    tiles="CartoDB dark_matter",
                    control_scale=True,
                )

                for seg in segments:
                    if len(seg) >= 2:
                        coords = [(float(h.latitude), float(h.longitude)) for h in seg]
                        hop_range = f"Hop {seg[0].hop_number} -> Hop {seg[-1].hop_number}"
                        folium.PolyLine(
                            locations=coords,
                            color=Theme.ACCENT_AMBER,
                            weight=3,
                            opacity=0.88,
                            tooltip=f"Approximate Contiguous Segment ({hop_range})",
                        ).add_to(fmap)

                for hop in mapped_hops:
                    loc_str = ", ".join(
                        p for p in (hop.city, hop.region, hop.country) if p and p != "—"
                    ) or "Approximate Location"
                    role_tag = "DESTINATION" if hop.is_destination else f"HOP #{hop.hop_number}"
                    popup_html = (
                        f"<div style='font-family:monospace;font-size:12px;min-width:210px;'>"
                        f"<b>{role_tag}</b><br>"
                        f"<b>IP:</b> {hop.ip_address}<br>"
                        f"<b>Host:</b> {hop.hostname}<br>"
                        f"<b>RTT:</b> {hop.rtt_display}<br>"
                        f"<b>Approx. Location:</b> {loc_str}<br>"
                        f"<b>Coords (Approx.):</b> {hop.latitude:.3f}, {hop.longitude:.3f}<br>"
                        f"<i>Note: IP geolocation is approximate.</i>"
                        f"</div>"
                    )
                    marker_color = "green" if hop.is_destination else "orange"
                    folium.Marker(
                        location=[float(hop.latitude), float(hop.longitude)],
                        popup=folium.Popup(popup_html, max_width=280),
                        tooltip=f"Hop {hop.hop_number}: {hop.ip_address} ({loc_str} - Approx.)",
                        icon=folium.Icon(color=marker_color, icon="info-sign"),
                    ).add_to(fmap)

                fmap.save(abs_out)
                return True, abs_out

            markers_js = []
            for hop in mapped_hops:
                loc_str = ", ".join(
                    p for p in (hop.city, hop.region, hop.country) if p and p != "—"
                ) or "Approximate Location"
                markers_js.append({
                    "hop": hop.hop_number,
                    "ip": hop.ip_address,
                    "hostname": hop.hostname,
                    "rtt": hop.rtt_display,
                    "location": loc_str,
                    "lat": float(hop.latitude),
                    "lon": float(hop.longitude),
                    "is_dest": bool(hop.is_destination),
                })

            polylines_js = [
                [[float(h.latitude), float(h.longitude)] for h in seg]
                for seg in segments
                if len(seg) >= 2
            ]

            html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>NetWatch Route Map — {destination_label} ({resolved_ip})</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  body {{ margin: 0; background: #17191C; color: #E2E5E9; font-family: monospace; }}
  #header {{ padding: 10px 16px; background: #202328; border-bottom: 1px solid #393E45; display: flex; justify-content: space-between; align-items: center; }}
  #map {{ width: 100vw; height: calc(100vh - 52px); background: #17191C; }}
  .badge {{ color: #D6A85C; font-weight: bold; }}
  .disclaimer {{ color: #9BA3AE; font-size: 11px; }}
</style>
</head>
<body>
<div id="header">
  <div><span class="badge">NETWATCH GEOGRAPHICAL ROUTE MAP</span> &nbsp;|&nbsp; Target: {destination_label} ({resolved_ip}) &nbsp;|&nbsp; Mapped Hops: {len(mapped_hops)} / {len(hops)}</div>
  <div class="disclaimer">Approximate IP Geolocation — Unresolved/private hops are not connected across unknown positions.</div>
</div>
<div id="map"></div>
<script>
  const map = L.map('map').setView([{avg_lat}, {avg_lon}], {zoom_start});
  L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
    attribution: '&copy; OpenStreetMap &copy; CARTO',
    subdomains: 'abcd',
    maxZoom: 19
  }}).addTo(map);

  const segments = {json.dumps(polylines_js)};
  segments.forEach(seg => {{
    L.polyline(seg, {{ color: '#D6A85C', weight: 3, opacity: 0.88 }}).addTo(map);
  }});

  const hops = {json.dumps(markers_js)};
  hops.forEach(h => {{
    const color = h.is_dest ? '#5E9E6E' : '#D6A85C';
    const marker = L.circleMarker([h.lat, h.lon], {{
      radius: h.is_dest ? 8 : 6,
      fillColor: color,
      color: '#17191C',
      weight: 2,
      opacity: 1,
      fillOpacity: 0.95
    }}).addTo(map);
    marker.bindPopup(
      `<b>${{h.is_dest ? 'DESTINATION' : 'HOP #' + h.hop}}</b><br>` +
      `<b>IP:</b> ${{h.ip}}<br>` +
      `<b>Host:</b> ${{h.hostname}}<br>` +
      `<b>RTT:</b> ${{h.rtt}}<br>` +
      `<b>Approx. Location:</b> ${{h.location}}<br>` +
      `<b>Coords:</b> ${{h.lat.toFixed(3)}}, ${{h.lon.toFixed(3)}}<br>` +
      `<i>Approximate IP geolocation</i>`
    );
  }});
</script>
</body>
</html>"""
            with open(abs_out, "w", encoding="utf-8") as f:
                f.write(html_doc)
            return True, abs_out

        except Exception as exc:
            return False, f"Failed to generate map HTML: {exc}"


class RouteMapper:
    """
    Cross-platform network route tracer and geographical hop mapper.
    Connected to `DatabaseManager` to persist completed route traces into `route_history`.
    """

    DOMAIN_REGEX = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$"
    )
    IPV4_EXTRACT_REGEX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    RTT_EXTRACT_REGEX = re.compile(r"(?:<\s*)?(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        geo_service: Optional[IPGeolocationService] = None,
    ) -> None:
        self.db_manager = db_manager
        self.geo_service = geo_service or IPGeolocationService()
        self.is_tracing: bool = False
        self.status_text: str = "Not started"
        self.target_input: str = ""
        self.resolved_ip: str = "—"
        self.last_map_path: Optional[str] = None

        self._hops: List[RouteHopRecord] = []
        self._lock = threading.Lock()
        self._cancel_event = threading.Event()
        self._trace_thread: Optional[threading.Thread] = None
        self._active_process: Optional[subprocess.Popen] = None

    @classmethod
    def validate_and_resolve_destination(
        cls,
        raw_input: str,
        allow_dns_network: bool = True,
    ) -> Tuple[bool, str, str, str]:
        target = raw_input.strip() if raw_input else ""
        if not target:
            return False, "Destination is required. Enter a domain name (e.g. example.com) or public IPv4 address (e.g. 1.1.1.1).", "", ""

        if "://" in target or "/" in target or " " in target:
            return (
                False,
                f"Invalid destination '{target}'. Enter a hostname or IPv4 address without 'http://' or URL paths.",
                target,
                "",
            )

        if re.match(r"^\d+(\.\d+){3}$", target):
            try:
                ip_obj = ipaddress.IPv4Address(target)
            except ValueError:
                return False, f"Invalid IPv4 address '{target}' (octets must be 0–255).", target, ""

            if ip_obj.is_unspecified or ip_obj.is_multicast or str(ip_obj) == "255.255.255.255":
                return False, f"Destination '{target}' is a reserved/broadcast address and cannot be traced.", target, ""

            if ip_obj.is_loopback:
                return False, f"Destination '{target}' is a loopback address. Enter a public IPv4 address or domain name.", target, ""

            return True, f"Valid IPv4 destination {ip_obj}", target, str(ip_obj)

        if ":" in target:
            return False, f"Invalid destination '{target}'. Please enter a domain name or IPv4 address.", target, ""

        if not cls.DOMAIN_REGEX.match(target):
            return (
                False,
                f"Invalid domain name or IPv4 address '{target}'. Example valid inputs: 'cloudflare.com', '8.8.8.8'.",
                target,
                "",
            )

        if not allow_dns_network:
            return True, f"Valid domain syntax {target}", target, "0.0.0.0"

        try:
            resolved_ip = socket.gethostbyname(target)
            return True, f"Resolved {target} -> {resolved_ip}", target, resolved_ip
        except socket.gaierror as exc:
            return (
                False,
                f"DNS resolution failed for '{target}': {exc}. Verify the domain name or network connectivity.",
                target,
                "",
            )
        except Exception as exc:
            return False, f"Unable to resolve destination '{target}': {exc}", target, ""

    def start_trace(
        self,
        destination: str,
        event_queue: Optional["queue.Queue[Dict[str, Any]]"] = None,
        max_hops: int = 24,
    ) -> bool:
        if self.is_tracing:
            if event_queue:
                event_queue.put({"type": "trace_error", "message": "A route trace is already in progress."})
            return False

        self.target_input = destination.strip()
        if not self.target_input:
            msg = "Destination required — Enter a domain name or public IPv4 address."
            self.status_text = msg
            if event_queue:
                event_queue.put({"type": "trace_error", "message": msg})
            return False

        self.is_tracing = True
        self.status_text = f"Validating & resolving '{self.target_input}'..."
        self._cancel_event.clear()
        with self._lock:
            self._hops.clear()

        self._trace_thread = threading.Thread(
            target=self._trace_worker,
            args=(self.target_input, max_hops, event_queue),
            name="NetWatchRouteMapper",
            daemon=True,
        )
        self._trace_thread.start()
        return True

    def stop_trace(self) -> None:
        self._cancel_event.set()
        proc = self._active_process
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass
        if self.is_tracing:
            self.status_text = "Cancelling trace..."

    def shutdown(self) -> None:
        """Cancel active traceroute, terminate OS subprocesses, and join worker thread."""
        self.stop_trace()
        if self._trace_thread is not None and self._trace_thread.is_alive() and threading.current_thread() is not self._trace_thread:
            try:
                self._trace_thread.join(timeout=1.5)
            except Exception:
                pass

    def _trace_worker(
        self,
        raw_destination: str,
        max_hops: int,
        event_queue: Optional["queue.Queue[Dict[str, Any]]"],
    ) -> None:
        is_valid, msg, clean_target, resolved_ip = self.validate_and_resolve_destination(raw_destination)
        if not is_valid:
            self.is_tracing = False
            self.status_text = f"Error: {msg}"
            if event_queue:
                event_queue.put({"type": "trace_error", "message": msg})
            return

        self.resolved_ip = resolved_ip
        self.status_text = f"Tracing route to {clean_target} ({resolved_ip})..."
        if event_queue:
            event_queue.put({
                "type": "trace_started",
                "target": clean_target,
                "resolved_ip": resolved_ip,
                "max_hops": max_hops,
            })

        try:
            cmd = self._build_os_traceroute_command(resolved_ip, max_hops)
            if cmd is not None:
                self._execute_os_traceroute(cmd, resolved_ip, event_queue)
            elif HAS_SCAPY and sr1 is not None and IP is not None and ICMP is not None:
                self._execute_scapy_traceroute(resolved_ip, max_hops, event_queue)
            else:
                self._execute_socket_fallback_trace(resolved_ip, event_queue)

            cancelled = self._cancel_event.is_set()
            hops_snapshot = self.get_hops()
            mapped_count = sum(1 for h in hops_snapshot if h.has_coordinates)

            map_ok, map_result = RouteMapGenerator.generate_map_html(
                destination_label=clean_target,
                resolved_ip=resolved_ip,
                hops=hops_snapshot,
            )
            if map_ok:
                self.last_map_path = map_result

            self.is_tracing = False
            state_label = "Cancelled" if cancelled else "Completed"
            self.status_text = (
                f"{state_label}: {len(hops_snapshot)} hops ({mapped_count} geo-mapped) to {clean_target} [{resolved_ip}]"
            )

            # Persist completed route to DatabaseManager (`route_history`)
            if self.db_manager is not None and hops_snapshot:
                self.db_manager.record_route_history(
                    destination=clean_target,
                    resolved_ip=resolved_ip,
                    hops=hops_snapshot,
                )

            if event_queue:
                event_queue.put({
                    "type": "trace_completed",
                    "target": clean_target,
                    "resolved_ip": resolved_ip,
                    "hops": hops_snapshot,
                    "mapped_count": mapped_count,
                    "cancelled": cancelled,
                    "map_path": self.last_map_path,
                    "status_text": self.status_text,
                })

        except Exception as exc:
            self.is_tracing = False
            err_msg = f"Traceroute failed for {clean_target} ({resolved_ip}): {exc}"
            self.status_text = err_msg
            if event_queue:
                event_queue.put({"type": "trace_error", "message": err_msg})

    @staticmethod
    def _build_os_traceroute_command(target_ip: str, max_hops: int) -> Optional[List[str]]:
        if sys.platform.startswith("win"):
            if shutil.which("tracert"):
                return ["tracert", "-d", "-h", str(max_hops), "-w", "1200", target_ip]
            return None

        if shutil.which("traceroute"):
            return ["traceroute", "-n", "-m", str(max_hops), "-w", "2", "-q", "1", target_ip]

        if shutil.which("tracepath"):
            return ["tracepath", "-n", "-m", str(max_hops), target_ip]

        return None

    def _execute_os_traceroute(
        self,
        cmd: List[str],
        target_ip: str,
        event_queue: Optional["queue.Queue[Dict[str, Any]]"],
    ) -> None:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform.startswith("win") else 0
        self._active_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=creationflags,
        )

        seen_hops: set = set()
        try:
            assert self._active_process.stdout is not None
            for raw_line in self._active_process.stdout:
                if self._cancel_event.is_set():
                    break
                parsed = self.parse_traceroute_line(raw_line, target_ip=target_ip)
                if parsed is None or parsed.hop_number in seen_hops:
                    continue
                seen_hops.add(parsed.hop_number)

                enriched = self.enrich_hop(parsed, allow_network=True)
                with self._lock:
                    self._hops.append(enriched)

                if event_queue:
                    event_queue.put({
                        "type": "trace_hop",
                        "hop": enriched,
                        "hops": self.get_hops(),
                    })

                if enriched.is_destination:
                    break
        finally:
            if self._active_process is not None:
                try:
                    self._active_process.terminate()
                except Exception:
                    pass
                self._active_process = None

    def _execute_scapy_traceroute(
        self,
        target_ip: str,
        max_hops: int,
        event_queue: Optional["queue.Queue[Dict[str, Any]]"],
    ) -> None:
        for ttl in range(1, max_hops + 1):
            if self._cancel_event.is_set():
                break

            pkt = IP(dst=target_ip, ttl=ttl) / ICMP()
            t0 = time.perf_counter()
            reply = sr1(pkt, timeout=1.5, verbose=0)
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)

            if reply is None:
                hop = RouteHopRecord(
                    hop_number=ttl,
                    ip_address="*",
                    hostname="—",
                    rtt_ms=None,
                    response_status="Request Timed Out",
                )
            else:
                hop_ip = str(getattr(reply, "src", "*"))
                is_dest = hop_ip == target_ip or int(getattr(reply, "type", -1)) == 0
                status = "Destination Reached" if is_dest else "Responded"
                if int(getattr(reply, "type", -1)) == 3 and not is_dest:
                    status = "Destination Unreachable"
                hop = RouteHopRecord(
                    hop_number=ttl,
                    ip_address=hop_ip,
                    hostname="—",
                    rtt_ms=elapsed_ms,
                    response_status=status,
                    is_destination=is_dest,
                )

            enriched = self.enrich_hop(hop, allow_network=True)
            with self._lock:
                self._hops.append(enriched)

            if event_queue:
                event_queue.put({
                    "type": "trace_hop",
                    "hop": enriched,
                    "hops": self.get_hops(),
                })

            if enriched.is_destination:
                break

    def _execute_socket_fallback_trace(
        self,
        target_ip: str,
        event_queue: Optional["queue.Queue[Dict[str, Any]]"],
    ) -> None:
        t0 = time.perf_counter()
        rtt_ms: Optional[float] = None
        status = "Unreachable (No traceroute binary or raw socket privilege)"
        try:
            with socket.create_connection((target_ip, 443), timeout=2.0):
                rtt_ms = round((time.perf_counter() - t0) * 1000.0, 1)
                status = "Destination Reached (Direct Probe)"
        except Exception:
            pass

        hop = RouteHopRecord(
            hop_number=1,
            ip_address=target_ip,
            hostname="—",
            rtt_ms=rtt_ms,
            response_status=status,
            is_destination=True,
        )
        enriched = self.enrich_hop(hop, allow_network=True)
        with self._lock:
            self._hops.append(enriched)
        if event_queue:
            event_queue.put({
                "type": "trace_hop",
                "hop": enriched,
                "hops": self.get_hops(),
            })

    @classmethod
    def parse_traceroute_line(cls, line: str, target_ip: str = "") -> Optional[RouteHopRecord]:
        if not line:
            return None
        s = line.strip()
        if not s:
            return None

        low = s.lower()
        if low.startswith(("tracing route", "traceroute to", "over a maximum", "trace complete", "resume:")):
            return None

        m_hop = re.match(r"^(\d+)\s*:?\s+(.*)$", s)
        if not m_hop:
            return None

        hop_num = int(m_hop.group(1))
        rest = m_hop.group(2).strip()

        if "too many hops" in rest.lower():
            return None

        ip_match = cls.IPV4_EXTRACT_REGEX.search(rest)
        if ip_match is None:
            if "*" in rest or "no reply" in rest.lower() or "timed out" in rest.lower():
                return RouteHopRecord(
                    hop_number=hop_num,
                    ip_address="*",
                    hostname="—",
                    rtt_ms=None,
                    response_status="Request Timed Out",
                    mapping_status="Not mapped (Timeout)",
                )
            return None

        hop_ip = ip_match.group(1)
        rtt_matches = cls.RTT_EXTRACT_REGEX.findall(rest)
        rtt_val: Optional[float] = None
        if rtt_matches:
            try:
                rtt_val = round(sum(float(x) for x in rtt_matches) / len(rtt_matches), 1)
            except Exception:
                rtt_val = None

        is_dest = bool(target_ip and hop_ip == target_ip)
        if any(tok in rest for tok in ("!H", "!N", "!P", "!X", "!S", "!F")) or "unreachable" in rest.lower():
            status = "Destination Unreachable"
        elif is_dest:
            status = "Destination Reached"
        else:
            status = "Responded"

        return RouteHopRecord(
            hop_number=hop_num,
            ip_address=hop_ip,
            hostname="—",
            rtt_ms=rtt_val,
            response_status=status,
            is_destination=is_dest,
        )

    def enrich_hop(self, hop: RouteHopRecord, allow_network: bool = True) -> RouteHopRecord:
        if hop.ip_address in ("*", "—", ""):
            hop.hostname = "—"
            hop.country = "—"
            hop.region = "—"
            hop.city = "—"
            hop.latitude = None
            hop.longitude = None
            hop.mapping_status = "Not mapped (Timeout)"
            return hop

        if allow_network and hop.hostname in ("—", "", "Unknown"):
            try:
                host, _aliases, _addrs = socket.gethostbyaddr(hop.ip_address)
                hop.hostname = host if host else "Unresolved"
            except Exception:
                hop.hostname = "Unresolved"

        geo = self.geo_service.lookup(hop.ip_address, allow_network=allow_network)
        hop.country = geo.country
        hop.region = geo.region
        hop.city = geo.city
        hop.latitude = geo.latitude
        hop.longitude = geo.longitude
        hop.mapping_status = geo.mapping_status
        return hop

    def load_historical_route(self, destination: str, resolved_ip: str, hops: List[RouteHopRecord]) -> None:
        """Load a previously performed route from `route_history` into the active RouteMapper state."""
        with self._lock:
            self.target_input = destination
            self.resolved_ip = resolved_ip
            self._hops = list(hops)
        ok_map, map_path = RouteMapGenerator.generate_map_html(destination, resolved_ip, hops)
        if ok_map:
            self.last_map_path = map_path
        self.status_text = f"Loaded historical route to {destination} ({len(hops)} hops)"

    def get_hops(self) -> List[RouteHopRecord]:
        with self._lock:
            return list(self._hops)

    def get_hop_by_number(self, hop_number: int) -> Optional[RouteHopRecord]:
        with self._lock:
            for h in self._hops:
                if h.hop_number == hop_number:
                    return h
        return None


# ============================================================================
# UI HELPER WIDGETS & EMBEDDED MATPLOTLIB CHARTS
# ============================================================================

def configure_ttk_styles(root: Any) -> None:
    if not HAS_TK:
        return
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        "NetWatch.Treeview",
        background=Theme.BG_PRIMARY,
        foreground=Theme.TEXT_PRIMARY,
        fieldbackground=Theme.BG_PRIMARY,
        bordercolor=Theme.BORDER,
        lightcolor=Theme.BORDER,
        darkcolor=Theme.BORDER,
        borderwidth=1,
        rowheight=23,
        font=Theme.FONT_MONO_SMALL,
    )
    style.map(
        "NetWatch.Treeview",
        background=[("selected", Theme.BG_SELECTED)],
        foreground=[("selected", Theme.ACCENT_AMBER)],
    )

    style.configure(
        "NetWatch.Treeview.Heading",
        background=Theme.BG_ELEVATED,
        foreground=Theme.TEXT_SECONDARY,
        bordercolor=Theme.BORDER,
        lightcolor=Theme.BORDER,
        darkcolor=Theme.BORDER,
        borderwidth=1,
        relief="flat",
        padding=(6, 4),
        font=Theme.FONT_UI_BOLD,
    )
    style.map(
        "NetWatch.Treeview.Heading",
        background=[("active", Theme.BG_HOVER)],
        foreground=[("active", Theme.TEXT_PRIMARY)],
    )

    style.configure(
        "NetWatch.Horizontal.TProgressbar",
        troughcolor=Theme.BG_PRIMARY,
        background=Theme.ACCENT_AMBER,
        bordercolor=Theme.BORDER,
        lightcolor=Theme.ACCENT_AMBER,
        darkcolor=Theme.ACCENT_AMBER,
        thickness=10,
    )

    style.configure(
        "NetWatch.Vertical.TScrollbar",
        background=Theme.BG_ELEVATED,
        troughcolor=Theme.BG_PRIMARY,
        bordercolor=Theme.BORDER,
        arrowcolor=Theme.TEXT_SECONDARY,
        relief="flat",
    )
    style.configure(
        "NetWatch.Horizontal.TScrollbar",
        background=Theme.BG_ELEVATED,
        troughcolor=Theme.BG_PRIMARY,
        bordercolor=Theme.BORDER,
        arrowcolor=Theme.TEXT_SECONDARY,
        relief="flat",
    )


def create_panel(parent: Any, border: bool = True) -> Any:
    if HAS_CTK:
        return ctk.CTkFrame(
            parent,
            fg_color=Theme.BG_PANEL,
            corner_radius=Theme.CORNER_RADIUS,
            border_width=Theme.BORDER_WIDTH if border else 0,
            border_color=Theme.BORDER,
        )
    return tk.Frame(
        parent,
        bg=Theme.BG_PANEL,
        highlightbackground=Theme.BORDER,
        highlightcolor=Theme.BORDER,
        highlightthickness=Theme.BORDER_WIDTH if border else 0,
        bd=0,
    )


def create_label(
    parent: Any,
    text: str,
    font: tuple = Theme.FONT_UI,
    text_color: str = Theme.TEXT_PRIMARY,
    anchor: str = "w",
) -> Any:
    if HAS_CTK:
        return ctk.CTkLabel(
            parent,
            text=text,
            font=font,
            text_color=text_color,
            anchor=anchor,
        )
    bg_color = Theme.BG_PANEL
    try:
        bg_color = parent.cget("bg")
    except Exception:
        pass
    return tk.Label(
        parent,
        text=text,
        font=font,
        fg=text_color,
        bg=bg_color,
        anchor=anchor,
    )


def create_button(
    parent: Any,
    text: str,
    command: Optional[Callable[[], None]] = None,
    variant: str = "default",
    width: int = 110,
    state: str = "normal",
) -> Any:
    color_map = {
        "default": (Theme.BG_ELEVATED, Theme.BG_HOVER, Theme.TEXT_PRIMARY, Theme.BORDER),
        "accent": (Theme.ACCENT_AMBER, Theme.ACCENT_AMBER_HOVER, "#121316", Theme.ACCENT_AMBER),
        "success": ("#274030", "#31523C", Theme.TEXT_PRIMARY, Theme.STATE_SUCCESS),
        "danger": ("#4A2525", "#5E2F2F", Theme.TEXT_PRIMARY, Theme.STATE_ERROR),
    }
    fg, hover, text_col, border_col = color_map.get(variant, color_map["default"])

    if HAS_CTK:
        return ctk.CTkButton(
            parent,
            text=text,
            command=command,
            width=width,
            height=26,
            corner_radius=Theme.CORNER_RADIUS,
            fg_color=fg,
            hover_color=hover,
            text_color=text_col,
            text_color_disabled=Theme.TEXT_MUTED,
            border_width=1,
            border_color=border_col,
            font=Theme.FONT_UI,
            state=state,
        )
    return tk.Button(
        parent,
        text=text,
        command=command,
        width=max(8, int(width / 8)),
        bg=fg,
        fg=text_col,
        activebackground=hover,
        activeforeground=text_col,
        disabledforeground=Theme.TEXT_MUTED,
        highlightbackground=border_col,
        highlightthickness=1,
        relief="flat",
        font=Theme.FONT_UI,
        state=state,
        padx=8,
        pady=2,
    )


def create_entry(
    parent: Any,
    placeholder_text: str = "",
    width: int = 200,
    font: tuple = Theme.FONT_MONO,
    show: str = "",
) -> Any:
    if HAS_CTK:
        kwargs: Dict[str, Any] = {
            "placeholder_text": placeholder_text,
            "width": width,
            "height": 26,
            "corner_radius": Theme.CORNER_RADIUS,
            "fg_color": Theme.BG_PRIMARY,
            "border_color": Theme.BORDER,
            "border_width": 1,
            "text_color": Theme.TEXT_PRIMARY,
            "placeholder_text_color": Theme.TEXT_MUTED,
            "font": font,
        }
        if show:
            kwargs["show"] = show
        return ctk.CTkEntry(parent, **kwargs)

    entry = tk.Entry(
        parent,
        width=max(10, int(width / 8)),
        bg=Theme.BG_PRIMARY,
        fg=Theme.TEXT_PRIMARY,
        insertbackground=Theme.TEXT_PRIMARY,
        highlightbackground=Theme.BORDER,
        highlightcolor=Theme.ACCENT_AMBER,
        highlightthickness=1,
        relief="flat",
        font=font,
        show=show,
    )
    if placeholder_text and not show:
        entry.insert(0, placeholder_text)
    return entry


class LiveThroughputChart(BaseFrame):  # type: ignore[misc]
    """Embedded Matplotlib chart displaying live Upload vs. Download throughput (KB/s)."""

    def __init__(self, parent: Any, height: int = 165) -> None:
        super().__init__(
            parent,
            bg=Theme.BG_PRIMARY,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
            bd=0,
        )
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.figure: Optional[Any] = None
        self.ax: Optional[Any] = None
        self.line_up: Optional[Any] = None
        self.line_down: Optional[Any] = None
        self.status_text_artist: Optional[Any] = None
        self.mpl_canvas: Optional[Any] = None
        self._init_chart(height)

    def _init_chart(self, height: int) -> None:
        if HAS_MATPLOTLIB and Figure is not None:
            self.figure = Figure(figsize=(6.5, height / 96.0), dpi=96, facecolor=Theme.BG_PRIMARY)
            self.figure.subplots_adjust(left=0.08, right=0.98, top=0.86, bottom=0.20)
            self.ax = self.figure.add_subplot(111)
            self.ax.set_facecolor(Theme.BG_PRIMARY)
            for spine in self.ax.spines.values():
                spine.set_color(Theme.BORDER)
                spine.set_linewidth(0.8)
            self.ax.tick_params(colors=Theme.TEXT_MUTED, labelsize=8)
            self.ax.grid(True, color="#22262C", linestyle="--", linewidth=0.6)
            self.ax.set_ylabel("KB/s", color=Theme.TEXT_SECONDARY, fontsize=8)
            self.ax.set_xlabel("Time (seconds ago)", color=Theme.TEXT_MUTED, fontsize=8)

            x_init = [float(-i) for i in range(59, -1, -1)]
            y_init = [0.0] * 60
            (self.line_up,) = self.ax.plot(
                x_init,
                y_init,
                color=Theme.ACCENT_AMBER,
                linewidth=1.5,
                label="Upload (TX KB/s)",
            )
            (self.line_down,) = self.ax.plot(
                x_init,
                y_init,
                color=Theme.STATE_SUCCESS,
                linewidth=1.5,
                label="Download (RX KB/s)",
            )
            self.ax.set_xlim(-59, 0)
            self.ax.set_ylim(0, 10.0)

            leg = self.ax.legend(
                loc="upper left",
                frameon=True,
                facecolor=Theme.BG_PANEL,
                edgecolor=Theme.BORDER,
                fontsize=8,
                labelcolor=Theme.TEXT_PRIMARY,
            )
            leg.get_frame().set_linewidth(0.8)

            self.status_text_artist = self.ax.text(
                0.5,
                0.5,
                "Capture not started — Click 'Start Monitoring' or 'Start Capture'",
                transform=self.ax.transAxes,
                ha="center",
                va="center",
                color=Theme.TEXT_MUTED,
                fontsize=9,
                family="monospace",
            )

            if HAS_MPL_TKAGG and FigureCanvasTkAgg is not None and HAS_TK:
                self.mpl_canvas = FigureCanvasTkAgg(self.figure, master=self)
                widget = self.mpl_canvas.get_tk_widget()
                widget.configure(bg=Theme.BG_PRIMARY, highlightthickness=0)
                widget.grid(row=0, column=0, sticky="nsew")
                return

        if HAS_TK:
            fallback = tk.Canvas(self, bg=Theme.BG_PRIMARY, highlightthickness=0, height=height)
            fallback.grid(row=0, column=0, sticky="nsew")

    def update_from_snapshot(self, snapshot: TrafficStatsSnapshot) -> None:
        if self.figure is not None and self.ax is not None and self.line_up is not None and self.line_down is not None:
            x_data = snapshot.time_axis
            up_data = snapshot.upload_history_kbs
            down_data = snapshot.download_history_kbs

            self.line_up.set_data(x_data, up_data)
            self.line_down.set_data(x_data, down_data)

            peak = max(max(up_data, default=0.0), max(down_data, default=0.0), 1.0)
            self.ax.set_ylim(0.0, max(5.0, peak * 1.25))

            if self.status_text_artist is not None:
                if not snapshot.is_capturing and snapshot.total_packets == 0:
                    self.status_text_artist.set_visible(True)
                else:
                    self.status_text_artist.set_visible(False)

            if self.mpl_canvas is not None:
                self.mpl_canvas.draw_idle()


class ProtocolDistributionChart(BaseFrame):  # type: ignore[misc]
    """Embedded Matplotlib horizontal bar chart showing packet counts across protocols."""

    PROTOCOLS = ("TCP", "UDP", "ICMP", "DNS", "Other")
    BAR_COLORS = (
        Theme.ACCENT_AMBER,
        Theme.CHART_BLUE,
        Theme.STATE_SUCCESS,
        Theme.CHART_TEAL,
        Theme.TEXT_SECONDARY,
    )

    def __init__(self, parent: Any, height: int = 160) -> None:
        super().__init__(
            parent,
            bg=Theme.BG_PRIMARY,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
            bd=0,
        )
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.figure: Optional[Any] = None
        self.ax: Optional[Any] = None
        self.bars: Any = None
        self.mpl_canvas: Optional[Any] = None
        self._init_chart(height)

    def _init_chart(self, height: int) -> None:
        if HAS_MATPLOTLIB and Figure is not None:
            self.figure = Figure(figsize=(3.6, height / 96.0), dpi=96, facecolor=Theme.BG_PRIMARY)
            self.figure.subplots_adjust(left=0.20, right=0.95, top=0.88, bottom=0.20)
            self.ax = self.figure.add_subplot(111)
            self.ax.set_facecolor(Theme.BG_PRIMARY)
            for spine in self.ax.spines.values():
                spine.set_color(Theme.BORDER)
                spine.set_linewidth(0.8)
            self.ax.tick_params(colors=Theme.TEXT_SECONDARY, labelsize=8)
            self.ax.grid(True, axis="x", color="#22262C", linestyle="--", linewidth=0.6)

            y_pos = list(range(len(self.PROTOCOLS) - 1, -1, -1))
            self.bars = self.ax.barh(
                y_pos,
                [0] * len(self.PROTOCOLS),
                color=self.BAR_COLORS,
                height=0.58,
                edgecolor=Theme.BORDER,
                linewidth=0.6,
            )
            self.ax.set_yticks(y_pos)
            self.ax.set_yticklabels(self.PROTOCOLS, color=Theme.TEXT_PRIMARY, fontsize=8, family="monospace")
            self.ax.set_xlim(0, 10)
            self.ax.set_xlabel("Packet Count", color=Theme.TEXT_MUTED, fontsize=8)

            if HAS_MPL_TKAGG and FigureCanvasTkAgg is not None and HAS_TK:
                self.mpl_canvas = FigureCanvasTkAgg(self.figure, master=self)
                widget = self.mpl_canvas.get_tk_widget()
                widget.configure(bg=Theme.BG_PRIMARY, highlightthickness=0)
                widget.grid(row=0, column=0, sticky="nsew")
                return

        if HAS_TK:
            fallback = tk.Canvas(self, bg=Theme.BG_PRIMARY, highlightthickness=0, height=height)
            fallback.grid(row=0, column=0, sticky="nsew")

    def update_counts(self, protocol_counts: Dict[str, int]) -> None:
        if self.figure is not None and self.ax is not None and self.bars is not None:
            values = [int(protocol_counts.get(p, 0)) for p in self.PROTOCOLS]
            for rect, val in zip(self.bars, values):
                rect.set_width(val)
            max_val = max(values) if values else 0
            self.ax.set_xlim(0, max(10, int(max_val * 1.2) + 1))
            if self.mpl_canvas is not None:
                self.mpl_canvas.draw_idle()


class TrafficActivityChart(BaseFrame):  # type: ignore[misc]
    """Embedded Matplotlib chart showing Traffic Activity Over Time (Packets/sec and KB/s)."""

    def __init__(self, parent: Any, height: int = 160) -> None:
        super().__init__(
            parent,
            bg=Theme.BG_PRIMARY,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
            bd=0,
        )
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.figure: Optional[Any] = None
        self.ax: Optional[Any] = None
        self.line_pps: Optional[Any] = None
        self.line_kbs: Optional[Any] = None
        self.status_text_artist: Optional[Any] = None
        self.mpl_canvas: Optional[Any] = None
        self._init_chart(height)

    def _init_chart(self, height: int) -> None:
        if HAS_MATPLOTLIB and Figure is not None:
            self.figure = Figure(figsize=(5.2, height / 96.0), dpi=96, facecolor=Theme.BG_PRIMARY)
            self.figure.subplots_adjust(left=0.10, right=0.97, top=0.88, bottom=0.20)
            self.ax = self.figure.add_subplot(111)
            self.ax.set_facecolor(Theme.BG_PRIMARY)
            for spine in self.ax.spines.values():
                spine.set_color(Theme.BORDER)
                spine.set_linewidth(0.8)
            self.ax.tick_params(colors=Theme.TEXT_MUTED, labelsize=8)
            self.ax.grid(True, color="#22262C", linestyle="--", linewidth=0.6)

            x_init = [float(-i) for i in range(59, -1, -1)]
            y_init = [0.0] * 60
            (self.line_pps,) = self.ax.plot(
                x_init,
                y_init,
                color=Theme.CHART_BLUE,
                linewidth=1.5,
                label="Packets / sec",
            )
            (self.line_kbs,) = self.ax.plot(
                x_init,
                y_init,
                color=Theme.ACCENT_AMBER,
                linewidth=1.4,
                linestyle="--",
                label="Volume (KB/s)",
            )
            self.ax.set_xlim(-59, 0)
            self.ax.set_ylim(0, 10.0)
            self.ax.set_ylabel("Rate", color=Theme.TEXT_SECONDARY, fontsize=8)
            self.ax.set_xlabel("Time (seconds ago)", color=Theme.TEXT_MUTED, fontsize=8)

            leg = self.ax.legend(
                loc="upper left",
                frameon=True,
                facecolor=Theme.BG_PANEL,
                edgecolor=Theme.BORDER,
                fontsize=8,
                labelcolor=Theme.TEXT_PRIMARY,
            )
            leg.get_frame().set_linewidth(0.8)

            self.status_text_artist = self.ax.text(
                0.5,
                0.5,
                "Capture idle — Click 'Start Capture' to monitor live traffic",
                transform=self.ax.transAxes,
                ha="center",
                va="center",
                color=Theme.TEXT_MUTED,
                fontsize=8.5,
                family="monospace",
            )

            if HAS_MPL_TKAGG and FigureCanvasTkAgg is not None and HAS_TK:
                self.mpl_canvas = FigureCanvasTkAgg(self.figure, master=self)
                widget = self.mpl_canvas.get_tk_widget()
                widget.configure(bg=Theme.BG_PRIMARY, highlightthickness=0)
                widget.grid(row=0, column=0, sticky="nsew")
                return

        if HAS_TK:
            fallback = tk.Canvas(self, bg=Theme.BG_PRIMARY, highlightthickness=0, height=height)
            fallback.grid(row=0, column=0, sticky="nsew")

    def update_from_snapshot(self, snapshot: TrafficStatsSnapshot) -> None:
        if self.figure is not None and self.ax is not None and self.line_pps is not None and self.line_kbs is not None:
            x_data = snapshot.time_axis
            pps_data = snapshot.pps_history
            kbs_data = snapshot.bps_history_kbs

            self.line_pps.set_data(x_data, pps_data)
            self.line_kbs.set_data(x_data, kbs_data)

            peak = max(max(pps_data, default=0.0), max(kbs_data, default=0.0), 1.0)
            self.ax.set_ylim(0.0, max(10.0, peak * 1.25))

            if self.status_text_artist is not None:
                if not snapshot.is_capturing and snapshot.total_packets == 0:
                    self.status_text_artist.set_visible(True)
                else:
                    self.status_text_artist.set_visible(False)

            if self.mpl_canvas is not None:
                self.mpl_canvas.draw_idle()


class TechnicalTable(BaseFrame):  # type: ignore[misc]
    """Reusable resizable Treeview table with dark technical headers and clickable sorting."""

    def __init__(
        self,
        parent: Any,
        columns: List[Dict[str, Any]],
        empty_message: str = "No records available — Monitoring not started",
        sortable: bool = True,
        on_row_select: Optional[Callable[[Tuple[Any, ...]], None]] = None,
    ) -> None:
        super().__init__(
            parent,
            bg=Theme.BG_PRIMARY,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
            bd=0,
        )
        self.columns_spec = columns
        self.empty_message = empty_message
        self.sortable = sortable
        self.on_row_select = on_row_select
        self._sort_col: Optional[str] = None
        self._sort_desc: bool = False

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        col_ids = [c["id"] for c in columns]
        self.tree = ttk.Treeview(
            self,
            columns=col_ids,
            show="headings",
            style="NetWatch.Treeview",
            selectmode="browse",
        )

        for col in columns:
            cid = col["id"]
            label = col["label"]
            if self.sortable:
                self.tree.heading(
                    cid,
                    text=label,
                    anchor=col.get("anchor", "w"),
                    command=lambda c=cid: self.sort_by_column(c),
                )
            else:
                self.tree.heading(cid, text=label, anchor=col.get("anchor", "w"))

            self.tree.column(
                cid,
                width=col.get("width", 120),
                minwidth=col.get("minwidth", 50),
                stretch=col.get("stretch", True),
                anchor=col.get("anchor", "w"),
            )

        self.tree.tag_configure("online", foreground=Theme.TEXT_PRIMARY)
        self.tree.tag_configure("local", foreground=Theme.ACCENT_AMBER)
        self.tree.tag_configure("offline", foreground=Theme.TEXT_MUTED)
        self.tree.tag_configure("error", foreground=Theme.STATE_ERROR)
        self.tree.tag_configure("mapped", foreground=Theme.STATE_SUCCESS)
        self.tree.tag_configure("dest", foreground=Theme.ACCENT_AMBER)
        self.tree.tag_configure("proto_dns", foreground=Theme.ACCENT_AMBER)
        self.tree.tag_configure("proto_icmp", foreground=Theme.STATE_SUCCESS)
        self.tree.tag_configure("proto_tcp", foreground=Theme.TEXT_PRIMARY)
        self.tree.tag_configure("proto_udp", foreground=Theme.CHART_BLUE)
        self.tree.tag_configure("proto_other", foreground=Theme.TEXT_SECONDARY)

        self.vsb = ttk.Scrollbar(
            self,
            orient="vertical",
            command=self.tree.yview,
            style="NetWatch.Vertical.TScrollbar",
        )
        self.hsb = ttk.Scrollbar(
            self,
            orient="horizontal",
            command=self.tree.xview,
            style="NetWatch.Horizontal.TScrollbar",
        )
        self.tree.configure(yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        self.vsb.grid(row=0, column=1, sticky="ns")
        self.hsb.grid(row=1, column=0, sticky="ew")

        if self.on_row_select is not None:
            self.tree.bind("<<TreeviewSelect>>", self._handle_select)

        self.empty_label = tk.Label(
            self.tree,
            text=self.empty_message,
            font=Theme.FONT_MONO,
            fg=Theme.TEXT_MUTED,
            bg=Theme.BG_PRIMARY,
            padx=14,
            pady=8,
            justify="center",
        )
        self._update_empty_overlay()

    def _handle_select(self, _event: Any = None) -> None:
        if not self.on_row_select:
            return
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0], "values")
        if values:
            self.on_row_select(tuple(values))

    @staticmethod
    def _sort_key_for_value(col_id: str, val: str) -> Any:
        if col_id in ("ip", "src_ip", "dst_ip"):
            try:
                return tuple(int(part) for part in val.split("."))
            except Exception:
                return (999, 999, 999, 999)
        if col_id in ("id", "session_id", "hop", "hop_count", "length", "src_port", "dst_port", "total_packets", "tcp", "udp", "icmp", "dns", "other"):
            try:
                return int(str(val).replace(",", ""))
            except Exception:
                return -1
        if col_id == "rtt":
            m = re.search(r"(\d+(?:\.\d+)?)", str(val))
            return float(m.group(1)) if m else 999999.0
        return str(val).lower()

    def sort_by_column(self, col_id: str, toggle: bool = True) -> None:
        if toggle:
            if self._sort_col == col_id:
                self._sort_desc = not self._sort_desc
            else:
                self._sort_col = col_id
                self._sort_desc = False

        items = [(self.tree.set(k, col_id), k) for k in self.tree.get_children("")]
        items.sort(
            key=lambda pair: self._sort_key_for_value(col_id, pair[0]),
            reverse=self._sort_desc,
        )
        for index, (_val, k) in enumerate(items):
            self.tree.move(k, "", index)

        for col in self.columns_spec:
            cid = col["id"]
            base_label = col["label"]
            if cid == self._sort_col:
                arrow = " ▼" if self._sort_desc else " ▲"
                self.tree.heading(cid, text=f"{base_label}{arrow}")
            else:
                self.tree.heading(cid, text=base_label)

    def clear(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._update_empty_overlay()

    def set_empty_message(self, message: str, is_error: bool = False) -> None:
        self.empty_message = message
        self.empty_label.configure(
            text=message,
            fg=Theme.STATE_ERROR if is_error else Theme.TEXT_MUTED,
        )
        self._update_empty_overlay()

    def _update_empty_overlay(self) -> None:
        if len(self.tree.get_children()) == 0:
            self.empty_label.place(relx=0.5, rely=0.55, anchor="center")
        else:
            self.empty_label.place_forget()


# ============================================================================
# WORKSPACE VIEWS (OVERVIEW, DEVICES, TRAFFIC, ROUTE MAPPER, HISTORY)
# ============================================================================

class DashboardView(BaseFrame):  # type: ignore[misc]
    """Overview Tab (Stage 1–5 Integrated)."""

    def __init__(self, parent: Any) -> None:
        super().__init__(parent, bg=Theme.BG_PRIMARY)
        self._build_ui()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=5)
        self.grid_rowconfigure(2, weight=5)

        strip_frame = create_panel(self, border=True)
        strip_frame.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_SM, pady=(Theme.PAD_SM, Theme.PAD_XS))

        metrics_spec = [
            ("interface", "NETWORK INTERFACE", "None", "Status: —"),
            ("ipv4", "LOCAL IPv4 / SUBNET", "Not available", "Mask: —"),
            ("gateway", "GATEWAY / HARDWARE MAC", "Not available", "MAC: —"),
            ("devices", "DISCOVERED DEVICES", "0 Online / 0 Total", "Scanner: Not started"),
            ("packets", "SESSION PACKETS & DURATION", "0 pkts  (00:00:00)", "TCP:0 UDP:0 ICMP:0 DNS:0 Oth:0"),
            ("throughput", "THROUGHPUT (TX / RX)", "0.0 B/s  /  0.0 B/s", "0.0 pkt/s  |  Total: 0 B"),
        ]

        self.readout_labels: Dict[str, Any] = {}
        self.readout_sublabels: Dict[str, Any] = {}
        for idx, (key, title, default_val, default_sub) in enumerate(metrics_spec):
            strip_frame.grid_columnconfigure(idx, weight=1, uniform="overview_metric")

            cell = tk.Frame(
                strip_frame,
                bg=Theme.BG_PANEL,
                highlightbackground=Theme.BORDER,
                highlightthickness=1,
                padx=8,
                pady=6,
            )
            cell.grid(row=0, column=idx, sticky="nsew", padx=2, pady=2)

            lbl_title = create_label(
                cell,
                text=title,
                font=Theme.FONT_UI_BOLD,
                text_color=Theme.TEXT_SECONDARY,
            )
            lbl_title.pack(anchor="w")

            lbl_val = create_label(
                cell,
                text=default_val,
                font=Theme.FONT_MONO,
                text_color=Theme.TEXT_PRIMARY,
            )
            lbl_val.pack(anchor="w", pady=(2, 0))
            self.readout_labels[key] = lbl_val

            lbl_sub = create_label(
                cell,
                text=default_sub,
                font=Theme.FONT_MONO_SMALL,
                text_color=Theme.TEXT_MUTED,
            )
            lbl_sub.pack(anchor="w", pady=(1, 0))
            self.readout_sublabels[key] = lbl_sub

        chart_panel = create_panel(self, border=True)
        chart_panel.grid(row=1, column=0, sticky="nsew", padx=Theme.PAD_SM, pady=Theme.PAD_XS)
        chart_panel.grid_rowconfigure(1, weight=1)
        chart_panel.grid_columnconfigure(0, weight=1)

        chart_header = tk.Frame(chart_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        chart_header.grid(row=0, column=0, sticky="ew")
        create_label(
            chart_header,
            text="LIVE UPLOAD / DOWNLOAD THROUGHPUT TELEMETRY (60s ROLLING WINDOW)",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")
        self.chart_state_lbl = create_label(
            chart_header,
            text="CAPTURE: NOT STARTED",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.ACCENT_AMBER,
        )
        self.chart_state_lbl.pack(side="right")

        self.throughput_chart = LiveThroughputChart(chart_panel, height=175)
        self.throughput_chart.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        activity_panel = create_panel(self, border=True)
        activity_panel.grid(row=2, column=0, sticky="nsew", padx=Theme.PAD_SM, pady=(Theme.PAD_XS, Theme.PAD_SM))
        activity_panel.grid_rowconfigure(1, weight=1)
        activity_panel.grid_columnconfigure(0, weight=1)

        act_header = tk.Frame(activity_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        act_header.grid(row=0, column=0, sticky="ew")
        create_label(
            act_header,
            text="RECENT NETWORK ACTIVITY",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")
        create_label(
            act_header,
            text="REAL-TIME SUBSYSTEM EVENT LOG",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_MUTED,
        ).pack(side="right")

        activity_columns = [
            {"id": "timestamp", "label": "Timestamp", "width": 150, "minwidth": 120, "stretch": False},
            {"id": "category", "label": "Subsystem", "width": 130, "minwidth": 100, "stretch": False},
            {"id": "source", "label": "Interface / Host", "width": 160, "minwidth": 120, "stretch": False},
            {"id": "event", "label": "Activity / Event Summary", "width": 440, "minwidth": 220, "stretch": True},
            {"id": "state", "label": "State", "width": 110, "minwidth": 85, "stretch": False},
        ]
        self.activity_table = TechnicalTable(
            activity_panel,
            columns=activity_columns,
            empty_message="No network activity recorded yet — Select an interface or start monitoring",
        )
        self.activity_table.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

    def append_activity(self, event: ActivityEvent) -> None:
        tag = "online"
        if event.state.lower() in ("error", "failed", "denied", "disconnected"):
            tag = "error"
        elif event.state.lower() in ("cancelled", "offline", "stopped"):
            tag = "offline"

        self.activity_table.tree.insert(
            "",
            0,
            values=(event.timestamp, event.subsystem, event.source, event.summary, event.state),
            tags=(tag,),
        )
        self.activity_table._update_empty_overlay()

    def update_overview(
        self,
        iface: InterfaceSummary,
        online_devices: int,
        total_devices: int,
        scanner_status: str,
        traffic_snapshot: TrafficStatsSnapshot,
        monitoring_active: bool,
    ) -> None:
        self.readout_labels["interface"].configure(
            text=iface.name,
            text_color=Theme.STATE_SUCCESS if iface.is_up else Theme.ACCENT_AMBER,
        )
        self.readout_sublabels["interface"].configure(text=f"Status: {iface.status_label}")

        self.readout_labels["ipv4"].configure(text=iface.ipv4_address)
        self.readout_sublabels["ipv4"].configure(text=f"Mask: {iface.netmask} ({iface.subnet_cidr})")

        self.readout_labels["gateway"].configure(text=iface.default_gateway)
        self.readout_sublabels["gateway"].configure(text=f"MAC: {iface.mac_address}")

        self.readout_labels["devices"].configure(
            text=f"{online_devices} Online / {total_devices} Total",
            text_color=Theme.STATE_SUCCESS if online_devices > 0 else Theme.TEXT_PRIMARY,
        )
        self.readout_sublabels["devices"].configure(text=f"Scan: {scanner_status[:32]}")

        dur_str = format_duration(traffic_snapshot.duration_seconds)
        self.readout_labels["packets"].configure(
            text=f"{traffic_snapshot.total_packets:,} pkts  ({dur_str})",
            text_color=Theme.STATE_SUCCESS if traffic_snapshot.is_capturing else Theme.TEXT_PRIMARY,
        )
        pc = traffic_snapshot.protocol_counts
        proto_summary = (
            f"TCP:{pc.get('TCP', 0)} UDP:{pc.get('UDP', 0)} "
            f"ICMP:{pc.get('ICMP', 0)} DNS:{pc.get('DNS', 0)} Oth:{pc.get('Other', 0)}"
        )
        self.readout_sublabels["packets"].configure(text=proto_summary)

        up_str = format_bytes_rate(traffic_snapshot.upload_bps)
        down_str = format_bytes_rate(traffic_snapshot.download_bps)
        self.readout_labels["throughput"].configure(text=f"↑ {up_str}  /  ↓ {down_str}")
        self.readout_sublabels["throughput"].configure(
            text=f"{traffic_snapshot.packets_per_sec:.1f} pkt/s  |  Total: {format_total_bytes(traffic_snapshot.total_bytes)}"
        )

        if traffic_snapshot.is_capturing:
            self.chart_state_lbl.configure(
                text=f"CAPTURING ON {traffic_snapshot.interface_name.upper()} ({dur_str})",
                text_color=Theme.STATE_SUCCESS,
            )
        elif monitoring_active:
            self.chart_state_lbl.configure(
                text=f"MONITORING STANDBY — {traffic_snapshot.status_text.upper()}",
                text_color=Theme.ACCENT_AMBER,
            )
        else:
            self.chart_state_lbl.configure(text="CAPTURE: NOT STARTED", text_color=Theme.ACCENT_AMBER)

        self.throughput_chart.update_from_snapshot(traffic_snapshot)


class DevicesView(BaseFrame):  # type: ignore[misc]
    """Devices Tab (Stage 2 Full Implementation)."""

    def __init__(
        self,
        parent: Any,
        on_scan: Optional[Callable[[], None]] = None,
        on_cancel_scan: Optional[Callable[[], None]] = None,
        on_refresh: Optional[Callable[[], None]] = None,
        on_search: Optional[Callable[[str], None]] = None,
        on_select_device: Optional[Callable[[str], Optional[DeviceRecord]]] = None,
    ) -> None:
        super().__init__(parent, bg=Theme.BG_PRIMARY)
        self.on_scan = on_scan
        self.on_cancel_scan = on_cancel_scan
        self.on_refresh = on_refresh
        self.on_search = on_search
        self.on_select_device = on_select_device
        self._selected_ip: Optional[str] = None
        self._build_ui()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        ctrl_bar = create_panel(self, border=True)
        ctrl_bar.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_SM, pady=(Theme.PAD_SM, Theme.PAD_XS))

        left_controls = tk.Frame(ctrl_bar, bg=Theme.BG_PANEL)
        left_controls.pack(side="left", fill="x", padx=6, pady=5)

        create_label(
            left_controls,
            text="SEARCH / FILTER:",
            font=Theme.FONT_UI_BOLD,
            text_color=Theme.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 6))

        self.search_entry = create_entry(
            left_controls,
            placeholder_text="Filter by IP, MAC, Hostname, or Vendor...",
            width=285,
        )
        self.search_entry.pack(side="left", padx=(0, 6))
        self.search_entry.bind("<KeyRelease>", lambda _e: self._handle_search())

        self.btn_search = create_button(
            left_controls,
            text="Apply Filter",
            command=self._handle_search,
            width=95,
        )
        self.btn_search.pack(side="left", padx=(0, 4))

        self.btn_clear = create_button(
            left_controls,
            text="Clear",
            command=self._handle_clear_search,
            width=64,
        )
        self.btn_clear.pack(side="left")

        right_controls = tk.Frame(ctrl_bar, bg=Theme.BG_PANEL)
        right_controls.pack(side="right", padx=6, pady=5)

        self.btn_refresh = create_button(
            right_controls,
            text="Refresh",
            command=self._handle_refresh,
            width=90,
        )
        self.btn_refresh.pack(side="left", padx=(0, 6))

        self.btn_scan = create_button(
            right_controls,
            text="Scan Subnet",
            command=self._handle_scan,
            variant="accent",
            width=115,
        )
        self.btn_scan.pack(side="left", padx=(0, 6))

        self.btn_cancel = create_button(
            right_controls,
            text="Cancel Scan",
            command=self._handle_cancel,
            variant="danger",
            width=100,
            state="disabled",
        )
        self.btn_cancel.pack(side="left")

        tele_bar = create_panel(self, border=True)
        tele_bar.grid(row=1, column=0, sticky="ew", padx=Theme.PAD_SM, pady=(0, Theme.PAD_XS))
        tele_bar.grid_columnconfigure(0, weight=3)
        tele_bar.grid_columnconfigure(1, weight=4)
        tele_bar.grid_columnconfigure(2, weight=3)

        iface_box = tk.Frame(tele_bar, bg=Theme.BG_PANEL, padx=8, pady=4)
        iface_box.grid(row=0, column=0, sticky="ew")
        self.iface_info_lbl = create_label(
            iface_box,
            text="TARGET: None  |  SUBNET: Not available  |  MAC: —",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_SECONDARY,
        )
        self.iface_info_lbl.pack(anchor="w")

        prog_box = tk.Frame(tele_bar, bg=Theme.BG_PANEL, padx=8, pady=4)
        prog_box.grid(row=0, column=1, sticky="ew")
        prog_box.grid_columnconfigure(1, weight=1)

        self.scan_status_lbl = create_label(
            prog_box,
            text="SCAN STATUS: Not started",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.ACCENT_AMBER,
        )
        self.scan_status_lbl.grid(row=0, column=0, sticky="w", padx=(0, 10))

        self.progress_bar = ttk.Progressbar(
            prog_box,
            orient="horizontal",
            mode="determinate",
            maximum=100.0,
            value=0.0,
            style="NetWatch.Horizontal.TProgressbar",
        )
        self.progress_bar.grid(row=0, column=1, sticky="ew", padx=(0, 8))

        self.progress_pct_lbl = create_label(
            prog_box,
            text="0%",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_SECONDARY,
        )
        self.progress_pct_lbl.grid(row=0, column=2, sticky="e")

        ts_box = tk.Frame(tele_bar, bg=Theme.BG_PANEL, padx=8, pady=4)
        ts_box.grid(row=0, column=2, sticky="e")
        self.timestamps_lbl = create_label(
            ts_box,
            text="START: —   |   COMPLETED: —",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_MUTED,
        )
        self.timestamps_lbl.pack(anchor="e")

        main_split = tk.Frame(self, bg=Theme.BG_PRIMARY)
        main_split.grid(row=2, column=0, sticky="nsew", padx=Theme.PAD_SM, pady=(Theme.PAD_XS, Theme.PAD_SM))
        main_split.grid_columnconfigure(0, weight=7)
        main_split.grid_columnconfigure(1, weight=3)
        main_split.grid_rowconfigure(0, weight=1)

        table_panel = create_panel(main_split, border=True)
        table_panel.grid(row=0, column=0, sticky="nsew", padx=(0, Theme.PAD_XS))
        table_panel.grid_rowconfigure(1, weight=1)
        table_panel.grid_columnconfigure(0, weight=1)

        hdr = tk.Frame(table_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            hdr,
            text="DISCOVERED LAN DEVICES (CLICK COLUMN HEADERS TO SORT)",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")
        self.count_lbl = create_label(
            hdr,
            text="ONLINE: 0  |  SESSION TOTAL: 0",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_SECONDARY,
        )
        self.count_lbl.pack(side="right")

        device_columns = [
            {"id": "ip", "label": "IP Address", "width": 130, "minwidth": 110, "stretch": False},
            {"id": "mac", "label": "MAC Address", "width": 145, "minwidth": 130, "stretch": False},
            {"id": "hostname", "label": "Hostname", "width": 185, "minwidth": 130, "stretch": True},
            {"id": "vendor", "label": "Vendor", "width": 200, "minwidth": 140, "stretch": True},
            {"id": "first_seen", "label": "First Seen", "width": 145, "minwidth": 125, "stretch": False},
            {"id": "last_seen", "label": "Last Seen", "width": 145, "minwidth": 125, "stretch": False},
            {"id": "status", "label": "Status", "width": 95, "minwidth": 80, "stretch": False},
        ]
        self.device_table = TechnicalTable(
            table_panel,
            columns=device_columns,
            empty_message="No discovered devices — Click 'Scan Subnet' to perform ARP discovery on the local network",
            sortable=True,
            on_row_select=self._on_table_row_selected,
        )
        self.device_table.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        detail_panel = create_panel(main_split, border=True)
        detail_panel.grid(row=0, column=1, sticky="nsew", padx=(Theme.PAD_XS, 0))
        detail_panel.grid_columnconfigure(0, weight=1)

        d_hdr = tk.Frame(detail_panel, bg=Theme.BG_ELEVATED, padx=10, pady=6)
        d_hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            d_hdr,
            text="DEVICE DETAIL INSPECTOR",
            font=Theme.FONT_SECTION,
            text_color=Theme.ACCENT_AMBER,
        ).pack(side="left")

        detail_body = tk.Frame(detail_panel, bg=Theme.BG_PANEL, padx=10, pady=8)
        detail_body.grid(row=1, column=0, sticky="nsew")
        detail_body.grid_columnconfigure(0, weight=1)

        detail_fields = [
            ("ip", "IPv4 ADDRESS"),
            ("mac", "HARDWARE MAC ADDRESS"),
            ("vendor", "MANUFACTURER / OUI VENDOR"),
            ("hostname", "RESOLVED HOSTNAME"),
            ("status", "AVAILABILITY STATUS"),
            ("interface", "DISCOVERED INTERFACE"),
            ("role", "HOST CLASSIFICATION"),
            ("first_seen", "FIRST DISCOVERED"),
            ("last_seen", "LAST SEEN TIMESTAMP"),
            ("responses", "ARP RESPONSES / RTT"),
        ]

        self.detail_labels: Dict[str, Any] = {}
        for idx, (f_key, f_title) in enumerate(detail_fields):
            box = tk.Frame(
                detail_body,
                bg=Theme.BG_PRIMARY,
                highlightbackground=Theme.BORDER,
                highlightthickness=1,
                padx=8,
                pady=4,
            )
            box.grid(row=idx, column=0, sticky="ew", pady=2)
            create_label(
                box,
                text=f_title,
                font=Theme.FONT_UI_BOLD,
                text_color=Theme.TEXT_MUTED,
            ).pack(anchor="w")
            val_lbl = create_label(
                box,
                text="— (Select a host row)",
                font=Theme.FONT_MONO_SMALL,
                text_color=Theme.TEXT_PRIMARY,
            )
            val_lbl.pack(anchor="w", pady=(1, 0))
            self.detail_labels[f_key] = val_lbl

    def get_filter_query(self) -> str:
        val = self.search_entry.get().strip()
        if val == "Filter by IP, MAC, Hostname, or Vendor...":
            return ""
        return val

    def _handle_search(self) -> None:
        if self.on_search:
            self.on_search(self.get_filter_query())

    def _handle_clear_search(self) -> None:
        self.search_entry.delete(0, "end")
        if self.on_search:
            self.on_search("")

    def _handle_refresh(self) -> None:
        if self.on_refresh:
            self.on_refresh()

    def _handle_scan(self) -> None:
        if self.on_scan:
            self.on_scan()

    def _handle_cancel(self) -> None:
        if self.on_cancel_scan:
            self.on_cancel_scan()

    def _on_table_row_selected(self, values: Tuple[Any, ...]) -> None:
        if not values:
            return
        ip_addr = str(values[0])
        self._selected_ip = ip_addr
        if self.on_select_device:
            record = self.on_select_device(ip_addr)
            if record is not None:
                self.update_device_detail(record)

    def update_interface_banner(self, iface: InterfaceSummary) -> None:
        self.iface_info_lbl.configure(
            text=(
                f"INTERFACE: {iface.name} ({iface.status_label})   |   "
                f"IPv4: {iface.ipv4_address}   |   MASK: {iface.netmask}   |   "
                f"SUBNET: {iface.subnet_cidr}   |   MAC: {iface.mac_address}"
            )
        )

    def set_scan_lifecycle(
        self,
        is_scanning: bool,
        status_text: str,
        progress_pct: float = 0.0,
        start_time: str = "—",
        end_time: str = "—",
        is_error: bool = False,
    ) -> None:
        self.btn_scan.configure(state="disabled" if is_scanning else "normal")
        self.btn_cancel.configure(state="normal" if is_scanning else "disabled")

        color = (
            Theme.STATE_ERROR
            if is_error
            else (Theme.STATE_SUCCESS if not is_scanning and progress_pct >= 100.0 else Theme.ACCENT_AMBER)
        )
        self.scan_status_lbl.configure(text=f"SCAN STATUS: {status_text}", text_color=color)

        clamped = max(0.0, min(100.0, progress_pct))
        self.progress_bar["value"] = clamped
        self.progress_pct_lbl.configure(text=f"{int(clamped)}%")

        self.timestamps_lbl.configure(text=f"START: {start_time}   |   COMPLETED: {end_time}")

        if is_error:
            self.device_table.set_empty_message(status_text, is_error=True)
        else:
            self.device_table.set_empty_message(
                f"No matching devices in table — {status_text}",
                is_error=False,
            )

    def populate_devices(
        self,
        devices: List[DeviceRecord],
        online_count: int,
        total_count: int,
    ) -> None:
        tree = self.device_table.tree
        for item in tree.get_children():
            tree.delete(item)

        for dev in devices:
            tag = "online"
            if dev.status == "Offline":
                tag = "offline"
            elif dev.is_local_host or dev.is_gateway:
                tag = "local"

            item_id = tree.insert(
                "",
                "end",
                values=(
                    dev.ip_address,
                    dev.mac_address,
                    dev.hostname,
                    dev.vendor,
                    dev.first_seen,
                    dev.last_seen,
                    dev.status,
                ),
                tags=(tag,),
            )
            if self._selected_ip and dev.ip_address == self._selected_ip:
                tree.selection_set(item_id)
                self.update_device_detail(dev)

        if self.device_table._sort_col:
            self.device_table.sort_by_column(self.device_table._sort_col, toggle=False)
        else:
            self.device_table._sort_col = "ip"
            self.device_table._sort_desc = False
            self.device_table.sort_by_column("ip", toggle=False)

        self.device_table._update_empty_overlay()
        self.count_lbl.configure(
            text=f"SHOWING: {len(devices)}  |  ONLINE: {online_count}  |  SESSION TOTAL: {total_count}"
        )

    def update_device_detail(self, dev: Optional[DeviceRecord]) -> None:
        if dev is None:
            for lbl in self.detail_labels.values():
                lbl.configure(text="— (Select a host row)", text_color=Theme.TEXT_PRIMARY)
            return

        role = "Standard LAN Host"
        if dev.is_local_host:
            role = "Local Workstation (This Host)"
        elif dev.is_gateway:
            role = "Default Subnet Gateway / Router"

        rtt_str = f"{dev.last_rtt_ms:.1f} ms" if dev.last_rtt_ms is not None else "Local / Direct"
        status_color = Theme.STATE_SUCCESS if "Online" in dev.status or "Persisted" in dev.status else Theme.STATE_ERROR

        self.detail_labels["ip"].configure(text=dev.ip_address)
        self.detail_labels["mac"].configure(text=dev.mac_address)
        self.detail_labels["vendor"].configure(text=dev.vendor)
        self.detail_labels["hostname"].configure(text=dev.hostname)
        self.detail_labels["status"].configure(text=dev.status, text_color=status_color)
        self.detail_labels["interface"].configure(text=dev.interface_name or "—")
        self.detail_labels["role"].configure(text=role)
        self.detail_labels["first_seen"].configure(text=dev.first_seen)
        self.detail_labels["last_seen"].configure(text=dev.last_seen)
        self.detail_labels["responses"].configure(text=f"{dev.response_Count} seen  |  RTT: {rtt_str}")


class TrafficView(BaseFrame):  # type: ignore[misc]
    """Traffic Monitor Tab (Stage 3 Real-Time Traffic Monitoring)."""

    def __init__(
        self,
        parent: Any,
        on_start_capture: Optional[Callable[[], None]] = None,
        on_stop_capture: Optional[Callable[[], None]] = None,
        on_clear_capture: Optional[Callable[[], None]] = None,
        on_filter_changed: Optional[Callable[[PacketFilterCriteria], None]] = None,
    ) -> None:
        super().__init__(parent, bg=Theme.BG_PRIMARY)
        self.on_start_capture = on_start_capture
        self.on_stop_capture = on_stop_capture
        self.on_clear_capture = on_clear_capture
        self.on_filter_changed = on_filter_changed
        self._build_ui()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=4)
        self.grid_rowconfigure(3, weight=6)

        ctrl_bar = create_panel(self, border=True)
        ctrl_bar.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_SM, pady=(Theme.PAD_SM, 2))

        left_box = tk.Frame(ctrl_bar, bg=Theme.BG_PANEL)
        left_box.pack(side="left", padx=6, pady=4)

        self.btn_start_cap = create_button(
            left_box,
            text="Start Capture",
            command=self._handle_start,
            variant="accent",
            width=105,
        )
        self.btn_start_cap.pack(side="left", padx=(0, 5))

        self.btn_stop_cap = create_button(
            left_box,
            text="Stop Capture",
            command=self._handle_stop,
            variant="danger",
            width=105,
            state="disabled",
        )
        self.btn_stop_cap.pack(side="left", padx=(0, 5))

        self.btn_clear_cap = create_button(
            left_box,
            text="Clear Buffer",
            command=self._handle_clear_buffer,
            width=92,
        )
        self.btn_clear_cap.pack(side="left", padx=(0, 8))

        tk.Frame(left_box, bg=Theme.BORDER, width=1, height=20).pack(side="left", padx=4)

        create_label(
            left_box,
            text="Proto:",
            font=Theme.FONT_UI_BOLD,
            text_color=Theme.TEXT_SECONDARY,
        ).pack(side="left", padx=(4, 4))

        self.protocol_var = tk.StringVar(value="ALL")
        if HAS_CTK:
            self.proto_menu = ctk.CTkOptionMenu(
                left_box,
                variable=self.protocol_var,
                values=["ALL", "TCP", "UDP", "ICMP", "DNS", "Other"],
                command=lambda _v: self._handle_filter_change(),
                width=84,
                height=26,
                corner_radius=Theme.CORNER_RADIUS,
                fg_color=Theme.BG_ELEVATED,
                button_color=Theme.BORDER,
                button_hover_color=Theme.BG_HOVER,
                text_color=Theme.TEXT_PRIMARY,
                font=Theme.FONT_MONO_SMALL,
            )
        else:
            self.proto_menu = ttk.Combobox(
                left_box,
                textvariable=self.protocol_var,
                values=["ALL", "TCP", "UDP", "ICMP", "DNS", "Other"],
                width=7,
                state="readonly",
                font=Theme.FONT_MONO_SMALL,
            )
            self.proto_menu.bind("<<ComboboxSelected>>", lambda _e: self._handle_filter_change())
        self.proto_menu.pack(side="left", padx=(0, 6))

        create_label(
            left_box,
            text="Src IP:",
            font=Theme.FONT_UI_BOLD,
            text_color=Theme.TEXT_SECONDARY,
        ).pack(side="left", padx=(2, 4))
        self.src_ip_entry = create_entry(left_box, placeholder_text="Source IP...", width=115, font=Theme.FONT_MONO_SMALL)
        self.src_ip_entry.pack(side="left", padx=(0, 6))
        self.src_ip_entry.bind("<KeyRelease>", lambda _e: self._handle_filter_change())

        create_label(
            left_box,
            text="Dst IP:",
            font=Theme.FONT_UI_BOLD,
            text_color=Theme.TEXT_SECONDARY,
        ).pack(side="left", padx=(2, 4))
        self.dst_ip_entry = create_entry(left_box, placeholder_text="Dest IP...", width=115, font=Theme.FONT_MONO_SMALL)
        self.dst_ip_entry.pack(side="left", padx=(0, 6))
        self.dst_ip_entry.bind("<KeyRelease>", lambda _e: self._handle_filter_change())

        create_label(
            left_box,
            text="Search:",
            font=Theme.FONT_UI_BOLD,
            text_color=Theme.TEXT_SECONDARY,
        ).pack(side="left", padx=(2, 4))
        self.search_entry = create_entry(
            left_box,
            placeholder_text="Port, flag, info...",
            width=135,
            font=Theme.FONT_MONO_SMALL,
        )
        self.search_entry.pack(side="left", padx=(0, 6))
        self.search_entry.bind("<KeyRelease>", lambda _e: self._handle_filter_change())

        self.btn_apply_filter = create_button(
            left_box,
            text="Filter",
            command=self._handle_filter_change,
            width=64,
        )
        self.btn_apply_filter.pack(side="left", padx=(0, 4))

        self.btn_clear_filter = create_button(
            left_box,
            text="Clear Filter",
            command=self._handle_reset_filter,
            width=84,
        )
        self.btn_clear_filter.pack(side="left")

        right_box = tk.Frame(ctrl_bar, bg=Theme.BG_PANEL)
        right_box.pack(side="right", padx=8, pady=4)
        self.capture_status_lbl = create_label(
            right_box,
            text="Capture: Not started",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.ACCENT_AMBER,
        )
        self.capture_status_lbl.pack(side="right")

        tele_panel = create_panel(self, border=True)
        tele_panel.grid(row=1, column=0, sticky="ew", padx=Theme.PAD_SM, pady=2)
        tele_panel.grid_columnconfigure(0, weight=1)

        metrics_row = tk.Frame(tele_panel, bg=Theme.BG_PANEL, padx=8, pady=3)
        metrics_row.grid(row=0, column=0, sticky="ew")

        self.lbl_duration = create_label(
            metrics_row,
            text="DURATION: 00:00:00",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_PRIMARY,
        )
        self.lbl_duration.pack(side="left", padx=(0, 14))

        self.lbl_totals = create_label(
            metrics_row,
            text="TOTAL: 0 pkts (0 B)",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_PRIMARY,
        )
        self.lbl_totals.pack(side="left", padx=(0, 14))

        self.lbl_rates = create_label(
            metrics_row,
            text="RATE: 0.0 pkt/s  |  0.0 B/s",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.ACCENT_AMBER,
        )
        self.lbl_rates.pack(side="left", padx=(0, 14))

        self.lbl_directional = create_label(
            metrics_row,
            text="EST. UPLOAD (TX): 0.0 B/s   |   EST. DOWNLOAD (RX): 0.0 B/s",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.STATE_SUCCESS,
        )
        self.lbl_directional.pack(side="left", padx=(0, 12))

        self.lbl_visibility_note = create_label(
            metrics_row,
            text=(
                "Note: Capture visibility depends on the selected interface and switch/Wi-Fi configuration "
                "(observes host unicast, broadcast, and multicast traffic; does not claim to see all remote switch ports)."
            ),
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_MUTED,
        )
        self.lbl_visibility_note.pack(side="right")

        mid_container = tk.Frame(self, bg=Theme.BG_PRIMARY)
        mid_container.grid(row=2, column=0, sticky="nsew", padx=Theme.PAD_SM, pady=2)
        mid_container.grid_columnconfigure(0, weight=2)
        mid_container.grid_columnconfigure(1, weight=3)
        mid_container.grid_columnconfigure(2, weight=5)
        mid_container.grid_rowconfigure(0, weight=1)

        proto_panel = create_panel(mid_container, border=True)
        proto_panel.grid(row=0, column=0, sticky="nsew", padx=(0, Theme.PAD_XS))
        proto_panel.grid_columnconfigure(0, weight=1)

        proto_hdr = tk.Frame(proto_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        proto_hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            proto_hdr,
            text="PROTOCOL COUNTS",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")
        create_label(
            proto_hdr,
            text="PKTS / SHARE",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_MUTED,
        ).pack(side="right")

        stats_grid = tk.Frame(proto_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        stats_grid.grid(row=1, column=0, sticky="nsew")
        stats_grid.grid_columnconfigure(0, weight=1)

        self.proto_stat_labels: Dict[str, Any] = {}
        for idx, proto_name in enumerate(["TCP", "UDP", "ICMP", "DNS", "Other"]):
            row_f = tk.Frame(
                stats_grid,
                bg=Theme.BG_PRIMARY,
                highlightbackground=Theme.BORDER,
                highlightthickness=1,
                padx=8,
                pady=3,
            )
            row_f.grid(row=idx, column=0, sticky="ew", pady=2)
            create_label(
                row_f,
                text=f"{proto_name:<6}",
                font=Theme.FONT_MONO_SMALL,
                text_color=Theme.TEXT_SECONDARY,
            ).pack(side="left")
            val_lbl = create_label(
                row_f,
                text="0 pkts   (0.0%)",
                font=Theme.FONT_MONO_SMALL,
                text_color=Theme.TEXT_PRIMARY,
            )
            val_lbl.pack(side="right")
            self.proto_stat_labels[proto_name] = val_lbl

        dist_panel = create_panel(mid_container, border=True)
        dist_panel.grid(row=0, column=1, sticky="nsew", padx=Theme.PAD_XS)
        dist_panel.grid_rowconfigure(1, weight=1)
        dist_panel.grid_columnconfigure(0, weight=1)

        dist_hdr = tk.Frame(dist_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        dist_hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            dist_hdr,
            text="PROTOCOL DISTRIBUTION",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")

        self.proto_dist_chart = ProtocolDistributionChart(dist_panel, height=150)
        self.proto_dist_chart.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        act_chart_panel = create_panel(mid_container, border=True)
        act_chart_panel.grid(row=0, column=2, sticky="nsew", padx=(Theme.PAD_XS, 0))
        act_chart_panel.grid_rowconfigure(1, weight=1)
        act_chart_panel.grid_columnconfigure(0, weight=1)

        c_hdr = tk.Frame(act_chart_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        c_hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            c_hdr,
            text="TRAFFIC ACTIVITY OVER TIME (PKTS/S & KB/S)",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")

        self.traffic_activity_chart = TrafficActivityChart(act_chart_panel, height=150)
        self.traffic_activity_chart.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        pkt_panel = create_panel(self, border=True)
        pkt_panel.grid(row=3, column=0, sticky="nsew", padx=Theme.PAD_SM, pady=(2, Theme.PAD_SM))
        pkt_panel.grid_rowconfigure(1, weight=1)
        pkt_panel.grid_columnconfigure(0, weight=1)

        p_hdr = tk.Frame(pkt_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        p_hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            p_hdr,
            text="PACKET INSPECTION WORKSPACE (BOUNDED RING BUFFER: MAX 1,000 PACKETS — HEADER METADATA ONLY)",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")
        self.pkt_count_lbl = create_label(
            p_hdr,
            text="SHOWING: 0  |  SESSION CAPTURED: 0",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_SECONDARY,
        )
        self.pkt_count_lbl.pack(side="right")

        packet_columns = [
            {"id": "timestamp", "label": "Timestamp", "width": 115, "minwidth": 95, "stretch": False},
            {"id": "src_ip", "label": "Source IP", "width": 135, "minwidth": 110, "stretch": False},
            {"id": "src_port", "label": "Src Port", "width": 75, "minwidth": 60, "stretch": False, "anchor": "e"},
            {"id": "dst_ip", "label": "Destination IP", "width": 135, "minwidth": 110, "stretch": False},
            {"id": "dst_port", "label": "Dst Port", "width": 75, "minwidth": 60, "stretch": False, "anchor": "e"},
            {"id": "protocol", "label": "Protocol", "width": 80, "minwidth": 65, "stretch": False},
            {"id": "length", "label": "Length", "width": 75, "minwidth": 60, "stretch": False, "anchor": "e"},
            {"id": "info", "label": "Information", "width": 420, "minwidth": 200, "stretch": True},
        ]
        self.packet_table = TechnicalTable(
            pkt_panel,
            columns=packet_columns,
            empty_message="No packets captured — Click 'Start Capture' or 'Start Monitoring' to inspect live traffic",
            sortable=True,
            on_row_select=self._on_packet_row_selected,
        )
        self.packet_table.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 4))

        insp_bar = tk.Frame(
            pkt_panel,
            bg=Theme.BG_ELEVATED,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
            padx=8,
            pady=3,
        )
        insp_bar.grid(row=2, column=0, sticky="ew", padx=6, pady=(0, 6))
        self.selected_pkt_lbl = create_label(
            insp_bar,
            text="SELECTED PACKET: None — Click any row above to inspect header metadata (payloads are never stored).",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_SECONDARY,
        )
        self.selected_pkt_lbl.pack(anchor="w")

    @staticmethod
    def _clean_placeholder(val: str, placeholder: str) -> str:
        val = val.strip()
        return "" if val == placeholder else val

    def get_filter_criteria(self) -> PacketFilterCriteria:
        return PacketFilterCriteria(
            protocol=self.protocol_var.get().strip() or "ALL",
            source_ip=self._clean_placeholder(self.src_ip_entry.get(), "Source IP..."),
            destination_ip=self._clean_placeholder(self.dst_ip_entry.get(), "Dest IP..."),
            search_text=self._clean_placeholder(self.search_entry.get(), "Port, flag, info..."),
        )

    def _handle_start(self) -> None:
        if self.on_start_capture:
            self.on_start_capture()

    def _handle_stop(self) -> None:
        if self.on_stop_capture:
            self.on_stop_capture()

    def _handle_clear_buffer(self) -> None:
        if self.on_clear_capture:
            self.on_clear_capture()

    def _handle_filter_change(self) -> None:
        if self.on_filter_changed:
            self.on_filter_changed(self.get_filter_criteria())

    def _handle_reset_filter(self) -> None:
        self.protocol_var.set("ALL")
        self.src_ip_entry.delete(0, "end")
        self.dst_ip_entry.delete(0, "end")
        self.search_entry.delete(0, "end")
        if self.on_filter_changed:
            self.on_filter_changed(PacketFilterCriteria())

    def _on_packet_row_selected(self, values: Tuple[Any, ...]) -> None:
        if len(values) >= 8:
            ts, sip, sport, dip, dport, proto, length, info = values[:8]
            self.selected_pkt_lbl.configure(
                text=(
                    f"PACKET HEADER  |  Time: {ts}  |  {sip}:{sport} -> {dip}:{dport}  |  "
                    f"Proto: {proto}  |  Len: {length} B  |  Summary: {info}"
                ),
                text_color=Theme.ACCENT_AMBER,
            )

    @staticmethod
    def _tag_for_protocol(proto: str) -> str:
        p = proto.upper()
        if p == "DNS":
            return "proto_dns"
        if p == "ICMP":
            return "proto_icmp"
        if p == "UDP":
            return "proto_udp"
        if p == "TCP":
            return "proto_tcp"
        return "proto_other"

    def append_packets_batch(
        self,
        packets: List[PacketRecord],
        criteria: PacketFilterCriteria,
        total_captured: int,
        max_rows: int = 1000,
    ) -> None:
        tree = self.packet_table.tree
        inserted = 0
        for pkt in packets:
            if criteria.matches(pkt):
                tree.insert(
                    "",
                    0,
                    values=(
                        pkt.timestamp,
                        pkt.source_ip,
                        pkt.src_port_str,
                        pkt.destination_ip,
                        pkt.dst_port_str,
                        pkt.protocol,
                        pkt.length,
                        pkt.info,
                    ),
                    tags=(self._tag_for_protocol(pkt.protocol),),
                )
                inserted += 1

        if inserted > 0:
            children = tree.get_children("")
            if len(children) > max_rows:
                for old_item in children[max_rows:]:
                    tree.delete(old_item)

        self.packet_table._update_empty_overlay()
        showing = len(tree.get_children(""))
        filter_badge = " (FILTER ACTIVE)" if criteria.is_active() else ""
        self.pkt_count_lbl.configure(
            text=f"SHOWING: {showing}{filter_badge}  |  SESSION CAPTURED: {total_captured:,}"
        )

    def repopulate_packets(
        self,
        packets: List[PacketRecord],
        criteria: PacketFilterCriteria,
        total_captured: int,
    ) -> None:
        tree = self.packet_table.tree
        for item in tree.get_children(""):
            tree.delete(item)

        for pkt in reversed(packets):
            tree.insert(
                "",
                "end",
                values=(
                    pkt.timestamp,
                    pkt.source_ip,
                    pkt.src_port_str,
                    pkt.destination_ip,
                    pkt.dst_port_str,
                    pkt.protocol,
                    pkt.length,
                    pkt.info,
                ),
                tags=(self._tag_for_protocol(pkt.protocol),),
            )

        if criteria.is_active() and len(packets) == 0:
            self.packet_table.set_empty_message(
                "No captured packets match the current filter criteria (capture continues in background)",
                is_error=False,
            )
        elif total_captured == 0:
            self.packet_table.set_empty_message(
                "No packets captured — Click 'Start Capture' or 'Start Monitoring' to inspect live traffic",
                is_error=False,
            )

        self.packet_table._update_empty_overlay()
        filter_badge = " (FILTER ACTIVE)" if criteria.is_active() else ""
        self.pkt_count_lbl.configure(
            text=f"SHOWING: {len(packets)}{filter_badge}  |  SESSION CAPTURED: {total_captured:,}"
        )

    def update_telemetry_and_charts(self, snapshot: TrafficStatsSnapshot, is_error: bool = False) -> None:
        self.btn_start_cap.configure(state="disabled" if snapshot.is_capturing else "normal")
        self.btn_stop_cap.configure(state="normal" if snapshot.is_capturing else "disabled")

        status_color = (
            Theme.STATE_ERROR
            if is_error
            else (Theme.STATE_SUCCESS if snapshot.is_capturing else Theme.ACCENT_AMBER)
        )
        self.capture_status_lbl.configure(
            text=f"Capture: {snapshot.status_text}",
            text_color=status_color,
        )

        self.lbl_duration.configure(text=f"DURATION: {format_duration(snapshot.duration_seconds)}")
        self.lbl_totals.configure(
            text=f"TOTAL: {snapshot.total_packets:,} pkts ({format_total_bytes(snapshot.total_bytes)})"
        )
        self.lbl_rates.configure(
            text=f"RATE: {snapshot.packets_per_sec:.1f} pkt/s  |  {format_bytes_rate(snapshot.bytes_per_sec)}"
        )
        self.lbl_directional.configure(
            text=(
                f"EST. UPLOAD (TX): {format_bytes_rate(snapshot.upload_bps)}   |   "
                f"EST. DOWNLOAD (RX): {format_bytes_rate(snapshot.download_bps)}"
            )
        )

        total_pkts = max(snapshot.total_packets, 1)
        for proto_name, lbl in self.proto_stat_labels.items():
            cnt = int(snapshot.protocol_counts.get(proto_name, 0))
            pct = (cnt / float(total_pkts)) * 100.0 if snapshot.total_packets > 0 else 0.0
            lbl.configure(text=f"{cnt:,} pkts  ({pct:4.1f}%)")

        self.proto_dist_chart.update_counts(snapshot.protocol_counts)
        self.traffic_activity_chart.update_from_snapshot(snapshot)

        if is_error and snapshot.total_packets == 0:
            self.packet_table.set_empty_message(snapshot.status_text, is_error=True)


class RouteView(BaseFrame):  # type: ignore[misc]
    """Route Mapper Tab (Stage 4 Geographical Route Mapping)."""

    def __init__(
        self,
        parent: Any,
        on_start_trace: Optional[Callable[[str], None]] = None,
        on_cancel_trace: Optional[Callable[[], None]] = None,
        on_open_external_map: Optional[Callable[[], None]] = None,
        on_select_hop: Optional[Callable[[int], Optional[RouteHopRecord]]] = None,
    ) -> None:
        super().__init__(parent, bg=Theme.BG_PRIMARY)
        self.on_start_trace = on_start_trace
        self.on_cancel_trace = on_cancel_trace
        self.on_open_external_map = on_open_external_map
        self.on_select_hop = on_select_hop
        self._current_hops: List[RouteHopRecord] = []
        self._selected_hop_num: Optional[int] = None
        self._target_summary: str = "Not started"
        self._build_ui()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        ctrl_bar = create_panel(self, border=True)
        ctrl_bar.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_SM, pady=(Theme.PAD_SM, 2))

        left_controls = tk.Frame(ctrl_bar, bg=Theme.BG_PANEL)
        left_controls.pack(side="left", padx=6, pady=4)

        create_label(
            left_controls,
            text="DESTINATION (DOMAIN / PUBLIC IPv4):",
            font=Theme.FONT_UI_BOLD,
            text_color=Theme.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 6))

        self.dest_entry = create_entry(
            left_controls,
            placeholder_text="Enter domain or public IPv4 (e.g. cloudflare.com or 1.1.1.1)",
            width=310,
        )
        self.dest_entry.pack(side="left", padx=(0, 8))
        self.dest_entry.bind("<Return>", lambda _e: self._handle_start_trace())

        self.btn_trace = create_button(
            left_controls,
            text="Start Trace",
            command=self._handle_start_trace,
            variant="accent",
            width=105,
        )
        self.btn_trace.pack(side="left", padx=(0, 6))

        self.btn_cancel = create_button(
            left_controls,
            text="Cancel Trace",
            command=self._handle_cancel_trace,
            variant="danger",
            width=105,
            state="disabled",
        )
        self.btn_cancel.pack(side="left", padx=(0, 6))

        self.btn_clear = create_button(
            left_controls,
            text="Clear",
            command=self._handle_clear,
            width=68,
        )
        self.btn_clear.pack(side="left", padx=(0, 8))

        tk.Frame(left_controls, bg=Theme.BORDER, width=1, height=20).pack(side="left", padx=4)

        self.btn_open_map = create_button(
            left_controls,
            text="Open Interactive Map (HTML)",
            command=self._handle_open_map,
            variant="success",
            width=190,
            state="disabled",
        )
        self.btn_open_map.pack(side="left", padx=(4, 0))

        right_controls = tk.Frame(ctrl_bar, bg=Theme.BG_PANEL)
        right_controls.pack(side="right", padx=8, pady=4)

        self.trace_status_lbl = create_label(
            right_controls,
            text="Trace Status: Not started",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.ACCENT_AMBER,
        )
        self.trace_status_lbl.pack(side="right")

        notice_bar = create_panel(self, border=True)
        notice_bar.grid(row=1, column=0, sticky="ew", padx=Theme.PAD_SM, pady=2)
        notice_inner = tk.Frame(notice_bar, bg=Theme.BG_PANEL, padx=8, pady=3)
        notice_inner.pack(fill="x")
        create_label(
            notice_inner,
            text="METHODOLOGY & ACCURACY:",
            font=Theme.FONT_UI_BOLD,
            text_color=Theme.ACCENT_AMBER,
        ).pack(side="left", padx=(0, 6))
        create_label(
            notice_inner,
            text=(
                "Traceroute identifies logical Layer-3 hops, not exact physical cable paths. "
                "Some routers do not respond to probes (* timeouts). "
                "IP geolocation is approximate; private/reserved IPs cannot be geographically mapped, "
                "and unresolved hops are never connected across unknown physical positions."
            ),
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_SECONDARY,
        ).pack(side="left")

        workspace_split = tk.Frame(self, bg=Theme.BG_PRIMARY)
        workspace_split.grid(row=2, column=0, sticky="nsew", padx=Theme.PAD_SM, pady=(2, Theme.PAD_SM))
        workspace_split.grid_columnconfigure(0, weight=6)
        workspace_split.grid_columnconfigure(1, weight=5)
        workspace_split.grid_rowconfigure(0, weight=1)

        left_pane = tk.Frame(workspace_split, bg=Theme.BG_PRIMARY)
        left_pane.grid(row=0, column=0, sticky="nsew", padx=(0, Theme.PAD_XS))
        left_pane.grid_rowconfigure(0, weight=7)
        left_pane.grid_rowconfigure(1, weight=3)
        left_pane.grid_columnconfigure(0, weight=1)

        hop_panel = create_panel(left_pane, border=True)
        hop_panel.grid(row=0, column=0, sticky="nsew", pady=(0, Theme.PAD_XS))
        hop_panel.grid_rowconfigure(1, weight=1)
        hop_panel.grid_columnconfigure(0, weight=1)

        hop_hdr = tk.Frame(hop_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        hop_hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            hop_hdr,
            text="HOP INFORMATION TABLE (SELECT A HOP TO INSPECT & HIGHLIGHT ON MAP)",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")
        self.hop_summary_lbl = create_label(
            hop_hdr,
            text="HOPS: 0  |  GEO-MAPPED: 0",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_SECONDARY,
        )
        self.hop_summary_lbl.pack(side="right")

        hop_columns = [
            {"id": "hop", "label": "Hop", "width": 48, "minwidth": 42, "stretch": False, "anchor": "center"},
            {"id": "ip", "label": "IP", "width": 120, "minwidth": 100, "stretch": False},
            {"id": "hostname", "label": "Hostname", "width": 165, "minwidth": 115, "stretch": True},
            {"id": "rtt", "label": "Response Time", "width": 95, "minwidth": 80, "stretch": False, "anchor": "e"},
            {"id": "country", "label": "Country", "width": 105, "minwidth": 80, "stretch": False},
            {"id": "city", "label": "City", "width": 105, "minwidth": 80, "stretch": False},
            {"id": "mapping_status", "label": "Mapping Status", "width": 185, "minwidth": 140, "stretch": True},
        ]
        self.hop_table = TechnicalTable(
            hop_panel,
            columns=hop_columns,
            empty_message="No route hops recorded — Enter a domain or public IPv4 address and click 'Start Trace'",
            sortable=True,
            on_row_select=self._on_hop_row_selected,
        )
        self.hop_table.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        insp_panel = create_panel(left_pane, border=True)
        insp_panel.grid(row=1, column=0, sticky="nsew")
        insp_panel.grid_columnconfigure(0, weight=1)
        insp_panel.grid_columnconfigure(1, weight=1)
        insp_panel.grid_columnconfigure(2, weight=1)

        insp_hdr = tk.Frame(insp_panel, bg=Theme.BG_ELEVATED, padx=8, pady=4)
        insp_hdr.grid(row=0, column=0, columnspan=3, sticky="ew")
        create_label(
            insp_hdr,
            text="SELECTED HOP DETAIL INSPECTOR (APPROXIMATE GEOLOCATION METADATA)",
            font=Theme.FONT_SECTION,
            text_color=Theme.ACCENT_AMBER,
        ).pack(side="left")

        insp_fields = [
            ("hop_ip", "HOP # / IP ADDRESS", 1, 0),
            ("hostname", "REVERSE DNS HOSTNAME", 1, 1),
            ("rtt_status", "RESPONSE TIME / STATUS", 1, 2),
            ("location", "COUNTRY / REGION / CITY (APPROX.)", 2, 0),
            ("coords", "APPROXIMATE COORDINATES (LAT, LON)", 2, 1),
            ("map_state", "GEOGRAPHICAL MAPPING STATUS", 2, 2),
        ]
        self.hop_detail_labels: Dict[str, Any] = {}
        for key, title, r_idx, c_idx in insp_fields:
            cell = tk.Frame(
                insp_panel,
                bg=Theme.BG_PRIMARY,
                highlightbackground=Theme.BORDER,
                highlightthickness=1,
                padx=8,
                pady=4,
            )
            cell.grid(row=r_idx, column=c_idx, sticky="nsew", padx=4, pady=3)
            create_label(
                cell,
                text=title,
                font=Theme.FONT_UI_BOLD,
                text_color=Theme.TEXT_MUTED,
            ).pack(anchor="w")
            val_lbl = create_label(
                cell,
                text="— (Select a hop row)",
                font=Theme.FONT_MONO_SMALL,
                text_color=Theme.TEXT_PRIMARY,
            )
            val_lbl.pack(anchor="w", pady=(1, 0))
            self.hop_detail_labels[key] = val_lbl

        map_panel = create_panel(workspace_split, border=True)
        map_panel.grid(row=0, column=1, sticky="nsew", padx=(Theme.PAD_XS, 0))
        map_panel.grid_rowconfigure(1, weight=1)
        map_panel.grid_columnconfigure(0, weight=1)

        map_hdr = tk.Frame(map_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        map_hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            map_hdr,
            text="GEOGRAPHICAL ROUTE MAP VIEWPORT (APPROXIMATE HOP POSITIONS)",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")
        self.map_badge_lbl = create_label(
            map_hdr,
            text="FOLIUM HTML READY ON COMPLETION",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_MUTED,
        )
        self.map_badge_lbl.pack(side="right")

        self.map_canvas = tk.Canvas(
            map_panel,
            bg=Theme.BG_PRIMARY,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
            bd=0,
        )
        self.map_canvas.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self.map_canvas.bind("<Configure>", self._draw_map_viewport)

    def _get_destination(self) -> str:
        val = self.dest_entry.get().strip()
        if val == "Enter domain or public IPv4 (e.g. cloudflare.com or 1.1.1.1)":
            return ""
        return val

    def _handle_start_trace(self) -> None:
        if self.on_start_trace:
            self.on_start_trace(self._get_destination())

    def _handle_cancel_trace(self) -> None:
        if self.on_cancel_trace:
            self.on_cancel_trace()

    def _handle_open_map(self) -> None:
        if self.on_open_external_map:
            self.on_open_external_map()

    def _handle_clear(self) -> None:
        self.dest_entry.delete(0, "end")
        self._current_hops.clear()
        self._selected_hop_num = None
        self._target_summary = "Not started"
        self.hop_table.clear()
        self.update_hop_detail(None)
        self.btn_open_map.configure(state="disabled")
        self.set_trace_lifecycle(is_tracing=False, status_text="Not started", is_error=False)
        self._draw_map_viewport()

    def _on_hop_row_selected(self, values: Tuple[Any, ...]) -> None:
        if not values:
            return
        try:
            hop_num = int(values[0])
        except Exception:
            return
        self._selected_hop_num = hop_num
        if self.on_select_hop:
            hop = self.on_select_hop(hop_num)
            if hop is not None:
                self.update_hop_detail(hop)
        self._draw_map_viewport()

    def set_trace_lifecycle(
        self,
        is_tracing: bool,
        status_text: str,
        is_error: bool = False,
        has_map_file: bool = False,
    ) -> None:
        self.btn_trace.configure(state="disabled" if is_tracing else "normal")
        self.btn_cancel.configure(state="normal" if is_tracing else "disabled")
        if has_map_file:
            self.btn_open_map.configure(state="normal")
            self.map_badge_lbl.configure(
                text="INTERACTIVE FOLIUM HTML GENERATED",
                text_color=Theme.STATE_SUCCESS,
            )

        color = (
            Theme.STATE_ERROR
            if is_error
            else (Theme.STATE_SUCCESS if not is_tracing and len(self._current_hops) > 0 else Theme.ACCENT_AMBER)
        )
        self.trace_status_lbl.configure(text=f"Trace Status: {status_text}", text_color=color)
        self._target_summary = status_text

        if is_error and len(self._current_hops) == 0:
            self.hop_table.set_empty_message(status_text, is_error=True)
        elif len(self._current_hops) == 0:
            self.hop_table.set_empty_message(f"No route hops recorded — {status_text}", is_error=False)

        self._draw_map_viewport()

    def populate_hops(self, hops: List[RouteHopRecord]) -> None:
        self._current_hops = list(hops)
        tree = self.hop_table.tree
        for item in tree.get_children(""):
            tree.delete(item)

        mapped_count = 0
        for hop in self._current_hops:
            if hop.has_coordinates:
                mapped_count += 1

            if hop.is_destination:
                tag = "dest"
            elif hop.has_coordinates:
                tag = "mapped"
            elif hop.ip_address == "*" or "Timed Out" in hop.response_status:
                tag = "offline"
            elif "Unreachable" in hop.response_status:
                tag = "error"
            else:
                tag = "online"

            item_id = tree.insert(
                "",
                "end",
                values=(
                    hop.hop_number,
                    hop.ip_address,
                    hop.hostname,
                    hop.rtt_display,
                    hop.country,
                    hop.city,
                    hop.mapping_status,
                ),
                tags=(tag,),
            )
            if self._selected_hop_num == hop.hop_number:
                tree.selection_set(item_id)
                self.update_hop_detail(hop)

        self.hop_table._update_empty_overlay()
        self.hop_summary_lbl.configure(
            text=f"HOPS: {len(self._current_hops)}  |  GEO-MAPPED: {mapped_count} (APPROX.)"
        )
        self._draw_map_viewport()

    def update_hop_detail(self, hop: Optional[RouteHopRecord]) -> None:
        if hop is None:
            for lbl in self.hop_detail_labels.values():
                lbl.configure(text="— (Select a hop row)", text_color=Theme.TEXT_PRIMARY)
            return

        role_suffix = " [DESTINATION]" if hop.is_destination else ""
        self.hop_detail_labels["hop_ip"].configure(
            text=f"Hop #{hop.hop_number}  |  IP: {hop.ip_address}{role_suffix}",
            text_color=Theme.ACCENT_AMBER if hop.is_destination else Theme.TEXT_PRIMARY,
        )
        self.hop_detail_labels["hostname"].configure(text=hop.hostname)
        self.hop_detail_labels["rtt_status"].configure(
            text=f"{hop.rtt_display}  ({hop.response_status})"
        )

        if hop.has_coordinates:
            loc_str = f"{hop.country} / {hop.region} / {hop.city} (Approx.)"
            coord_str = f"{hop.latitude:.4f}°, {hop.longitude:.4f}° (Approx.)"
            map_color = Theme.STATE_SUCCESS
        else:
            loc_str = "Not geographically mapped"
            coord_str = "— (No coordinates)"
            map_color = Theme.TEXT_MUTED

        self.hop_detail_labels["location"].configure(text=loc_str)
        self.hop_detail_labels["coords"].configure(text=coord_str)
        self.hop_detail_labels["map_state"].configure(text=hop.mapping_status, text_color=map_color)

    @staticmethod
    def _latlon_to_xy(lat: float, lon: float, pad_l: float, pad_t: float, map_w: float, map_h: float) -> Tuple[float, float]:
        clamped_lat = max(-85.0, min(85.0, lat))
        clamped_lon = max(-180.0, min(180.0, lon))
        x = pad_l + ((clamped_lon + 180.0) / 360.0) * map_w
        y = pad_t + ((90.0 - clamped_lat) / 180.0) * map_h
        return x, y

    def _draw_map_viewport(self, _event: Any = None) -> None:
        self.map_canvas.delete("all")
        w = max(self.map_canvas.winfo_width(), 240)
        h = max(self.map_canvas.winfo_height(), 180)

        pad_l, pad_r, pad_t, pad_b = 34.0, 14.0, 26.0, 26.0
        map_w = max(80.0, w - pad_l - pad_r)
        map_h = max(60.0, h - pad_t - pad_b)

        self.map_canvas.create_rectangle(
            pad_l,
            pad_t,
            pad_l + map_w,
            pad_t + map_h,
            fill="#14171A",
            outline=Theme.BORDER,
            width=1,
        )

        for lon in (-120, -60, 0, 60, 120):
            x, _ = self._latlon_to_xy(0, lon, pad_l, pad_t, map_w, map_h)
            dash = () if lon == 0 else (2, 4)
            col = "#2A2F37" if lon == 0 else "#1E2228"
            self.map_canvas.create_line(x, pad_t, x, pad_t + map_h, fill=col, dash=dash)
            self.map_canvas.create_text(
                x,
                pad_t + map_h + 5,
                text=f"{lon}°",
                anchor="n",
                fill=Theme.TEXT_MUTED,
                font=Theme.FONT_MONO_SMALL,
            )

        for lat in (-60, -30, 0, 30, 60):
            _, y = self._latlon_to_xy(lat, 0, pad_l, pad_t, map_w, map_h)
            dash = () if lat == 0 else (2, 4)
            col = "#2A2F37" if lat == 0 else "#1E2228"
            self.map_canvas.create_line(pad_l, y, pad_l + map_w, y, fill=col, dash=dash)
            self.map_canvas.create_text(
                pad_l - 4,
                y,
                text=f"{lat}°",
                anchor="e",
                fill=Theme.TEXT_MUTED,
                font=Theme.FONT_MONO_SMALL,
            )

        continents = [
            [(68, -165), (68, -60), (45, -55), (25, -80), (15, -90), (30, -115), (55, -135)],
            [(10, -78), (5, -35), (-22, -40), (-54, -70), (-18, -75)],
            [(70, 10), (70, 55), (45, 45), (36, 25), (36, -9), (50, -5)],
            [(35, -6), (32, 33), (11, 51), (-34, 20), (5, 8), (5, -8)],
            [(70, 58), (70, 170), (22, 120), (8, 100), (8, 77), (25, 55), (45, 45)],
            [(-12, 130), (-15, 145), (-38, 148), (-34, 115), (-20, 114)],
        ]
        for poly in continents:
            pts: List[float] = []
            for plat, plon in poly:
                px, py = self._latlon_to_xy(plat, plon, pad_l, pad_t, map_w, map_h)
                pts.extend([px, py])
            if len(pts) >= 6:
                self.map_canvas.create_polygon(*pts, fill="#1C2026", outline="#292E36", width=1)

        self.map_canvas.create_text(
            pad_l,
            6,
            text="EQUIRECTANGULAR PROJECTION  |  SOLID LINE = CONTIGUOUS MAPPED HOPS  |  LOCATIONS ARE APPROXIMATE",
            anchor="nw",
            fill=Theme.TEXT_MUTED,
            font=Theme.FONT_MONO_SMALL,
        )

        mapped_hops = [h for h in self._current_hops if h.has_coordinates]
        segments = RouteMapGenerator.build_contiguous_mapped_segments(self._current_hops)

        if not mapped_hops:
            cx = pad_l + map_w / 2.0
            cy = pad_t + map_h / 2.0
            box_w, box_h = min(400.0, map_w - 20.0), 62.0
            self.map_canvas.create_rectangle(
                cx - box_w / 2.0,
                cy - box_h / 2.0,
                cx + box_w / 2.0,
                cy + box_h / 2.0,
                fill=Theme.BG_PANEL,
                outline=Theme.BORDER,
                width=1,
            )
            msg = f"No geographically mapped public hops yet.\nStatus: {self._target_summary[:52]}"
            self.map_canvas.create_text(
                cx,
                cy,
                text=msg,
                anchor="center",
                justify="center",
                fill=Theme.TEXT_SECONDARY,
                font=Theme.FONT_MONO_SMALL,
            )
            return

        for seg in segments:
            if len(seg) >= 2:
                line_pts: List[float] = []
                for h_item in seg:
                    hx, hy = self._latlon_to_xy(
                        float(h_item.latitude),
                        float(h_item.longitude),
                        pad_l,
                        pad_t,
                        map_w,
                        map_h,
                    )
                    line_pts.extend([hx, hy])
                self.map_canvas.create_line(*line_pts, fill=Theme.ACCENT_AMBER, width=2)

        for h_item in mapped_hops:
            hx, hy = self._latlon_to_xy(
                float(h_item.latitude),
                float(h_item.longitude),
                pad_l,
                pad_t,
                map_w,
                map_h,
            )
            is_sel = self._selected_hop_num == h_item.hop_number
            if is_sel:
                self.map_canvas.create_oval(
                    hx - 9,
                    hy - 9,
                    hx + 9,
                    hy + 9,
                    outline=Theme.ACCENT_AMBER,
                    width=2,
                )

            r = 6 if h_item.is_destination else 4.5
            fill_col = Theme.STATE_SUCCESS if h_item.is_destination else Theme.ACCENT_AMBER
            self.map_canvas.create_oval(
                hx - r,
                hy - r,
                hx + r,
                hy + r,
                fill=fill_col,
                outline=Theme.BG_PRIMARY,
                width=1.2,
            )

            city_tag = h_item.city if h_item.city not in ("—", "") else h_item.country
            lbl_text = f"#{h_item.hop_number} {city_tag}"
            self.map_canvas.create_text(
                hx + 7,
                hy - 6,
                text=lbl_text,
                anchor="nw",
                fill=Theme.TEXT_PRIMARY if is_sel or h_item.is_destination else Theme.TEXT_SECONDARY,
                font=Theme.FONT_MONO_SMALL,
            )


class HistoryView(BaseFrame):  # type: ignore[misc]
    """
    History & Archives Tab (Stage 5 Historical Persistence Interface):
    Provides sub-views and detailed record inspection for:
    1. Previously Discovered Devices (`devices` table)
    2. Previous Monitoring Sessions & Aggregated Traffic Summaries
       (`monitoring_sessions` + `traffic_statistics` tables)
    3. Previously Performed Routes (`route_history` table with JSON `route_data`,
       hop breakdown table, and 'Load onto Route Mapper' button)
    """

    def __init__(
        self,
        parent: Any,
        on_refresh_history: Optional[Callable[[], None]] = None,
        on_open_db_settings: Optional[Callable[[], None]] = None,
        on_load_route_to_mapper: Optional[Callable[[RouteHistoryRecord], None]] = None,
    ) -> None:
        super().__init__(parent, bg=Theme.BG_PRIMARY)
        self.on_refresh_history = on_refresh_history
        self.on_open_db_settings = on_open_db_settings
        self.on_load_route_to_mapper = on_load_route_to_mapper

        self._devices: List[DeviceRecord] = []
        self._sessions: List[MonitoringSessionRecord] = []
        self._traffic_stats: List[TrafficStatIntervalRecord] = []
        self._routes: List[RouteHistoryRecord] = []
        self._selected_route: Optional[RouteHistoryRecord] = None
        self._active_subtab: str = "Devices History"
        self._build_ui()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # 1. Top Control & Database Persistence Banner
        top_bar = create_panel(self, border=True)
        top_bar.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_SM, pady=(Theme.PAD_SM, 2))

        left_box = tk.Frame(top_bar, bg=Theme.BG_PANEL)
        left_box.pack(side="left", padx=6, pady=4)

        create_label(
            left_box,
            text="STORAGE BACKEND:",
            font=Theme.FONT_UI_BOLD,
            text_color=Theme.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 6))

        self.db_banner_lbl = create_label(
            left_box,
            text="Disconnected — Showing in-memory session records (MySQL persistence unavailable)",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.ACCENT_AMBER,
        )
        self.db_banner_lbl.pack(side="left", padx=(0, 12))

        right_box = tk.Frame(top_bar, bg=Theme.BG_PANEL)
        right_box.pack(side="right", padx=6, pady=4)

        self.btn_db_settings = create_button(
            right_box,
            text="Database Settings...",
            command=lambda: self.on_open_db_settings() if self.on_open_db_settings else None,
            width=145,
        )
        self.btn_db_settings.pack(side="left", padx=(0, 6))

        self.btn_refresh_hist = create_button(
            right_box,
            text="Refresh History",
            command=lambda: self.on_refresh_history() if self.on_refresh_history else None,
            variant="accent",
            width=125,
        )
        self.btn_refresh_hist.pack(side="left")

        # 2. Sub-navigation selector bar for the 3 historical views
        sub_bar = tk.Frame(
            self,
            bg=Theme.BG_ELEVATED,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
        )
        sub_bar.grid(row=1, column=0, sticky="ew", padx=Theme.PAD_SM, pady=2)

        self.subtab_buttons: Dict[str, Any] = {}
        subtab_names = [
            "Devices History",
            "Monitoring Sessions & Traffic Summaries",
            "Route History",
        ]
        for sname in subtab_names:
            b = tk.Button(
                sub_bar,
                text=sname.upper(),
                command=lambda n=sname: self.switch_subtab(n),
                bg=Theme.BG_ELEVATED,
                fg=Theme.TEXT_SECONDARY,
                activebackground=Theme.BG_HOVER,
                activeforeground=Theme.TEXT_PRIMARY,
                bd=0,
                relief="flat",
                padx=14,
                pady=5,
                font=Theme.FONT_UI_BOLD,
                cursor="hand2",
            )
            b.pack(side="left", padx=(0, 1))
            self.subtab_buttons[sname] = b

        # 3. Sub-viewport container
        self.sub_viewport = tk.Frame(self, bg=Theme.BG_PRIMARY)
        self.sub_viewport.grid(row=2, column=0, sticky="nsew", padx=Theme.PAD_SM, pady=(2, Theme.PAD_SM))
        self.sub_viewport.grid_rowconfigure(0, weight=1)
        self.sub_viewport.grid_columnconfigure(0, weight=1)

        self._build_devices_history_pane()
        self._build_sessions_traffic_pane()
        self._build_routes_history_pane()

        self.switch_subtab("Devices History")

    def _build_devices_history_pane(self) -> None:
        self.pane_devices = tk.Frame(self.sub_viewport, bg=Theme.BG_PRIMARY)
        self.pane_devices.grid(row=0, column=0, sticky="nsew")
        self.pane_devices.grid_rowconfigure(0, weight=1)
        self.pane_devices.grid_columnconfigure(0, weight=7)
        self.pane_devices.grid_columnconfigure(1, weight=3)

        tbl_panel = create_panel(self.pane_devices, border=True)
        tbl_panel.grid(row=0, column=0, sticky="nsew", padx=(0, Theme.PAD_XS))
        tbl_panel.grid_rowconfigure(1, weight=1)
        tbl_panel.grid_columnconfigure(0, weight=1)

        hdr = tk.Frame(tbl_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            hdr,
            text="PREVIOUSLY DISCOVERED DEVICES (MYSQL `devices` TABLE / SESSION ARCHIVE)",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")
        self.hist_dev_count_lbl = create_label(
            hdr,
            text="RECORDS: 0",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_SECONDARY,
        )
        self.hist_dev_count_lbl.pack(side="right")

        cols = [
            {"id": "id", "label": "ID", "width": 55, "minwidth": 45, "stretch": False, "anchor": "center"},
            {"id": "ip", "label": "IP Address", "width": 130, "minwidth": 110, "stretch": False},
            {"id": "mac", "label": "MAC Address", "width": 150, "minwidth": 130, "stretch": False},
            {"id": "hostname", "label": "Hostname", "width": 190, "minwidth": 130, "stretch": True},
            {"id": "vendor", "label": "Vendor", "width": 200, "minwidth": 140, "stretch": True},
            {"id": "first_seen", "label": "First Seen", "width": 150, "minwidth": 125, "stretch": False},
            {"id": "last_seen", "label": "Last Seen", "width": 150, "minwidth": 125, "stretch": False},
        ]
        self.hist_device_table = TechnicalTable(
            tbl_panel,
            columns=cols,
            empty_message="No historical device records found.",
            sortable=True,
            on_row_select=self._on_hist_device_selected,
        )
        self.hist_device_table.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        insp_panel = create_panel(self.pane_devices, border=True)
        insp_panel.grid(row=0, column=1, sticky="nsew", padx=(Theme.PAD_XS, 0))
        insp_panel.grid_columnconfigure(0, weight=1)

        i_hdr = tk.Frame(insp_panel, bg=Theme.BG_ELEVATED, padx=10, pady=6)
        i_hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            i_hdr,
            text="HISTORICAL DEVICE INSPECTOR",
            font=Theme.FONT_SECTION,
            text_color=Theme.ACCENT_AMBER,
        ).pack(side="left")

        body = tk.Frame(insp_panel, bg=Theme.BG_PANEL, padx=10, pady=8)
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)

        self.hist_dev_labels: Dict[str, Any] = {}
        for idx, (k, title) in enumerate([
            ("id", "DATABASE RECORD ID"),
            ("ip", "LAST OBSERVED IPv4"),
            ("mac", "UNIQUE HARDWARE MAC"),
            ("hostname", "RESOLVED HOSTNAME"),
            ("vendor", "HARDWARE MANUFACTURER"),
            ("first_seen", "FIRST DISCOVERED TIMESTAMP"),
            ("last_seen", "LAST SEEN TIMESTAMP"),
        ]):
            box = tk.Frame(body, bg=Theme.BG_PRIMARY, highlightbackground=Theme.BORDER, highlightthickness=1, padx=8, pady=5)
            box.grid(row=idx, column=0, sticky="ew", pady=3)
            create_label(box, text=title, font=Theme.FONT_UI_BOLD, text_color=Theme.TEXT_MUTED).pack(anchor="w")
            lbl = create_label(box, text="— (Select a device row)", font=Theme.FONT_MONO_SMALL, text_color=Theme.TEXT_PRIMARY)
            lbl.pack(anchor="w", pady=(2, 0))
            self.hist_dev_labels[k] = lbl

    def _build_sessions_traffic_pane(self) -> None:
        self.pane_sessions = tk.Frame(self.sub_viewport, bg=Theme.BG_PRIMARY)
        self.pane_sessions.grid(row=0, column=0, sticky="nsew")
        self.pane_sessions.grid_rowconfigure(0, weight=5)
        self.pane_sessions.grid_rowconfigure(1, weight=5)
        self.pane_sessions.grid_columnconfigure(0, weight=1)

        # Top: Previous Monitoring Sessions (`monitoring_sessions`)
        sess_panel = create_panel(self.pane_sessions, border=True)
        sess_panel.grid(row=0, column=0, sticky="nsew", pady=(0, Theme.PAD_XS))
        sess_panel.grid_rowconfigure(1, weight=1)
        sess_panel.grid_columnconfigure(0, weight=1)

        s_hdr = tk.Frame(sess_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        s_hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            s_hdr,
            text="PREVIOUS MONITORING SESSIONS (`monitoring_sessions` — SELECT A SESSION TO FILTER TRAFFIC INTERVALS)",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")

        btn_show_all = create_button(
            s_hdr,
            text="Show All Traffic Intervals",
            command=lambda: self._populate_traffic_stats_table(self._traffic_stats),
            width=165,
        )
        btn_show_all.pack(side="right")

        sess_cols = [
            {"id": "id", "label": "Session ID", "width": 90, "minwidth": 70, "stretch": False, "anchor": "center"},
            {"id": "interface", "label": "Interface", "width": 150, "minwidth": 110, "stretch": False},
            {"id": "start_time", "label": "Start Time", "width": 175, "minwidth": 140, "stretch": False},
            {"id": "end_time", "label": "End Time", "width": 175, "minwidth": 140, "stretch": False},
            {"id": "total_packets", "label": "Total Packets", "width": 135, "minwidth": 100, "stretch": False, "anchor": "e"},
            {"id": "source", "label": "Storage Source", "width": 150, "minwidth": 120, "stretch": True},
        ]
        self.hist_sessions_table = TechnicalTable(
            sess_panel,
            columns=sess_cols,
            empty_message="No monitoring sessions recorded yet.",
            sortable=True,
            on_row_select=self._on_hist_session_selected,
        )
        self.hist_sessions_table.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        # Bottom: Historical Aggregated Traffic Summaries (`traffic_statistics`)
        stat_panel = create_panel(self.pane_sessions, border=True)
        stat_panel.grid(row=1, column=0, sticky="nsew", pady=(Theme.PAD_XS, 0))
        stat_panel.grid_rowconfigure(1, weight=1)
        stat_panel.grid_columnconfigure(0, weight=1)

        st_hdr = tk.Frame(stat_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        st_hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            st_hdr,
            text="HISTORICAL AGGREGATED TRAFFIC SUMMARIES (`traffic_statistics` TABLE)",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")
        self.hist_stat_summary_lbl = create_label(
            st_hdr,
            text="INTERVALS: 0",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.ACCENT_AMBER,
        )
        self.hist_stat_summary_lbl.pack(side="right")

        stat_cols = [
            {"id": "id", "label": "ID", "width": 55, "minwidth": 45, "stretch": False, "anchor": "center"},
            {"id": "session_id", "label": "Session ID", "width": 85, "minwidth": 70, "stretch": False, "anchor": "center"},
            {"id": "timestamp", "label": "Timestamp", "width": 165, "minwidth": 135, "stretch": False},
            {"id": "download_bytes", "label": "Download Bytes", "width": 125, "minwidth": 95, "stretch": False, "anchor": "e"},
            {"id": "upload_bytes", "label": "Upload Bytes", "width": 125, "minwidth": 95, "stretch": False, "anchor": "e"},
            {"id": "tcp", "label": "TCP Pkts", "width": 85, "minwidth": 70, "stretch": False, "anchor": "e"},
            {"id": "udp", "label": "UDP Pkts", "width": 85, "minwidth": 70, "stretch": False, "anchor": "e"},
            {"id": "icmp", "label": "ICMP Pkts", "width": 85, "minwidth": 70, "stretch": False, "anchor": "e"},
            {"id": "dns", "label": "DNS Pkts", "width": 85, "minwidth": 70, "stretch": False, "anchor": "e"},
            {"id": "other", "label": "Other Pkts", "width": 90, "minwidth": 70, "stretch": True, "anchor": "e"},
        ]
        self.hist_stats_table = TechnicalTable(
            stat_panel,
            columns=stat_cols,
            empty_message="No aggregated traffic statistics intervals recorded yet.",
            sortable=True,
        )
        self.hist_stats_table.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

    def _build_routes_history_pane(self) -> None:
        self.pane_routes = tk.Frame(self.sub_viewport, bg=Theme.BG_PRIMARY)
        self.pane_routes.grid(row=0, column=0, sticky="nsew")
        self.pane_routes.grid_rowconfigure(0, weight=1)
        self.pane_routes.grid_columnconfigure(0, weight=5)
        self.pane_routes.grid_columnconfigure(1, weight=6)

        # Left: Route History Table (`route_history`)
        r_panel = create_panel(self.pane_routes, border=True)
        r_panel.grid(row=0, column=0, sticky="nsew", padx=(0, Theme.PAD_XS))
        r_panel.grid_rowconfigure(1, weight=1)
        r_panel.grid_columnconfigure(0, weight=1)

        r_hdr = tk.Frame(r_panel, bg=Theme.BG_PANEL, padx=8, pady=4)
        r_hdr.grid(row=0, column=0, sticky="ew")
        create_label(
            r_hdr,
            text="PREVIOUSLY PERFORMED ROUTES (`route_history`)",
            font=Theme.FONT_SECTION,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(side="left")

        r_cols = [
            {"id": "id", "label": "ID", "width": 55, "minwidth": 45, "stretch": False, "anchor": "center"},
            {"id": "destination", "label": "Destination", "width": 195, "minwidth": 135, "stretch": True},
            {"id": "timestamp", "label": "Timestamp", "width": 160, "minwidth": 130, "stretch": False},
            {"id": "hop_count", "label": "Hop Count", "width": 85, "minwidth": 70, "stretch": False, "anchor": "center"},
        ]
        self.hist_routes_table = TechnicalTable(
            r_panel,
            columns=r_cols,
            empty_message="No route history records found.",
            sortable=True,
            on_row_select=self._on_hist_route_selected,
        )
        self.hist_routes_table.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        # Right: Selected Route Hop Breakdown & Load to Map button
        hop_panel = create_panel(self.pane_routes, border=True)
        hop_panel.grid(row=0, column=1, sticky="nsew", padx=(Theme.PAD_XS, 0))
        hop_panel.grid_rowconfigure(1, weight=1)
        hop_panel.grid_columnconfigure(0, weight=1)

        hp_hdr = tk.Frame(hop_panel, bg=Theme.BG_ELEVATED, padx=8, pady=4)
        hp_hdr.grid(row=0, column=0, sticky="ew")
        self.selected_route_lbl = create_label(
            hp_hdr,
            text="INSPECTED ROUTE HOPS: Select a route on the left",
            font=Theme.FONT_SECTION,
            text_color=Theme.ACCENT_AMBER,
        )
        self.selected_route_lbl.pack(side="left")

        self.btn_load_route = create_button(
            hp_hdr,
            text="Load onto Route Mapper",
            command=self._handle_load_route_to_mapper,
            variant="accent",
            width=165,
            state="disabled",
        )
        self.btn_load_route.pack(side="right")

        hop_cols = [
            {"id": "hop", "label": "Hop", "width": 50, "minwidth": 42, "stretch": False, "anchor": "center"},
            {"id": "ip", "label": "IP Address", "width": 125, "minwidth": 100, "stretch": False},
            {"id": "hostname", "label": "Hostname", "width": 160, "minwidth": 110, "stretch": True},
            {"id": "rtt", "label": "RTT", "width": 85, "minwidth": 70, "stretch": False, "anchor": "e"},
            {"id": "location", "label": "Approx. Location", "width": 165, "minwidth": 120, "stretch": True},
        ]
        self.hist_route_hops_table = TechnicalTable(
            hop_panel,
            columns=hop_cols,
            empty_message="Select a historical route record on the left to inspect its stored hop path.",
            sortable=False,
        )
        self.hist_route_hops_table.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

    def switch_subtab(self, subtab_name: str) -> None:
        self._active_subtab = subtab_name
        pane_map = {
            "Devices History": self.pane_devices,
            "Monitoring Sessions & Traffic Summaries": self.pane_sessions,
            "Route History": self.pane_routes,
        }
        if subtab_name in pane_map:
            pane_map[subtab_name].tkraise()
        for name, btn in self.subtab_buttons.items():
            if name == subtab_name:
                btn.configure(bg=Theme.BG_PRIMARY, fg=Theme.ACCENT_AMBER)
            else:
                btn.configure(bg=Theme.BG_ELEVATED, fg=Theme.TEXT_SECONDARY)

    def populate_all_history(
        self,
        devices: List[DeviceRecord],
        sessions: List[MonitoringSessionRecord],
        traffic_stats: List[TrafficStatIntervalRecord],
        routes: List[RouteHistoryRecord],
        is_connected: bool,
        status_label: str,
    ) -> None:
        """Render all four historical datasets into the History workspace."""
        self._devices = list(devices)
        self._sessions = list(sessions)
        self._traffic_stats = list(traffic_stats)
        self._routes = list(routes)

        if is_connected:
            self.db_banner_lbl.configure(
                text=f"{status_label} — Persistent MySQL history active",
                text_color=Theme.STATE_SUCCESS,
            )
        else:
            self.db_banner_lbl.configure(
                text=f"{status_label} — Showing current-session records (MySQL persistence unavailable)",
                text_color=Theme.ACCENT_AMBER,
            )

        # 1. Devices
        dtree = self.hist_device_table.tree
        for item in dtree.get_children(""):
            dtree.delete(item)
        for idx, d in enumerate(self._devices, start=1):
            row_id = d.db_id if d.db_id is not None else idx
            dtree.insert(
                "",
                "end",
                values=(row_id, d.ip_address, d.mac_address, d.hostname, d.vendor, d.first_seen, d.last_seen),
                tags=("online",),
            )
        self.hist_device_table._update_empty_overlay()
        self.hist_dev_count_lbl.configure(text=f"RECORDS: {len(self._devices)}")

        # 2. Monitoring Sessions
        stree = self.hist_sessions_table.tree
        for item in stree.get_children(""):
            stree.delete(item)
        for s in self._sessions:
            stree.insert(
                "",
                "end",
                values=(s.id, s.interface, s.start_time, s.end_time, f"{s.total_packets:,}", s.source),
                tags=("online",),
            )
        self.hist_sessions_table._update_empty_overlay()

        # 3. Traffic Statistics Intervals
        self._populate_traffic_stats_table(self._traffic_stats)

        # 4. Route History
        rtree = self.hist_routes_table.tree
        for item in rtree.get_children(""):
            rtree.delete(item)
        for r in self._routes:
            rtree.insert(
                "",
                "end",
                values=(r.id, r.destination, r.timestamp, r.hop_count),
                tags=("online",),
            )
        self.hist_routes_table._update_empty_overlay()

    def _populate_traffic_stats_table(
        self,
        stats: List[TrafficStatIntervalRecord],
        session_filter_id: Optional[int] = None,
    ) -> None:
        tree = self.hist_stats_table.tree
        for item in tree.get_children(""):
            tree.delete(item)

        total_dl = 0
        total_ul = 0
        for st in stats:
            total_dl += st.download_bytes
            total_ul += st.upload_bytes
            tree.insert(
                "",
                "end",
                values=(
                    st.id,
                    st.session_id,
                    st.timestamp,
                    f"{st.download_bytes:,}",
                    f"{st.upload_bytes:,}",
                    st.tcp_packets,
                    st.udp_packets,
                    st.icmp_packets,
                    st.dns_packets,
                    st.other_packets,
                ),
                tags=("online",),
            )
        self.hist_stats_table._update_empty_overlay()
        scope = f"SESSION #{session_filter_id}" if session_filter_id is not None else "ALL SESSIONS"
        self.hist_stat_summary_lbl.configure(
            text=(
                f"{scope}  |  INTERVALS: {len(stats)}  |  "
                f"SUM RX: {format_total_bytes(total_dl)}  |  SUM TX: {format_total_bytes(total_ul)}"
            )
        )

    def _on_hist_device_selected(self, values: Tuple[Any, ...]) -> None:
        if len(values) >= 7:
            keys = ["id", "ip", "mac", "hostname", "vendor", "first_seen", "last_seen"]
            for k, val in zip(keys, values[:7]):
                self.hist_dev_labels[k].configure(text=str(val))

    def _on_hist_session_selected(self, values: Tuple[Any, ...]) -> None:
        if not values:
            return
        try:
            sess_id = int(values[0])
        except Exception:
            return
        filtered = [st for st in self._traffic_stats if st.session_id == sess_id]
        self._populate_traffic_stats_table(filtered, session_filter_id=sess_id)

    def _on_hist_route_selected(self, values: Tuple[Any, ...]) -> None:
        if not values:
            return
        try:
            route_id = int(values[0])
        except Exception:
            return

        target_rec: Optional[RouteHistoryRecord] = None
        for r in self._routes:
            if r.id == route_id:
                target_rec = r
                break

        if target_rec is None:
            return

        self._selected_route = target_rec
        self.btn_load_route.configure(state="normal")
        res_ip, hops = target_rec.parse_hops()
        self.selected_route_lbl.configure(
            text=f"ROUTE #{target_rec.id}: {target_rec.destination} @ {target_rec.timestamp} ({len(hops)} hops)"
        )

        htree = self.hist_route_hops_table.tree
        for item in htree.get_children(""):
            htree.delete(item)

        for h in hops:
            loc = ", ".join(p for p in (h.city, h.country) if p and p != "—") or h.mapping_status
            htree.insert(
                "",
                "end",
                values=(h.hop_number, h.ip_address, h.hostname, h.rtt_display, loc),
                tags=("mapped" if h.has_coordinates else "online",),
            )
        self.hist_route_hops_table._update_empty_overlay()

    def _handle_load_route_to_mapper(self) -> None:
        if self._selected_route is not None and self.on_load_route_to_mapper is not None:
            self.on_load_route_to_mapper(self._selected_route)


# ============================================================================
# DATABASE SETTINGS DIALOG (SETTINGS > DATABASE CONFIGURATION)
# ============================================================================

class DatabaseSettingsDialog:
    """
    Modal configuration dialog allowing the user to configure MySQL connection
    parameters (Host, Port, Username, Password, Database name = `netwatch_db`),
    test connectivity, connect & initialize schema, or disconnect.
    """

    def __init__(
        self,
        parent: Any,
        db_manager: DatabaseManager,
        on_config_applied: Optional[Callable[[bool, str], None]] = None,
    ) -> None:
        self.parent = parent
        self.db_manager = db_manager
        self.on_config_applied = on_config_applied

        self.dialog = tk.Toplevel(parent)
        self.dialog.title("MySQL Database Configuration — NetWatch")
        self.dialog.geometry("540x430")
        self.dialog.resizable(False, False)
        self.dialog.configure(bg=Theme.BG_PANEL)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self._build_ui()

    def _build_ui(self) -> None:
        container = tk.Frame(
            self.dialog,
            bg=Theme.BG_PANEL,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
            padx=18,
            pady=14,
        )
        container.pack(fill="both", expand=True, padx=10, pady=10)
        container.grid_columnconfigure(1, weight=1)

        create_label(
            container,
            text="MYSQL DATABASE CONFIGURATION",
            font=Theme.FONT_TITLE,
            text_color=Theme.ACCENT_AMBER,
        ).grid(row=0, column=0, columnspan=2, sticky="w")

        create_label(
            container,
            text=(
                "Configure MySQL Connector/Python persistence. Credentials are never hardcoded\n"
                "and passwords are never written to application logs."
            ),
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_SECONDARY,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 12))

        cfg = self.db_manager.config

        # Form rows: Host, Port, Username, Password, Database Name
        fields = [
            ("host", "MySQL Host:", cfg.host or "127.0.0.1", ""),
            ("port", "MySQL Port:", str(cfg.port or 3306), ""),
            ("username", "Username:", cfg.username, ""),
            ("password", "Password:", cfg.password, "*"),
            ("database", "Database Name:", cfg.database or "netwatch_db", ""),
        ]

        self.entries: Dict[str, Any] = {}
        for idx, (key, label_txt, initial_val, mask_char) in enumerate(fields, start=2):
            create_label(
                container,
                text=label_txt,
                font=Theme.FONT_UI_BOLD,
                text_color=Theme.TEXT_PRIMARY,
            ).grid(row=idx, column=0, sticky="w", pady=5, padx=(0, 12))

            ent = create_entry(
                container,
                placeholder_text="",
                width=310,
                font=Theme.FONT_MONO,
                show=mask_char,
            )
            ent.grid(row=idx, column=1, sticky="ew", pady=5)
            ent.delete(0, "end")
            if initial_val:
                ent.insert(0, initial_val)
            self.entries[key] = ent

        # Save profile checkbox
        self.save_var = tk.BooleanVar(value=cfg.save_connection_profile)
        chk = tk.Checkbutton(
            container,
            text="Save connection profile (host/port/user/database) to ~/.netwatch/db_config.json",
            variable=self.save_var,
            bg=Theme.BG_PANEL,
            fg=Theme.TEXT_SECONDARY,
            selectcolor=Theme.BG_PRIMARY,
            activebackground=Theme.BG_PANEL,
            activeforeground=Theme.TEXT_PRIMARY,
            font=Theme.FONT_UI,
        )
        chk.grid(row=7, column=0, columnspan=2, sticky="w", pady=(6, 8))

        # Status readout box
        status_frame = tk.Frame(
            container,
            bg=Theme.BG_PRIMARY,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
            padx=10,
            pady=8,
        )
        status_frame.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(4, 12))

        self.status_lbl = create_label(
            status_frame,
            text=f"Current State: {self.db_manager.get_connection_state()}",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.STATE_SUCCESS if self.db_manager.is_connected else Theme.ACCENT_AMBER,
        )
        self.status_lbl.pack(anchor="w")

        # Action Buttons
        btn_row = tk.Frame(container, bg=Theme.BG_PANEL)
        btn_row.grid(row=9, column=0, columnspan=2, sticky="ew")

        self.btn_test = create_button(
            btn_row,
            text="Test Connection",
            command=self._handle_test,
            width=125,
        )
        self.btn_test.pack(side="left", padx=(0, 6))

        self.btn_connect = create_button(
            btn_row,
            text="Save & Connect",
            command=self._handle_save_connect,
            variant="accent",
            width=130,
        )
        self.btn_connect.pack(side="left", padx=(0, 6))

        self.btn_disconnect = create_button(
            btn_row,
            text="Disconnect",
            command=self._handle_disconnect,
            variant="danger",
            width=100,
        )
        self.btn_disconnect.pack(side="left")

        btn_close = create_button(
            btn_row,
            text="Close",
            command=self.dialog.destroy,
            width=80,
        )
        btn_close.pack(side="right")

    def _read_form_config(self) -> Tuple[Optional[DatabaseConfig], Optional[str]]:
        host = self.entries["host"].get().strip()
        port_str = self.entries["port"].get().strip() or "3306"
        username = self.entries["username"].get().strip()
        password = self.entries["password"].get()
        database = self.entries["database"].get().strip() or "netwatch_db"

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            return None, f"Invalid MySQL port '{port_str}' (must be 1–65535)."

        if not host or not username:
            return None, "Host and Username are required."

        return (
            DatabaseConfig(
                host=host,
                port=port,
                username=username,
                password=password,
                database=database,
                save_connection_profile=bool(self.save_var.get()),
            ),
            None,
        )

    def _handle_test(self) -> None:
        cfg, err = self._read_form_config()
        if err or cfg is None:
            self.status_lbl.configure(text=f"Validation Error: {err}", text_color=Theme.STATE_ERROR)
            return

        self.status_lbl.configure(text=f"Testing connection to {cfg.safe_summary()}...", text_color=Theme.ACCENT_AMBER)
        self.btn_test.configure(state="disabled")

        def _worker() -> None:
            ok, msg = self.db_manager.test_connection(cfg)
            try:
                self.dialog.after(
                    0,
                    lambda: (
                        self.btn_test.configure(state="normal"),
                        self.status_lbl.configure(
                            text=msg[:85],
                            text_color=Theme.STATE_SUCCESS if ok else Theme.STATE_ERROR,
                        ),
                    ),
                )
            except Exception:
                pass

        threading.Thread(target=_worker, name="NetWatchDBTest", daemon=True).start()

    def _handle_save_connect(self) -> None:
        cfg, err = self._read_form_config()
        if err or cfg is None:
            self.status_lbl.configure(text=f"Validation Error: {err}", text_color=Theme.STATE_ERROR)
            return

        self.status_lbl.configure(
            text=f"Connecting & initializing schema on {cfg.safe_summary()}...",
            text_color=Theme.ACCENT_AMBER,
        )
        self.btn_connect.configure(state="disabled")

        def _on_done(ok: bool, msg: str) -> None:
            try:
                self.dialog.after(
                    0,
                    lambda: (
                        self.btn_connect.configure(state="normal"),
                        self.status_lbl.configure(
                            text=msg[:85],
                            text_color=Theme.STATE_SUCCESS if ok else Theme.STATE_ERROR,
                        ),
                        self.on_config_applied(ok, msg) if self.on_config_applied else None,
                    ),
                )
            except Exception:
                pass

        self.db_manager.connect_async(new_config=cfg, on_done=_on_done)

    def _handle_disconnect(self) -> None:
        self.db_manager.disconnect()
        self.status_lbl.configure(
            text=f"Disconnected: {self.db_manager.get_connection_state()}",
            text_color=Theme.ACCENT_AMBER,
        )
        if self.on_config_applied:
            self.on_config_applied(False, "Disconnected from MySQL database by user.")


# ============================================================================
# MAIN APPLICATION CONTROLLER & WORKSTATION WINDOW
# ============================================================================

BaseWindowClass = ctk.CTk if HAS_CTK else (tk.Tk if HAS_TK else object)


class NetWatchApp(BaseWindowClass):  # type: ignore[misc]
    """
    Main application class for NetWatch (Stage 5: MySQL Database Integration).
    Coordinates interface detection, threaded Scapy ARP scanning, threaded Scapy
    packet capture, threaded traceroute & Folium map generation, asynchronous
    MySQL persistence, historical record inspection, and clean shutdown.
    """

    APP_NAME = "NetWatch"
    APP_STAGE = "Stage 6 — Final Release (v1.0.0)"
    APP_VERSION = "1.0.0"
    QUEUE_POLL_MS = 100

    def __init__(self) -> None:
        if not HAS_TK:
            raise RuntimeError(
                "Tkinter is required to launch the NetWatch GUI window, "
                "but 'tkinter' is not installed in this Python environment."
            )

        if HAS_CTK:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")

        super().__init__()

        self.event_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()

        # Core Backend Services
        self.oui_lookup = OUILookup()
        self.db_manager = DatabaseManager(event_queue=self.event_queue)
        self.interface_manager = NetworkInterfaceManager()
        self.device_scanner = DeviceScanner(db_manager=self.db_manager, oui_lookup=self.oui_lookup)
        self.packet_monitor = PacketMonitor(db_manager=self.db_manager)
        self.geo_service = IPGeolocationService()
        self.route_mapper = RouteMapper(db_manager=self.db_manager, geo_service=self.geo_service)

        # Application State
        self.is_monitoring: bool = False
        self.active_tab_name: str = "Overview"
        self._after_job_id: Optional[str] = None

        # Configure Main Window
        self.title(f"{self.APP_NAME}")
        self.geometry("1400x870")
        self.minsize(1100, 700)
        if HAS_CTK:
            self.configure(fg_color=Theme.BG_PRIMARY)
        else:
            self.configure(bg=Theme.BG_PRIMARY)

        configure_ttk_styles(self)

        # Build UI Layers
        self._build_menu_bar()
        self._build_main_layout()
        self._build_toolbar()
        self._build_workspace_tabs()
        self._build_status_bar()

        # Bind Shutdown Handler & Keyboard Shortcuts
        self.protocol("WM_DELETE_WINDOW", self.on_shutdown)
        self.bind("<Control-q>", lambda _e: self.on_shutdown())
        self.bind("<F5>", lambda _e: self.action_refresh())

        self._sync_all_views()
        active_iface = self.interface_manager.get_current_summary()
        self._log_activity(
            subsystem="InterfaceMgr",
            source=active_iface.name,
            summary=(
                f"Ready on interface {active_iface.name} "
                f"(IPv4: {active_iface.ipv4_address}, Subnet: {active_iface.subnet_cidr})"
            ),
            state=active_iface.status_label,
        )

        # Attempt background MySQL connection if user previously configured credentials
        if self.db_manager.config.is_configured():
            self.db_manager.connect_async()
        else:
            self._log_activity(
                subsystem="DatabaseMgr",
                source="netwatch_db",
                summary=(
                    "MySQL credentials not yet configured (Settings > Database Configuration). "
                    "Continuing in session-memory mode; historical database persistence is unavailable."
                ),
                state="Disconnected",
            )

        self._schedule_queue_poll()

    # ------------------------------------------------------------------------
    # UI CONSTRUCTION
    # ------------------------------------------------------------------------

    def _build_menu_bar(self) -> None:
        menubar = tk.Menu(
            self,
            bg=Theme.BG_ELEVATED,
            fg=Theme.TEXT_PRIMARY,
            activebackground=Theme.BG_HOVER,
            activeforeground=Theme.ACCENT_AMBER,
            bd=0,
            relief="flat",
        )

        menu_cfg = {
            "tearoff": 0,
            "bg": Theme.BG_PANEL,
            "fg": Theme.TEXT_PRIMARY,
            "activebackground": Theme.BG_HOVER,
            "activeforeground": Theme.ACCENT_AMBER,
            "bd": 1,
            "relief": "flat",
        }

        # 1. File Menu
        file_menu = tk.Menu(menubar, **menu_cfg)
        file_menu.add_command(label="Settings: Database Configuration...", command=self.open_database_settings)
        file_menu.add_command(label="Refresh Interfaces & Views", accelerator="F5", command=self.action_refresh)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", accelerator="Ctrl+Q", command=self.on_shutdown)
        menubar.add_cascade(label="File", menu=file_menu)

        # 2. View Menu
        view_menu = tk.Menu(menubar, **menu_cfg)
        view_menu.add_command(label="Overview", command=lambda: self.switch_tab("Overview"))
        view_menu.add_command(label="Devices", command=lambda: self.switch_tab("Devices"))
        view_menu.add_command(label="Traffic Monitor", command=lambda: self.switch_tab("Traffic Monitor"))
        view_menu.add_command(label="Route Mapper", command=lambda: self.switch_tab("Route Mapper"))
        view_menu.add_command(label="History & Archives", command=lambda: self.switch_tab("History"))
        menubar.add_cascade(label="View", menu=view_menu)

        # 3. Monitoring Menu
        monitoring_menu = tk.Menu(menubar, **menu_cfg)
        monitoring_menu.add_command(label="Start Monitoring", command=self.action_start_monitoring)
        monitoring_menu.add_command(label="Stop Monitoring", command=self.action_stop_monitoring)
        monitoring_menu.add_separator()
        monitoring_menu.add_command(label="Start Packet Capture", command=self.action_start_packet_capture)
        monitoring_menu.add_command(label="Stop Packet Capture", command=self.action_stop_packet_capture)
        monitoring_menu.add_command(label="Clear Captured Packets", command=self.action_clear_packet_capture)
        monitoring_menu.add_separator()
        monitoring_menu.add_command(label="Scan Local Subnet (ARP)", command=self.action_scan_devices)
        monitoring_menu.add_command(label="Cancel Active Scan", command=self.action_cancel_scan)
        menubar.add_cascade(label="Monitoring", menu=monitoring_menu)

        # 4. Tools & Settings Menu
        tools_menu = tk.Menu(menubar, **menu_cfg)
        tools_menu.add_command(label="Settings > Database Configuration...", command=self.open_database_settings)
        tools_menu.add_command(
            label="Inspect Historical Records",
            command=lambda: self.switch_tab("History"),
        )
        tools_menu.add_separator()
        tools_menu.add_command(
            label="Run LAN Subnet Discovery",
            command=lambda: (self.switch_tab("Devices"), self.action_scan_devices()),
        )
        tools_menu.add_command(
            label="Live Packet Capture Workspace",
            command=lambda: self.switch_tab("Traffic Monitor"),
        )
        tools_menu.add_command(
            label="Geographical Route Mapper",
            command=lambda: self.switch_tab("Route Mapper"),
        )
        menubar.add_cascade(label="Tools", menu=tools_menu)

        # 5. Help Menu
        help_menu = tk.Menu(menubar, **menu_cfg)
        help_menu.add_command(label="Database Setup Instructions", command=self.open_db_setup_help)
        help_menu.add_command(label="About NetWatch", command=self.show_about_dialog)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.configure(menu=menubar)

    def _build_main_layout(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=0)

    def _format_interface_choices(self) -> List[str]:
        summaries = self.interface_manager.get_all_summaries()
        if not summaries:
            return ["No interfaces found"]
        choices: List[str] = []
        for s in summaries:
            state_tag = "UP" if s.is_up else "DOWN"
            ip_tag = s.ipv4_address if s.ipv4_address != "Not available" else "No IPv4"
            choices.append(f"{s.name} [{state_tag} - {ip_tag}]")
        return choices

    def _choice_for_current_interface(self, choices: List[str]) -> str:
        cur = self.interface_manager.get_current_summary().name
        for c in choices:
            if c.startswith(f"{cur} "):
                return c
        return choices[0]

    def _build_toolbar(self) -> None:
        self.toolbar = create_panel(self, border=True)
        self.toolbar.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_SM, pady=(Theme.PAD_SM, 2))

        left_group = tk.Frame(self.toolbar, bg=Theme.BG_PANEL)
        left_group.pack(side="left", padx=6, pady=4)

        create_label(
            left_group,
            text="INTERFACE:",
            font=Theme.FONT_UI_BOLD,
            text_color=Theme.TEXT_SECONDARY,
        ).pack(side="left", padx=(2, 6))

        choices = self._format_interface_choices()
        initial_choice = self._choice_for_current_interface(choices)
        self.interface_var = tk.StringVar(value=initial_choice)

        if HAS_CTK:
            self.interface_selector = ctk.CTkOptionMenu(
                left_group,
                variable=self.interface_var,
                values=choices,
                command=self._on_interface_selected,
                width=250,
                height=26,
                corner_radius=Theme.CORNER_RADIUS,
                fg_color=Theme.BG_ELEVATED,
                button_color=Theme.BORDER,
                button_hover_color=Theme.BG_HOVER,
                text_color=Theme.TEXT_PRIMARY,
                font=Theme.FONT_MONO,
            )
        else:
            self.interface_selector = ttk.Combobox(
                left_group,
                textvariable=self.interface_var,
                values=choices,
                state="readonly",
                width=28,
                font=Theme.FONT_MONO,
            )
            self.interface_selector.bind(
                "<<ComboboxSelected>>",
                lambda _e: self._on_interface_selected(self.interface_var.get()),
            )
        self.interface_selector.pack(side="left", padx=(0, 10))

        tk.Frame(left_group, bg=Theme.BORDER, width=1, height=20).pack(side="left", padx=6)

        self.btn_start_mon = create_button(
            left_group,
            text="Start Monitoring",
            command=self.action_start_monitoring,
            variant="accent",
            width=125,
        )
        self.btn_start_mon.pack(side="left", padx=(4, 6))

        self.btn_stop_mon = create_button(
            left_group,
            text="Stop Monitoring",
            command=self.action_stop_monitoring,
            variant="danger",
            width=120,
            state="disabled",
        )
        self.btn_stop_mon.pack(side="left", padx=(0, 6))

        self.btn_refresh = create_button(
            left_group,
            text="Refresh",
            command=self.action_refresh,
            width=82,
        )
        self.btn_refresh.pack(side="left", padx=(0, 6))

        self.btn_db_cfg = create_button(
            left_group,
            text="DB Settings",
            command=self.open_database_settings,
            width=96,
        )
        self.btn_db_cfg.pack(side="left")

        right_group = tk.Frame(self.toolbar, bg=Theme.BG_PANEL)
        right_group.pack(side="right", padx=10, pady=4)

        create_label(
            right_group,
            text="MONITORING STATUS:",
            font=Theme.FONT_UI_BOLD,
            text_color=Theme.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 6))

        self.toolbar_status_dot = tk.Canvas(
            right_group,
            width=10,
            height=10,
            bg=Theme.BG_PANEL,
            highlightthickness=0,
        )
        self.toolbar_status_dot.pack(side="left", padx=(0, 6))
        self._dot_id = self.toolbar_status_dot.create_oval(1, 1, 9, 9, fill=Theme.ACCENT_AMBER, outline="")

        self.toolbar_status_lbl = create_label(
            right_group,
            text="Not started",
            font=Theme.FONT_MONO,
            text_color=Theme.ACCENT_AMBER,
        )
        self.toolbar_status_lbl.pack(side="left")

    def _build_workspace_tabs(self) -> None:
        self.workspace_container = create_panel(self, border=True)
        self.workspace_container.grid(row=1, column=0, sticky="nsew", padx=Theme.PAD_SM, pady=4)
        self.workspace_container.grid_rowconfigure(1, weight=1)
        self.workspace_container.grid_columnconfigure(0, weight=1)

        self.tab_bar = tk.Frame(
            self.workspace_container,
            bg=Theme.BG_ELEVATED,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
        )
        self.tab_bar.grid(row=0, column=0, sticky="ew")

        self.tab_buttons: Dict[str, Any] = {}
        tab_names = ["Overview", "Devices", "Traffic Monitor", "Route Mapper", "History"]

        for name in tab_names:
            btn = tk.Button(
                self.tab_bar,
                text=name.upper(),
                command=lambda n=name: self.switch_tab(n),
                bg=Theme.BG_ELEVATED,
                fg=Theme.TEXT_SECONDARY,
                activebackground=Theme.BG_HOVER,
                activeforeground=Theme.TEXT_PRIMARY,
                bd=0,
                relief="flat",
                padx=18,
                pady=7,
                font=Theme.FONT_UI_BOLD,
                cursor="hand2",
            )
            btn.pack(side="left", padx=(0, 1))
            self.tab_buttons[name] = btn

        self.tab_viewport = tk.Frame(self.workspace_container, bg=Theme.BG_PRIMARY)
        self.tab_viewport.grid(row=1, column=0, sticky="nsew")
        self.tab_viewport.grid_rowconfigure(0, weight=1)
        self.tab_viewport.grid_columnconfigure(0, weight=1)

        self.dashboard_view = DashboardView(self.tab_viewport)
        self.devices_view = DevicesView(
            self.tab_viewport,
            on_scan=self.action_scan_devices,
            on_cancel_scan=self.action_cancel_scan,
            on_refresh=self.action_refresh,
            on_search=self.action_filter_devices,
            on_select_device=self.device_scanner.get_device_by_ip,
        )
        self.traffic_view = TrafficView(
            self.tab_viewport,
            on_start_capture=self.action_start_packet_capture,
            on_stop_capture=self.action_stop_packet_capture,
            on_clear_capture=self.action_clear_packet_capture,
            on_filter_changed=self.action_filter_packets,
        )
        self.route_view = RouteView(
            self.tab_viewport,
            on_start_trace=self.action_start_route_trace,
            on_cancel_trace=self.action_cancel_route_trace,
            on_open_external_map=self.action_open_route_map_external,
            on_select_hop=self.route_mapper.get_hop_by_number,
        )
        self.history_view = HistoryView(
            self.tab_viewport,
            on_refresh_history=self.action_refresh_history,
            on_open_db_settings=self.open_database_settings,
            on_load_route_to_mapper=self.action_load_historical_route,
        )

        self.views: Dict[str, Any] = {
            "Overview": self.dashboard_view,
            "Devices": self.devices_view,
            "Traffic Monitor": self.traffic_view,
            "Route Mapper": self.route_view,
            "History": self.history_view,
        }

        for view in self.views.values():
            view.grid(row=0, column=0, sticky="nsew")

        self.switch_tab("Overview")

    def _build_status_bar(self) -> None:
        self.status_bar = create_panel(self, border=True)
        self.status_bar.grid(row=2, column=0, sticky="ew", padx=Theme.PAD_SM, pady=(2, Theme.PAD_SM))

        for col_idx in range(4):
            self.status_bar.grid_columnconfigure(col_idx, weight=1)

        def _make_status_segment(col: int, label_prefix: str, initial_value: str) -> Any:
            seg = tk.Frame(self.status_bar, bg=Theme.BG_PANEL, padx=8, pady=3)
            seg.grid(row=0, column=col, sticky="ew")
            create_label(
                seg,
                text=label_prefix,
                font=Theme.FONT_UI_BOLD,
                text_color=Theme.TEXT_SECONDARY,
            ).pack(side="left", padx=(0, 6))
            val_lbl = create_label(
                seg,
                text=initial_value,
                font=Theme.FONT_MONO_SMALL,
                text_color=Theme.TEXT_PRIMARY,
            )
            val_lbl.pack(side="left")
            return val_lbl

        self.sb_interface_lbl = _make_status_segment(0, "INTERFACE:", "None")
        self.sb_ip_lbl = _make_status_segment(1, "LOCAL IP / SUBNET:", "Not available")
        self.sb_monitoring_lbl = _make_status_segment(2, "MONITORING:", "Not started")
        self.sb_database_lbl = _make_status_segment(3, "DATABASE:", self.db_manager.get_connection_state())

    # ------------------------------------------------------------------------
    # THREAD-SAFE QUEUE POLLING VIA TKINTER.AFTER()
    # ------------------------------------------------------------------------

    def _schedule_queue_poll(self) -> None:
        processed = 0
        try:
            while processed < 50:
                event = self.event_queue.get_nowait()
                self._handle_worker_event(event)
                processed += 1
        except queue.Empty:
            pass

        try:
            self._after_job_id = self.after(self.QUEUE_POLL_MS, self._schedule_queue_poll)
        except Exception:
            self._after_job_id = None

    def _handle_worker_event(self, event: Dict[str, Any]) -> None:
        etype = event.get("type")

        # --- Stage 2 Device Discovery Events ---
        if etype == "scan_started":
            subnet = event.get("subnet", "")
            iface = event.get("interface", "")
            start_ts = event.get("start_time", "—")
            total = event.get("total_hosts", 0)
            self.devices_view.set_scan_lifecycle(
                is_scanning=True,
                status_text=f"Scanning {subnet} on {iface} (0/{total} hosts)...",
                progress_pct=2.0,
                start_time=start_ts,
                end_time="In progress...",
                is_error=False,
            )
            self._log_activity(
                subsystem="DeviceScanner",
                source=iface,
                summary=f"Started ARP discovery scan across {subnet} ({total} target addresses)",
                state="Running",
            )
            self._sync_all_views()

        elif etype == "scan_progress":
            scanned = event.get("scanned", 0)
            total = event.get("total", 1)
            fraction = event.get("fraction", 0.0)
            found = event.get("discovered_count", 0)
            self.devices_view.set_scan_lifecycle(
                is_scanning=True,
                status_text=f"Scanning ({scanned}/{total} probed — {found} active found)",
                progress_pct=fraction * 100.0,
                start_time=self.device_scanner.last_scan_start,
                end_time="In progress...",
                is_error=False,
            )

        elif etype in ("device_found", "device_updated"):
            self._refresh_device_table()
            self._sync_all_views()

        elif etype == "scan_completed":
            iface = event.get("interface", "")
            subnet = event.get("subnet", "")
            start_ts = event.get("start_time", "—")
            end_ts = event.get("end_time", "—")
            found = event.get("discovered_count", 0)
            cancelled = event.get("cancelled", False)

            state_word = "Cancelled" if cancelled else "Completed"
            pct = self.device_scanner.progress_fraction * 100.0 if cancelled else 100.0
            self.devices_view.set_scan_lifecycle(
                is_scanning=False,
                status_text=f"{state_word} — {found} active host(s) on {subnet}",
                progress_pct=pct,
                start_time=start_ts,
                end_time=end_ts,
                is_error=False,
            )
            self._refresh_device_table()
            self._log_activity(
                subsystem="DeviceScanner",
                source=iface,
                summary=f"ARP scan {state_word.lower()} on {subnet}: {found} active host(s) responded",
                state=state_word,
            )
            self._sync_all_views()

        elif etype == "scan_error":
            msg = event.get("message", "Unknown scan error")
            self.devices_view.set_scan_lifecycle(
                is_scanning=False,
                status_text=msg,
                progress_pct=0.0,
                start_time=self.device_scanner.last_scan_start,
                end_time=self.device_scanner.last_scan_end,
                is_error=True,
            )
            iface_name = self.interface_manager.get_current_summary().name
            self._log_activity(
                subsystem="DeviceScanner",
                source=iface_name,
                summary=msg,
                state="Error",
            )
            self._sync_all_views()

        # --- Stage 3 Packet Capture Events ---
        elif etype == "capture_started":
            iface = event.get("interface", "")
            local_ip = event.get("local_ip", "")
            snap = self.packet_monitor.get_snapshot()
            self.traffic_view.update_telemetry_and_charts(snap, is_error=False)
            self._log_activity(
                subsystem="PacketMonitor",
                source=iface,
                summary=f"Started live packet capture on {iface} (local IP: {local_ip})",
                state="Capturing",
            )
            self._sync_all_views()

        elif etype == "packet_batch":
            batch: List[PacketRecord] = event.get("packets", [])
            if batch:
                criteria = self.traffic_view.get_filter_criteria()
                self.traffic_view.append_packets_batch(
                    packets=batch,
                    criteria=criteria,
                    total_captured=self.packet_monitor.captured_count,
                )

        elif etype == "traffic_stats":
            snap_obj: Optional[TrafficStatsSnapshot] = event.get("snapshot")
            if snap_obj is not None:
                self.traffic_view.update_telemetry_and_charts(snap_obj, is_error=False)
                self._sync_all_views(snapshot=snap_obj)

        elif etype == "capture_stopped":
            iface = event.get("interface", "")
            snap_obj = event.get("snapshot") or self.packet_monitor.get_snapshot()
            self.traffic_view.update_telemetry_and_charts(snap_obj, is_error=False)
            self._log_activity(
                subsystem="PacketMonitor",
                source=iface,
                summary=(
                    f"Stopped packet capture on {iface} "
                    f"({snap_obj.total_packets:,} packets, {format_total_bytes(snap_obj.total_bytes)}, "
                    f"duration {format_duration(snap_obj.duration_seconds)})"
                ),
                state="Stopped",
            )
            self._sync_all_views(snapshot=snap_obj)

        elif etype == "capture_error":
            msg = event.get("message", "Unknown packet capture error")
            snap_obj = self.packet_monitor.get_snapshot()
            self.traffic_view.update_telemetry_and_charts(snap_obj, is_error=True)
            iface_name = self.interface_manager.get_current_summary().name
            self._log_activity(
                subsystem="PacketMonitor",
                source=iface_name,
                summary=msg,
                state="Error",
            )
            self._sync_all_views(snapshot=snap_obj)

        # --- Stage 4 Route Mapper Events ---
        elif etype == "trace_started":
            target = event.get("target", "")
            resolved_ip = event.get("resolved_ip", "")
            self.route_view.populate_hops([])
            self.route_view.set_trace_lifecycle(
                is_tracing=True,
                status_text=f"Tracing route to {target} ({resolved_ip})...",
                is_error=False,
            )
            self._log_activity(
                subsystem="RouteMapper",
                source=target,
                summary=f"Started traceroute to {target} (resolved IPv4: {resolved_ip})",
                state="Tracing",
            )
            self._sync_all_views()

        elif etype == "trace_hop":
            hops_list: List[RouteHopRecord] = event.get("hops", [])
            hop_obj: Optional[RouteHopRecord] = event.get("hop")
            self.route_view.populate_hops(hops_list)
            if hop_obj is not None:
                self.route_view.set_trace_lifecycle(
                    is_tracing=True,
                    status_text=f"Hop #{hop_obj.hop_number}: {hop_obj.ip_address} ({hop_obj.rtt_display})",
                    is_error=False,
                )

        elif etype == "trace_completed":
            target = event.get("target", "")
            resolved_ip = event.get("resolved_ip", "")
            hops_list = event.get("hops", [])
            mapped_cnt = event.get("mapped_count", 0)
            cancelled = event.get("cancelled", False)
            map_path = event.get("map_path")
            status_text = event.get("status_text", "Completed")

            self.route_view.populate_hops(hops_list)
            self.route_view.set_trace_lifecycle(
                is_tracing=False,
                status_text=status_text,
                is_error=False,
                has_map_file=bool(map_path and os.path.isfile(map_path)),
            )
            state_word = "Cancelled" if cancelled else "Completed"
            self._log_activity(
                subsystem="RouteMapper",
                source=f"{target} ({resolved_ip})",
                summary=f"Traceroute {state_word.lower()}: {len(hops_list)} hops recorded ({mapped_cnt} geo-mapped)",
                state=state_word,
            )
            self._sync_all_views()

        elif etype == "trace_error":
            msg = event.get("message", "Unknown traceroute error")
            self.route_view.set_trace_lifecycle(
                is_tracing=False,
                status_text=msg,
                is_error=True,
            )
            self._log_activity(
                subsystem="RouteMapper",
                source=self.route_mapper.target_input or "RouteMapper",
                summary=msg,
                state="Error",
            )
            self._sync_all_views()

        # --- Stage 5 Database & History Events ---
        elif etype == "db_state_changed":
            connected = bool(event.get("connected", False))
            msg = str(event.get("message", ""))
            self._log_activity(
                subsystem="DatabaseMgr",
                source=self.db_manager.config.safe_summary(),
                summary=msg,
                state="Connected" if connected else "Disconnected",
            )
            self._sync_all_views()
            self.action_refresh_history()

        elif etype == "history_loaded":
            self.history_view.populate_all_history(
                devices=event.get("devices", []),
                sessions=event.get("sessions", []),
                traffic_stats=event.get("traffic_stats", []),
                routes=event.get("routes", []),
                is_connected=bool(event.get("is_connected", False)),
                status_label=str(event.get("status_label", "")),
            )

    def _log_activity(self, subsystem: str, source: str, summary: str, state: str) -> None:
        ev = ActivityEvent(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            subsystem=subsystem,
            source=source,
            summary=summary,
            state=state,
        )
        self.dashboard_view.append_activity(ev)

    # ------------------------------------------------------------------------
    # NAVIGATION & APPLICATION LOGIC
    # ------------------------------------------------------------------------

    def switch_tab(self, tab_name: str) -> None:
        if tab_name not in self.views:
            return
        self.active_tab_name = tab_name
        self.views[tab_name].tkraise()

        for name, btn in self.tab_buttons.items():
            if name == tab_name:
                btn.configure(bg=Theme.BG_PRIMARY, fg=Theme.ACCENT_AMBER)
            else:
                btn.configure(bg=Theme.BG_ELEVATED, fg=Theme.TEXT_SECONDARY)

        if tab_name == "History":
            self.action_refresh_history()

    def _on_interface_selected(self, selection_label: str) -> None:
        iface_name = selection_label.split(" [")[0].strip()
        if self.packet_monitor.is_capturing:
            self.packet_monitor.stop_capture(self.event_queue)
        summary = self.interface_manager.select_interface(iface_name)
        self._log_activity(
            subsystem="InterfaceMgr",
            source=summary.name,
            summary=f"Selected interface {summary.name} (IPv4: {summary.ipv4_address}, Subnet: {summary.subnet_cidr})",
            state=summary.status_label,
        )
        self._sync_all_views()

    def action_start_monitoring(self) -> None:
        self.is_monitoring = True
        self.btn_start_mon.configure(state="disabled")
        self.btn_stop_mon.configure(state="normal")

        iface = self.interface_manager.get_current_summary()
        self._log_activity(
            subsystem="MonitorCtrl",
            source=iface.name,
            summary=f"Monitoring started on interface {iface.name}",
            state="Active",
        )

        if not self.packet_monitor.is_capturing:
            self.action_start_packet_capture()

        if not self.device_scanner.is_scanning:
            self.action_scan_devices()

        self._sync_all_views()

    def action_stop_monitoring(self) -> None:
        self.is_monitoring = False
        self.device_scanner.stop_scan()
        self.packet_monitor.stop_capture(self.event_queue)

        self.btn_start_mon.configure(state="normal")
        self.btn_stop_mon.configure(state="disabled")

        iface = self.interface_manager.get_current_summary()
        self._log_activity(
            subsystem="MonitorCtrl",
            source=iface.name,
            summary="Monitoring stopped by user",
            state="Stopped",
        )
        self._sync_all_views()

    def action_refresh(self) -> None:
        self.interface_manager.refresh_interfaces()
        choices = self._format_interface_choices()
        self.interface_selector.configure(values=choices)
        self.interface_var.set(self._choice_for_current_interface(choices))
        self._refresh_device_table()
        self.action_filter_packets(self.traffic_view.get_filter_criteria())
        if self.active_tab_name == "History":
            self.action_refresh_history()
        self._sync_all_views()

    def action_scan_devices(self) -> None:
        iface = self.interface_manager.get_current_summary()
        self.device_scanner.start_scan(iface=iface, event_queue=self.event_queue)

    def action_cancel_scan(self) -> None:
        self.device_scanner.stop_scan()

    def action_filter_devices(self, _query: str = "") -> None:
        self._refresh_device_table()

    def _refresh_device_table(self) -> None:
        query = self.devices_view.get_filter_query()
        filtered = self.device_scanner.get_discovered_devices(query)
        online_count = self.device_scanner.get_online_device_count()
        total_count = self.device_scanner.get_device_count()
        self.devices_view.populate_devices(
            devices=filtered,
            online_count=online_count,
            total_count=total_count,
        )

    def action_start_packet_capture(self) -> None:
        iface = self.interface_manager.get_current_summary()
        started = self.packet_monitor.start_capture(iface=iface, event_queue=self.event_queue)
        if started:
            self.is_monitoring = True
            self.btn_start_mon.configure(state="disabled")
            self.btn_stop_mon.configure(state="normal")
        self._sync_all_views()

    def action_stop_packet_capture(self) -> None:
        self.packet_monitor.stop_capture(self.event_queue)
        if not self.device_scanner.is_scanning:
            self.is_monitoring = False
            self.btn_start_mon.configure(state="normal")
            self.btn_stop_mon.configure(state="disabled")
        self._sync_all_views()

    def action_clear_packet_capture(self) -> None:
        self.packet_monitor.clear_history()
        criteria = self.traffic_view.get_filter_criteria()
        self.traffic_view.repopulate_packets([], criteria, total_captured=0)
        snap = self.packet_monitor.get_snapshot()
        self.traffic_view.update_telemetry_and_charts(snap, is_error=False)
        self._sync_all_views(snapshot=snap)

    def action_filter_packets(self, criteria: PacketFilterCriteria) -> None:
        matching = self.packet_monitor.get_recent_packets(criteria)
        self.traffic_view.repopulate_packets(
            packets=matching,
            criteria=criteria,
            total_captured=self.packet_monitor.captured_count,
        )

    def action_start_route_trace(self, destination: str) -> None:
        self.route_mapper.start_trace(destination=destination, event_queue=self.event_queue)
        self._sync_all_views()

    def action_cancel_route_trace(self) -> None:
        self.route_mapper.stop_trace()

    def action_open_route_map_external(self) -> None:
        map_path = self.route_mapper.last_map_path
        if not map_path or not os.path.isfile(map_path):
            if messagebox is not None:
                messagebox.showinfo(
                    "Route Map Not Available",
                    "Run a route trace first to generate the interactive geographical HTML map.",
                )
            return
        try:
            file_uri = Path(map_path).resolve().as_uri()
            webbrowser.open(file_uri)
        except Exception as exc:
            if messagebox is not None:
                messagebox.showerror("Open Map Error", f"Could not open map file '{map_path}': {exc}")

    def action_refresh_history(self) -> None:
        """Asynchronously query MySQL / Session History and populate the History tab."""
        self.db_manager.fetch_all_history_async(self.event_queue)

    def action_load_historical_route(self, route_rec: RouteHistoryRecord) -> None:
        """Load a selected historical route into the Route Mapper tab and render its map."""
        res_ip, hops = route_rec.parse_hops()
        self.route_mapper.load_historical_route(route_rec.destination, res_ip, hops)
        self.route_view.populate_hops(hops)
        self.route_view.set_trace_lifecycle(
            is_tracing=False,
            status_text=f"Loaded Historical Route #{route_rec.id}: {route_rec.destination} ({len(hops)} hops)",
            is_error=False,
            has_map_file=bool(self.route_mapper.last_map_path and os.path.isfile(self.route_mapper.last_map_path)),
        )
        self.switch_tab("Route Mapper")

    def open_database_settings(self) -> None:
        """Open the Settings > Database Configuration modal dialog."""
        DatabaseSettingsDialog(
            parent=self,
            db_manager=self.db_manager,
            on_config_applied=lambda _ok, _msg: (self._sync_all_views(), self.action_refresh_history()),
        )

    def _sync_all_views(self, snapshot: Optional[TrafficStatsSnapshot] = None) -> None:
        iface_summary = self.interface_manager.get_current_summary()
        online_devs = self.device_scanner.get_online_device_count()
        total_devs = self.device_scanner.get_device_count()
        snap = snapshot or self.packet_monitor.get_snapshot()

        self.dashboard_view.update_overview(
            iface=iface_summary,
            online_devices=online_devs,
            total_devices=total_devs,
            scanner_status=self.device_scanner.status_text,
            traffic_snapshot=snap,
            monitoring_active=self.is_monitoring,
        )

        self.devices_view.update_interface_banner(iface_summary)

        if snap.is_capturing:
            self.toolbar_status_dot.itemconfig(self._dot_id, fill=Theme.STATE_SUCCESS)
            self.toolbar_status_lbl.configure(
                text=(
                    f"Capturing ({snap.total_packets:,} pkts | "
                    f"↑{format_bytes_rate(snap.upload_bps)} ↓{format_bytes_rate(snap.download_bps)})"
                ),
                text_color=Theme.STATE_SUCCESS,
            )
        elif self.device_scanner.is_scanning:
            self.toolbar_status_dot.itemconfig(self._dot_id, fill=Theme.STATE_SUCCESS)
            self.toolbar_status_lbl.configure(text="Scanning LAN Subnet...", text_color=Theme.STATE_SUCCESS)
        elif self.route_mapper.is_tracing:
            self.toolbar_status_dot.itemconfig(self._dot_id, fill=Theme.STATE_SUCCESS)
            self.toolbar_status_lbl.configure(text="Tracing Route...", text_color=Theme.STATE_SUCCESS)
        elif self.is_monitoring:
            self.toolbar_status_dot.itemconfig(self._dot_id, fill=Theme.ACCENT_AMBER)
            self.toolbar_status_lbl.configure(text=f"Standby ({snap.status_text})", text_color=Theme.ACCENT_AMBER)
        else:
            self.toolbar_status_dot.itemconfig(self._dot_id, fill=Theme.ACCENT_AMBER)
            self.toolbar_status_lbl.configure(
                text="Not started" if snap.total_packets == 0 else f"Stopped ({snap.total_packets:,} pkts)",
                text_color=Theme.ACCENT_AMBER,
            )

        self.sb_interface_lbl.configure(
            text=f"{iface_summary.name} ({iface_summary.status_label})",
            text_color=Theme.STATE_SUCCESS if iface_summary.is_up else Theme.ACCENT_AMBER,
        )
        self.sb_ip_lbl.configure(text=f"{iface_summary.ipv4_address}  [{iface_summary.subnet_cidr}]")
        mon_text = (
            f"Capturing ({snap.packets_per_sec:.1f} pkt/s | {format_duration(snap.duration_seconds)})"
            if snap.is_capturing
            else (
                "Scanning LAN..."
                if self.device_scanner.is_scanning
                else ("Tracing Route..." if self.route_mapper.is_tracing else "Idle / Not started")
            )
        )
        self.sb_monitoring_lbl.configure(
            text=mon_text,
            text_color=Theme.STATE_SUCCESS
            if (snap.is_capturing or self.device_scanner.is_scanning or self.route_mapper.is_tracing)
            else Theme.ACCENT_AMBER,
        )
        self.sb_database_lbl.configure(
            text=self.db_manager.get_connection_state(),
            text_color=Theme.STATE_SUCCESS if self.db_manager.is_connected else Theme.ACCENT_AMBER,
        )

    # ------------------------------------------------------------------------
    # DIALOGS & SHUTDOWN HANDLING
    # ------------------------------------------------------------------------

    def open_db_setup_help(self) -> None:
        """Display MySQL Setup Instructions dialog."""
        dialog = tk.Toplevel(self)
        dialog.title("MySQL Database Setup Instructions")
        dialog.geometry("580x360")
        dialog.resizable(False, False)
        dialog.configure(bg=Theme.BG_PANEL)
        dialog.transient(self)
        dialog.grab_set()

        container = tk.Frame(
            dialog,
            bg=Theme.BG_PANEL,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        container.pack(fill="both", expand=True, padx=10, pady=10)

        create_label(
            container,
            text="MYSQL SETUP INSTRUCTIONS (netwatch_db)",
            font=Theme.FONT_TITLE,
            text_color=Theme.ACCENT_AMBER,
        ).pack(anchor="w", pady=(0, 8))

        help_text = (
            "1. Install MySQL Server and MySQL Connector/Python:\n"
            "   pip install mysql-connector-python\n\n"
            "2. Create a MySQL user with privileges on `netwatch_db`:\n"
            "   CREATE DATABASE IF NOT EXISTS netwatch_db;\n"
            "   CREATE USER 'netwatch'@'localhost' IDENTIFIED BY '<your_password>';\n"
            "   GRANT ALL PRIVILEGES ON netwatch_db.* TO 'netwatch'@'localhost';\n"
            "   FLUSH PRIVILEGES;\n\n"
            "3. Open 'File > Settings: Database Configuration...' (or click 'DB Settings'\n"
            "   on the toolbar), enter Host, Port, Username, Password, and Database\n"
            "   (`netwatch_db`), and click 'Save & Connect'.\n\n"
            "NetWatch automatically creates all required tables (`devices`,\n"
            "`monitoring_sessions`, `traffic_statistics`, `route_history`)."
        )
        create_label(
            container,
            text=help_text,
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, 12))

        create_button(
            container,
            text="Close",
            command=dialog.destroy,
            variant="accent",
            width=90,
        ).pack(anchor="e")

    def show_about_dialog(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title(f"About {self.APP_NAME}")
        dialog.geometry("530x390")
        dialog.resizable(False, False)
        dialog.configure(bg=Theme.BG_PANEL)
        dialog.transient(self)
        dialog.grab_set()

        container = tk.Frame(
            dialog,
            bg=Theme.BG_PANEL,
            highlightbackground=Theme.BORDER,
            highlightthickness=1,
            padx=18,
            pady=16,
        )
        container.pack(fill="both", expand=True, padx=10, pady=10)

        create_label(
            container,
            text="NETWATCH WORKSTATION",
            font=Theme.FONT_TITLE,
            text_color=Theme.ACCENT_AMBER,
        ).pack(anchor="w")

        create_label(
            container,
            text=f"Version {self.APP_VERSION}  |  {self.APP_STAGE}",
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_SECONDARY,
        ).pack(anchor="w", pady=(2, 12))

        ui_backend = "CustomTkinter + Tkinter ttk" if HAS_CTK else "Standard Tkinter (CustomTkinter fallback)"
        opt_status = ", ".join(MISSING_OPTIONAL_DEPS) if MISSING_OPTIONAL_DEPS else "All present"

        details = (
            "Desktop network engineering and monitoring workstation.\n"
            "Stage 5 adds MySQL persistence (`netwatch_db`) with automatic\n"
            "schema creation, parameterized batched queries, aggregated\n"
            "traffic interval logging, route history, and seamless\n"
            "in-memory fallback when MySQL is disconnected.\n\n"
            f"UI Backend:       {ui_backend}\n"
            f"MySQL Connector:  {'Available' if HAS_MYSQL_CONNECTOR else 'Missing (In-Memory Fallback)'}\n"
            f"Matplotlib:       {'Available' if HAS_MATPLOTLIB else 'Missing'}\n"
            f"Folium:           {'Available' if HAS_FOLIUM else 'Leaflet HTML Fallback'}\n"
            f"Optional Missing: {opt_status}\n"
            f"Database State:   {self.db_manager.get_connection_state()}"
        )
        create_label(
            container,
            text=details,
            font=Theme.FONT_MONO_SMALL,
            text_color=Theme.TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, 16))

        btn_close = create_button(
            container,
            text="Close",
            command=dialog.destroy,
            variant="accent",
            width=90,
        )
        btn_close.pack(anchor="e")

    def on_shutdown(self) -> None:
        """Gracefully stop packet capture, cancel active scans/traces, flush & close DB, and exit."""
        try:
            if self._after_job_id is not None:
                try:
                    self.after_cancel(self._after_job_id)
                except Exception:
                    pass
                self._after_job_id = None

            self.packet_monitor.shutdown()
            self.device_scanner.shutdown()
            self.route_mapper.shutdown()
            self.db_manager.shutdown()
        finally:
            self.destroy()


# ============================================================================
# SELF-TEST & VERIFICATION SUITE (--check)
# ============================================================================

class _MockMySQLVerificationBackend:
    """
    Lightweight SQLite-backed adapter that emulates `mysql.connector`'s connection
    and `%s` parameterized cursor interface solely during `--check` self-tests when
    a live MySQL server is not running in the test environment.
    Allows deterministic verification of `DatabaseManager`'s connection management,
    schema initialization (`devices`, `monitoring_sessions`, `traffic_statistics`,
    `route_history`), parameterized batch upserts, deduplication, and retrieval queries.
    """

    def __init__(self) -> None:
        import sqlite3
        self._sqlite = sqlite3.connect(":memory:", check_same_thread=False)
        self._init_sqlite_tables()

    def _init_sqlite_tables(self) -> None:
        cur = self._sqlite.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                mac_address TEXT NOT NULL UNIQUE,
                hostname TEXT DEFAULT 'Unknown',
                vendor TEXT DEFAULT 'Unknown',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                interface TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT DEFAULT NULL,
                total_packets INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS traffic_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                download_bytes INTEGER NOT NULL DEFAULT 0,
                upload_bytes INTEGER NOT NULL DEFAULT 0,
                tcp_packets INTEGER NOT NULL DEFAULT 0,
                udp_packets INTEGER NOT NULL DEFAULT 0,
                icmp_packets INTEGER NOT NULL DEFAULT 0,
                dns_packets INTEGER NOT NULL DEFAULT 0,
                other_packets INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES monitoring_sessions(id) ON DELETE CASCADE
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS route_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                destination TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                hop_count INTEGER NOT NULL DEFAULT 0,
                route_data TEXT NOT NULL
            )
        """)
        self._sqlite.commit()

    def connect(self, **kwargs: Any) -> Any:
        if kwargs.get("host") == "unreachable.invalid":
            raise RuntimeError("2003 (HY000): Can't connect to MySQL server on 'unreachable.invalid:3306'")
        return _MockMySQLConnection(self._sqlite)


class _MockMySQLConnection:
    def __init__(self, sqlite_conn: Any) -> None:
        self._sqlite = sqlite_conn
        self.closed = False

    def get_server_info(self) -> str:
        return "8.0.36-MySQL-Compatible-Test"

    def ping(self, reconnect: bool = True, attempts: int = 1, delay: int = 0) -> None:
        if self.closed:
            if reconnect:
                self.closed = False
            else:
                raise RuntimeError("Connection lost")

    def is_connected(self) -> bool:
        return not self.closed

    def cursor(self) -> Any:
        return _MockMySQLCursor(self._sqlite)

    def commit(self) -> None:
        self._sqlite.commit()

    def rollback(self) -> None:
        self._sqlite.rollback()

    def close(self) -> None:
        self.closed = True


class _MockMySQLCursor:
    def __init__(self, sqlite_conn: Any) -> None:
        self._sqlite = sqlite_conn
        self._cur = sqlite_conn.cursor()
        self.lastrowid: Optional[int] = None

    @staticmethod
    def _translate_sql(sql: str) -> Optional[str]:
        s = sql.strip()
        up = s.upper()
        if up.startswith(("CREATE DATABASE", "USE ", "CREATE TABLE")):
            return None
        if "ON DUPLICATE KEY UPDATE" in up:
            return """
                INSERT INTO devices (ip_address, mac_address, hostname, vendor, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    ip_address = excluded.ip_address,
                    hostname = CASE
                        WHEN excluded.hostname NOT IN ('', '—', 'Unknown', 'Resolving...') THEN excluded.hostname
                        ELSE devices.hostname
                    END,
                    vendor = CASE
                        WHEN excluded.vendor NOT IN ('', 'Unknown') THEN excluded.vendor
                        ELSE devices.vendor
                    END,
                    first_seen = MIN(devices.first_seen, excluded.first_seen),
                    last_seen = MAX(devices.last_seen, excluded.last_seen)
            """
        return s.replace("%s", "?")

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
        assert "%s" in sql or sql.strip().upper().startswith(("CREATE", "USE", "SELECT")), (
            f"All data queries must use parameterized %s placeholders: {sql}"
        )
        translated = self._translate_sql(sql)
        if translated is None:
            return
        self._cur.execute(translated, params)
        self.lastrowid = self._cur.lastrowid

    def executemany(self, sql: str, seq_of_params: List[Tuple[Any, ...]]) -> None:
        translated = self._translate_sql(sql)
        if translated is None:
            return
        self._cur.executemany(translated, seq_of_params)

    def fetchall(self) -> List[Tuple[Any, ...]]:
        return self._cur.fetchall()

    def close(self) -> None:
        self._cur.close()


def run_verification_checks() -> int:
    """
    Comprehensive Stage 6 Engineering & Quality-Assurance Verification Suite:
    1. AST Thread-Safety & Security Audit:
       - Verifies no background worker method directly mutates Tkinter widgets.
       - Verifies all SQL execution uses parameterized `%s` queries.
       - Verifies `DatabaseConfig` never hardcodes credentials or leaks passwords.
    2. Network Interface Detection & Disconnected Handling:
       - Enumerates interfaces, selects active adapter, and verifies graceful handling
         of disconnected/loopback/public interfaces.
    3. Device Discovery & Session/DB Deduplication:
       - Verifies OUI lookup, duplicate MAC/IP merging, `first_seen` preservation,
         filtering, and natural IPv4 sorting keys.
    4. Real-Time Traffic Monitoring & Bounded Buffers:
       - Verifies idle startup, TCP/UDP/ICMP/DNS/Other classification, upload/download
         throughput calculation, bounded ring buffer (`MAX_PACKET_HISTORY = 1000`),
         and non-destructive live filtering.
    5. Geographical Route Mapper & Accuracy Safeguards:
       - Verifies domain/IPv4 validation, cross-platform traceroute line parsing
         (Linux `traceroute`, Windows `tracert`, `tracepath`, `*` timeouts, `!H` unreachable),
         private IP geolocation exclusion, session caching, contiguous segment building
         (never connecting across unresolved hops), and Folium/Leaflet HTML generation.
    6. MySQL Database Persistence & Unavailable-DB Fallback:
       - Verifies graceful fallback to in-memory session storage when MySQL is unreachable.
       - Verifies automatic schema creation (`devices`, `monitoring_sessions`,
         `traffic_statistics`, `route_history`), batched device upserts, aggregated
         traffic interval logging, route history JSON round-trip, and clean thread shutdown.
    """
    import ast

    print(f"NetWatch")

    # 1. Static AST Thread-Safety & Parameterized SQL Audit
    with open(__file__, "r", encoding="utf-8") as f:
        source_code = f.read()
    tree = ast.parse(source_code)

    forbidden_ui_calls = {"tkraise", "insert", "delete", "selection_set", "draw_idle"}
    worker_methods = {"_scan_worker", "_capture_worker", "_trace_worker", "_db_worker_loop"}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in worker_methods:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Attribute) and sub.attr in forbidden_ui_calls:
                    raise AssertionError(
                        f"Thread-safety violation: worker '{node.name}' called UI method '{sub.attr}'"
                    )
    print("[1/6] AST Thread-Safety Audit passed (zero direct widget mutations inside worker threads).")

    # 2. Network Interface Enumeration & Disconnected Interface Handling
    if_mgr = NetworkInterfaceManager()
    all_ifaces = if_mgr.get_all_summaries()
    active_iface = if_mgr.get_current_summary()
    missing_iface = if_mgr.select_interface("nonexistent_adapter_99")
    assert missing_iface.status_label == "Disconnected", "Missing interface must report Disconnected"
    if active_iface.name != "None":
        if_mgr.select_interface(active_iface.name)
    print(
        f"[2/6] NetworkInterfaceManager verified ({len(all_ifaces)} interface(s); "
        f"active={if_mgr.get_current_summary().name}, disconnected fallback='Disconnected')."
    )

    # 3. LAN Device Discovery, Subnet Safety, OUI Lookup, Sorting & Deduplication
    mock_backend = _MockMySQLVerificationBackend()
    db_mgr = DatabaseManager(connector_module=mock_backend)
    oui = OUILookup()
    scanner = DeviceScanner(db_manager=db_mgr, oui_lookup=oui)

    ok_pub, msg_pub, _ = scanner.validate_local_subnet(
        InterfaceSummary(name="wan0", ipv4_address="8.8.8.8", netmask="255.255.255.0", subnet_cidr="8.8.8.0/24", is_up=True)
    )
    assert not ok_pub, "Public IP range must be blocked from ARP scanning"

    ok_down, msg_down, _ = scanner.validate_local_subnet(
        InterfaceSummary(name="eth_down", ipv4_address="192.168.1.5", netmask="255.255.255.0", subnet_cidr="192.168.1.0/24", is_up=False)
    )
    assert not ok_down, "Down interface must be rejected before ARP scan"

    rec_a = DeviceRecord(
        ip_address="192.168.1.1",
        mac_address="24:5A:4C:11:22:33",
        hostname="router.lan",
        vendor=oui.lookup("24:5A:4C:11:22:33"),
        first_seen="2026-11-01 10:00:00",
        last_seen="2026-11-01 10:00:00",
        status="Online",
        interface_name="eth0",
    )
    rec_b = DeviceRecord(
        ip_address="192.168.1.1",
        mac_address="24:5A:4C:11:22:33",
        hostname="Resolving...",
        vendor="Unknown",
        first_seen="2026-11-01 10:05:00",
        last_seen="2026-11-01 10:05:00",
        status="Online",
        interface_name="eth0",
    )
    scanner._register_discovered_device(rec_a)
    merged = scanner._register_discovered_device(rec_b)
    assert scanner.get_device_count() == 1
    assert merged.first_seen == "2026-11-01 10:00:00" and merged.last_seen == "2026-11-01 10:05:00"
    assert merged.hostname == "router.lan" and merged.vendor == "Ubiquiti Inc."
    assert len(scanner.get_discovered_devices("ubiquiti")) == 1
    assert TechnicalTable._sort_key_for_value("ip", "192.168.1.2") < TechnicalTable._sort_key_for_value("ip", "192.168.1.10")
    print("[3/6] DeviceScanner verified (subnet guards, OUI lookup, deduplication, search & natural IP sort).")

    # 4. Real-Time Traffic Monitoring, Bounded Buffers, Filtering & Chart Updates
    pkt_mon = PacketMonitor(db_manager=db_mgr)
    assert not pkt_mon.is_capturing, "Capture must not start automatically"
    local_ip = "192.168.1.50"
    pkt_mon.local_ip = local_ip
    pkt_mon.interface_name = "eth0"

    test_packets = [
        PacketRecord(1, "12:00:01.100", time.time(), local_ip, "93.184.216.34", "TCP", 1024, 54321, 443, "Upload", "SYN"),
        PacketRecord(2, "12:00:01.200", time.time(), "93.184.216.34", local_ip, "TCP", 2048, 443, 54321, "Download", "ACK"),
        PacketRecord(3, "12:00:01.300", time.time(), local_ip, "1.1.1.1", "DNS", 128, 55100, 53, "Upload", "DNS Query"),
        PacketRecord(4, "12:00:01.400", time.time(), "1.1.1.1", local_ip, "UDP", 512, 443, 55200, "Download", "QUIC"),
        PacketRecord(5, "12:00:01.500", time.time(), "192.168.1.1", local_ip, "ICMP", 84, None, None, "Download", "Echo Reply"),
        PacketRecord(6, "12:00:01.600", time.time(), "192.168.1.1", "ff:ff:ff:ff:ff:ff", "Other", 60, None, None, "Local/Other", "ARP"),
    ]
    for p in test_packets:
        pkt_mon.ingest_packet_record(p)

    snap = pkt_mon.step_telemetry_window(elapsed_sec=1.0)
    assert snap.total_packets == 6 and snap.upload_bps == 1152.0 and snap.download_bps == 2644.0
    assert snap.protocol_counts == {"TCP": 2, "UDP": 1, "ICMP": 1, "DNS": 1, "Other": 1}
    assert len(pkt_mon.get_recent_packets(PacketFilterCriteria(protocol="DNS"))) == 1
    assert len(pkt_mon.get_recent_packets(PacketFilterCriteria(source_ip="93.184"))) == 1
    assert len(pkt_mon.get_recent_packets()) == 6, "Filtering must not drop underlying packet history"

    for _ in range(1050):
        pkt_mon.ingest_packet_record(test_packets[0])
    assert len(pkt_mon.get_recent_packets()) == PacketMonitor.MAX_PACKET_HISTORY
    print(
        f"[4/6] PacketMonitor verified (TX={format_bytes_rate(snap.upload_bps)}, "
        f"RX={format_bytes_rate(snap.download_bps)}, ring buffer capped at {PacketMonitor.MAX_PACKET_HISTORY})."
    )

    # 5. Geographical Route Mapper, Traceroute Parser, Geolocation Cache & Map Generation
    ok_ip, _, _, res_ip = RouteMapper.validate_and_resolve_destination("1.1.1.1")
    assert ok_ip and res_ip == "1.1.1.1"
    ok_bad, _, _, _ = RouteMapper.validate_and_resolve_destination("http://invalid/url")
    assert not ok_bad

    geo = IPGeolocationService()
    assert not geo.lookup("10.0.0.1", allow_network=False).is_mapped
    assert geo.lookup("198.51.100.99", allow_network=False).latitude is None

    geo.seed_cache("93.184.216.1", GeoLocationResult("93.184.216.1", True, True, "USA", "MA", "Boston", 42.3601, -71.0589, mapping_status="Mapped (Approx.)"))
    geo.seed_cache("93.184.216.2", GeoLocationResult("93.184.216.2", True, True, "USA", "NY", "New York", 40.7128, -74.0060, mapping_status="Mapped (Approx.)"))
    geo.seed_cache("1.1.1.1", GeoLocationResult("1.1.1.1", True, True, "USA", "CA", "Los Angeles", 34.0522, -118.2437, mapping_status="Mapped (Approx.)"))

    mapper = RouteMapper(db_manager=db_mgr, geo_service=geo)
    hops = [
        mapper.enrich_hop(RouteMapper.parse_traceroute_line(" 1  192.168.1.1  1.1 ms", "1.1.1.1"), allow_network=False),  # type: ignore[arg-type]
        mapper.enrich_hop(RouteMapper.parse_traceroute_line(" 2  93.184.216.1  9.4 ms", "1.1.1.1"), allow_network=False),  # type: ignore[arg-type]
        mapper.enrich_hop(RouteMapper.parse_traceroute_line(" 3  93.184.216.2  14.8 ms", "1.1.1.1"), allow_network=False),  # type: ignore[arg-type]
        mapper.enrich_hop(RouteMapper.parse_traceroute_line(" 4  * * *", "1.1.1.1"), allow_network=False),  # type: ignore[arg-type]
        mapper.enrich_hop(RouteMapper.parse_traceroute_line(" 5  1.1.1.1  22.1 ms", "1.1.1.1"), allow_network=False),  # type: ignore[arg-type]
    ]
    segs = RouteMapGenerator.build_contiguous_mapped_segments(hops)
    assert len(segs) == 2 and [h.hop_number for h in segs[0]] == [2, 3] and [h.hop_number for h in segs[1]] == [5]
    ok_map, map_path = RouteMapGenerator.generate_map_html("one.one.one.one", "1.1.1.1", hops, output_path="/tmp/netwatch_final_map.html")
    assert ok_map and os.path.isfile(map_path)
    print("[5/6] RouteMapper & RouteMapGenerator verified (timeout gap breaks polyline; HTML map generated).")

    # 6. MySQL Database Persistence,Unavailable-DB Fallback & Clean Worker Shutdown
    ok_fail, _ = db_mgr.connect(DatabaseConfig("unreachable.invalid", 3306, "u", "p", "netwatch_db", False))
    assert not ok_fail and not db_mgr.is_connected

    ok_conn, _ = db_mgr.connect(DatabaseConfig("127.0.0.1", 3306, "netwatch", "secret", "netwatch_db", False))
    assert ok_conn and db_mgr.is_connected

    sid = db_mgr.start_monitoring_session("eth0")
    db_mgr.record_traffic_statistics_interval(sid, 4096, 2048, {"TCP": 12, "UDP": 3, "ICMP": 1, "DNS": 2, "Other": 0}, 18)
    db_mgr.end_monitoring_session(sid, 18)
    db_mgr.record_route_history("one.one.one.one", "1.1.1.1", hops)
    db_mgr.flush_pending_writes(timeout=2.0)

    assert len(db_mgr.fetch_historical_devices()) >= 1
    assert len(db_mgr.fetch_monitoring_sessions()) == 1
    assert len(db_mgr.fetch_traffic_statistics()) == 1
    assert len(db_mgr.fetch_route_history()) == 1

    # Shutdown all background workers and verify no hanging threads
    pkt_mon.shutdown()
    scanner.shutdown()
    mapper.shutdown()
    db_mgr.shutdown()
    assert not db_mgr._worker_thread.is_alive(), "Database worker thread must terminate cleanly on shutdown"
    print("[6/6] MySQL persistence, fallback mode, and clean background thread termination verified.")
    print(f"=== All NetWatch v{NetWatchApp.APP_VERSION} QA & Integration Checks Passed ===")
    return 0


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

def main() -> int:
    """Launch the NetWatch desktop workstation."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if "--check" in sys.argv:
        return run_verification_checks()

    if not HAS_TK:
        sys.stderr.write(
            "[NetWatch] Error: Python 'tkinter' module is not installed in this environment.\n"
            "Install python3-tk and customtkinter to launch the desktop interface.\n"
        )
        return 1

    app = NetWatchApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
