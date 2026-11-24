"""Optional passive IPv4 packet capture and explainable rolling-window detections.

Scapy is imported lazily so the simulator and incident workspace work without
packet-capture dependencies or elevated privileges.
"""
from __future__ import annotations

import ipaddress
import importlib.util
import threading
import time
from collections import defaultdict, deque
from typing import Any

from incidents import IncidentStore


_RFC1918 = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _is_private(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return address.version == 4 and any(address in network for network in _RFC1918)
    except ValueError:
        return False


def packet_observation(packet: Any) -> dict[str, Any] | None:
    """Convert a Scapy packet into a small, payload-free IPv4 observation."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except ImportError as error:
        raise RuntimeError("Live capture requires Scapy. Install it with: pip install -r requirements-live.txt") from error
    if not packet.haslayer(IP):
        return None
    ip = packet[IP]
    protocol, port, syn = "OTHER", None, False
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        protocol, port = "TCP", int(tcp.dport)
        syn = bool(int(tcp.flags) & 0x02) and not bool(int(tcp.flags) & 0x10)
        if not 1 <= port <= 65535:
            port = None
    elif packet.haslayer(UDP):
        protocol, port = "UDP", int(packet[UDP].dport)
        if not 1 <= port <= 65535:
            port = None
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    return {
        "source_ip": str(ip.src), "destination_ip": str(ip.dst),
        "protocol": protocol, "destination_port": port,
        "tcp_syn": syn, "packet_bytes": int(len(packet)),
    }


class DetectionWindowEngine:
    """Conservative packet-metadata heuristics; never claims to detect login failures."""

    def __init__(self, port_scan_threshold: int = 10, dos_threshold: int = 100,
                 lateral_threshold: int = 3, scan_window: float = 60,
                 dos_window: float = 10, lateral_window: float = 60):
        self.port_scan_threshold = port_scan_threshold
        self.dos_threshold = dos_threshold
        self.lateral_threshold = lateral_threshold
        self.scan_window = scan_window
        self.dos_window = dos_window
        self.lateral_window = lateral_window
        self._scans: dict[tuple[str, str], deque] = defaultdict(deque)
        self._dos: dict[tuple[str, str], deque] = defaultdict(deque)
        self._lateral: dict[str, deque] = defaultdict(deque)
        self._emitted: dict[tuple[str, str, str], float] = {}
        self._event_count = 0

    @staticmethod
    def _bound(mapping: dict, now: float, limit: int = 4096) -> None:
        if len(mapping) > limit:
            oldest = min(mapping, key=lambda key: mapping[key][-1][0] if mapping[key] else now)
            del mapping[oldest]

    def _cooldown(self, key: tuple[str, str, str], now: float, window: float) -> bool:
        previous = self._emitted.get(key)
        if previous is not None and now - previous < window:
            return False
        self._emitted[key] = now
        return True

    def process(self, event: dict[str, Any], now: float | None = None) -> list[dict[str, Any]]:
        now = time.monotonic() if now is None else now
        self._event_count += 1
        if self._event_count % 256 == 0:
            cutoff = now - (2 * max(self.scan_window, self.dos_window, self.lateral_window))
            self._emitted = {key: seen for key, seen in self._emitted.items() if seen >= cutoff}
            if len(self._emitted) > 8192:
                while len(self._emitted) > 8192:
                    self._emitted.pop(min(self._emitted, key=self._emitted.get), None)
        src, dst = event["source_ip"], event["destination_ip"]
        protocol, port = event["protocol"], event.get("destination_port")
        size = max(1, int(event.get("packet_bytes", 1)))
        detections = []

        if protocol == "TCP" and event.get("tcp_syn") and isinstance(port, int) and 1 <= port <= 65535:
            key = (src, dst)
            samples = self._scans[key]
            samples.append((now, port))
            while len(samples) > 2048:
                samples.popleft()
            self._bound(self._scans, now)
            while samples and now - samples[0][0] > self.scan_window:
                samples.popleft()
            ports = sorted({item[1] for item in samples})
            cooldown = ("port_scan", src, dst)
            if len(ports) >= self.port_scan_threshold and self._cooldown(cooldown, now, self.scan_window):
                detections.append({
                    "type": "port_scan", "source_ip": src, "destination_ip": dst,
                    "protocol": "TCP", "summary": "TCP SYN traffic reached multiple destination ports",
                    "evidence": {"distinct_ports": len(ports), "ports": ports,
                                 "threshold": self.port_scan_threshold, "window_seconds": self.scan_window,
                                 "source": "live_packet_capture"},
                })

        key = (src, dst)
        samples = self._dos[key]
        samples.append((now, size))
        while len(samples) > 2048:
            samples.popleft()
        self._bound(self._dos, now)
        while samples and now - samples[0][0] > self.dos_window:
            samples.popleft()
        if len(samples) >= self.dos_threshold and self._cooldown(("dos", src, dst), now, self.dos_window):
            detections.append({
                "type": "dos", "source_ip": src, "destination_ip": dst,
                "protocol": protocol, "destination_port": port,
                "summary": "High packet rate observed from one source to one destination",
                "evidence": {"packet_count": len(samples), "total_bytes": sum(item[1] for item in samples),
                             "threshold": self.dos_threshold, "window_seconds": self.dos_window,
                             "source": "live_packet_capture"},
            })

        if _is_private(src) and _is_private(dst) and src != dst:
            samples = self._lateral[src]
            samples.append((now, dst))
            while len(samples) > 2048:
                samples.popleft()
            self._bound(self._lateral, now)
            while samples and now - samples[0][0] > self.lateral_window:
                samples.popleft()
            destinations = sorted({item[1] for item in samples})
            if len(destinations) >= self.lateral_threshold and self._cooldown(
                ("lateral_movement", src, "private-network"), now, self.lateral_window
            ):
                detections.append({
                    "type": "lateral_movement", "source_ip": src,
                    "destination_ip": dst, "protocol": protocol, "destination_port": port,
                    "summary": "Internal host contacted multiple private network destinations",
                    "evidence": {"distinct_internal_destinations": len(destinations),
                                 "destinations": destinations[:100],
                                 "destinations_truncated": len(destinations) > 100,
                                 "threshold": self.lateral_threshold,
                                 "window_seconds": self.lateral_window, "source": "live_packet_capture"},
                })
        return detections


def list_capture_interfaces() -> list[dict[str, str]]:
    try:
        from scapy.all import conf
    except ImportError as error:
        raise RuntimeError("Live capture is optional. Install it with: pip install -r requirements-live.txt") from error
    result = []
    for interface in conf.ifaces.values():
        name = str(getattr(interface, "name", "") or "")
        if name:
            result.append({"name": name, "description": str(getattr(interface, "description", "") or name)})
    return sorted(result, key=lambda item: (item["description"].lower(), item["name"]))


class LiveTrafficMonitor:
    """Owns one optional Scapy sniffer and forwards metadata detections to SQLite."""

    def __init__(self, store: IncidentStore):
        self.store = store
        self._lock = threading.RLock()
        self._sniffer = None
        self._interface = None
        self._engine = DetectionWindowEngine()
        self._packets_seen = 0
        self._detections = 0
        self._ingest_errors = 0
        self._last_error = None
        self._started_at = None

    def status(self) -> dict[str, Any]:
        with self._lock:
            running = bool(self._sniffer is not None and getattr(self._sniffer, "running", False))
            sniffer_error = getattr(self._sniffer, "exception", None) if self._sniffer is not None else None
            if sniffer_error is not None and self._last_error is None:
                self._last_error = str(sniffer_error)[:500]
            return {"available": importlib.util.find_spec("scapy") is not None,
                    "running": running, "interface": self._interface,
                    "packets_seen": self._packets_seen, "detections_created": self._detections,
                    "ingest_errors": self._ingest_errors, "last_error": self._last_error,
                    "started_at": self._started_at}

    def start(self, interface: str) -> dict[str, Any]:
        if not isinstance(interface, str) or not interface.strip() or len(interface) > 512:
            raise ValueError("Select a valid network interface")
        try:
            from scapy.all import AsyncSniffer
            available = {item["name"] for item in list_capture_interfaces()}
        except (ImportError, RuntimeError) as error:
            raise RuntimeError(str(error)) from error
        if interface not in available:
            raise ValueError("Selected network interface is not available")
        with self._lock:
            if self._sniffer is not None and getattr(self._sniffer, "running", False):
                raise RuntimeError("Live monitoring is already running")
            self._engine = DetectionWindowEngine()
            self._packets_seen = self._detections = self._ingest_errors = 0
            self._last_error = None
            self._interface = interface
            self._started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._sniffer = AsyncSniffer(iface=interface, filter="ip", prn=self._on_packet, store=False)
            try:
                self._sniffer.start()
            except Exception as error:
                self._last_error = str(error)
                self._sniffer = None
                raise RuntimeError(
                    "Packet capture could not start. Check Npcap on Windows or capture permissions on Linux. "
                    + str(error)
                ) from error
            return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            sniffer = self._sniffer
            if sniffer is None:
                return self.status()
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop()
        except Exception as error:
            with self._lock:
                self._last_error = str(error)
        return self.status()

    def _on_packet(self, packet: Any) -> None:
        try:
            observation = packet_observation(packet)
            if observation is None:
                return
            with self._lock:
                self._packets_seen += 1
                detections = self._engine.process(observation)
            for detection in detections:
                self.store.ingest(detection)
                with self._lock:
                    self._detections += 1
        except Exception as error:
            with self._lock:
                self._ingest_errors += 1
                self._last_error = str(error)[:500]
