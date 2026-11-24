import sys
import unittest
import tempfile
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from live_monitor import DetectionWindowEngine, LiveTrafficMonitor, packet_observation
from incidents import IncidentStore


class LiveDetectionWindowTests(unittest.TestCase):
    def test_port_scan_requires_distinct_tcp_syn_ports_and_cooldown(self):
        engine = DetectionWindowEngine(port_scan_threshold=3)
        events = []
        for timestamp, port in enumerate((22, 80, 443)):
            events.extend(engine.process({
                "source_ip": "192.168.1.10", "destination_ip": "192.168.1.20",
                "protocol": "TCP", "destination_port": port, "tcp_syn": True,
                "packet_bytes": 60,
            }, now=timestamp))
        self.assertEqual([item["type"] for item in events], ["port_scan"])
        self.assertEqual(events[0]["evidence"]["distinct_ports"], 3)

    def test_repeated_same_port_does_not_become_port_scan(self):
        engine = DetectionWindowEngine(port_scan_threshold=3)
        results = [engine.process({
            "source_ip": "192.168.1.10", "destination_ip": "192.168.1.20",
            "protocol": "TCP", "destination_port": 443, "tcp_syn": True,
            "packet_bytes": 60,
        }, now=t) for t in range(5)]
        self.assertFalse(any(item["type"] == "port_scan" for batch in results for item in batch))

    def test_dos_rate_window_and_threshold(self):
        engine = DetectionWindowEngine(dos_threshold=4)
        results = []
        for t in range(4):
            results.extend(engine.process({
                "source_ip": "8.8.8.8", "destination_ip": "1.1.1.1",
                "protocol": "UDP", "destination_port": 53, "packet_bytes": 100,
            }, now=t))
        dos = [item for item in results if item["type"] == "dos"]
        self.assertEqual(len(dos), 1)
        self.assertEqual(dos[0]["evidence"]["packet_count"], 4)

    def test_internal_fanout_requires_private_destinations(self):
        engine = DetectionWindowEngine(lateral_threshold=3, dos_threshold=999)
        results = []
        for t, destination in enumerate(("10.0.0.2", "10.0.0.3", "10.0.0.4")):
            results.extend(engine.process({
                "source_ip": "10.0.0.20", "destination_ip": destination,
                "protocol": "TCP", "destination_port": 445, "tcp_syn": True,
                "packet_bytes": 70,
            }, now=t))
        self.assertEqual([item["type"] for item in results], ["lateral_movement"])

    def test_window_expiry_prevents_stale_scan(self):
        engine = DetectionWindowEngine(port_scan_threshold=3, scan_window=5, dos_threshold=999)
        for t, port in enumerate((22, 80)):
            engine.process({"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                            "protocol": "TCP", "destination_port": port, "tcp_syn": True,
                            "packet_bytes": 60}, now=t)
        result = engine.process({"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                                 "protocol": "TCP", "destination_port": 443, "tcp_syn": True,
                                 "packet_bytes": 60}, now=10)
        self.assertFalse(any(item["type"] == "port_scan" for item in result))



class LivePacketAdapterTests(unittest.TestCase):
    def test_tcp_syn_packet_is_normalized_without_payload(self):
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(dport=443, flags="S") / Raw(load=b"secret-payload")
        result = packet_observation(packet)
        self.assertEqual(result["protocol"], "TCP")
        self.assertEqual(result["destination_port"], 443)
        self.assertTrue(result["tcp_syn"])
        self.assertNotIn("payload", result)
        self.assertNotIn("secret-payload", str(result))

    def test_tcp_syn_ack_is_not_classified_as_scan_syn(self):
        from scapy.layers.inet import IP, TCP
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(dport=443, flags="SA")
        self.assertFalse(packet_observation(packet)["tcp_syn"])

    def test_udp_and_icmp_are_normalized(self):
        from scapy.layers.inet import IP, UDP, ICMP
        udp = packet_observation(IP(src="8.8.8.8", dst="1.1.1.1") / UDP(dport=53))
        icmp = packet_observation(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())
        self.assertEqual((udp["protocol"], udp["destination_port"]), ("UDP", 53))
        self.assertEqual((icmp["protocol"], icmp["destination_port"]), ("ICMP", None))

    def test_non_ipv4_packet_is_ignored(self):
        from scapy.layers.l2 import Ether
        self.assertIsNone(packet_observation(Ether()))

    def test_capture_lifecycle_and_detection_persist_to_sqlite(self):
        from scapy.layers.inet import IP, TCP

        class FakeSniffer:
            instance = None
            def __init__(self, **kwargs):
                self.callback = kwargs["prn"]
                self.running = False
                self.exception = None
                FakeSniffer.instance = self
            def start(self):
                self.running = True
            def stop(self):
                self.running = False

        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "live.sqlite3")
            monitor = LiveTrafficMonitor(store)
            with patch("scapy.all.AsyncSniffer", FakeSniffer), patch(
                "live_monitor.list_capture_interfaces", return_value=[{"name": "test0", "description": "Test"}]
            ):
                started = monitor.start("test0")
                self.assertTrue(started["running"])
                for destination in ("10.0.0.2", "10.0.0.3", "10.0.0.4"):
                    FakeSniffer.instance.callback(
                        IP(src="10.0.0.20", dst=destination) / TCP(dport=445, flags="S")
                    )
                stopped = monitor.stop()
            self.assertFalse(stopped["running"])
            self.assertEqual(stopped["packets_seen"], 3)
            self.assertEqual(stopped["detections_created"], 1)
            incidents = store.list_incidents()
            self.assertEqual(len(incidents), 1)
            self.assertEqual(incidents[0]["type"], "lateral_movement")

    def test_invalid_interface_is_rejected_before_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor = LiveTrafficMonitor(IncidentStore(Path(directory) / "test.sqlite3"))
            with patch("live_monitor.list_capture_interfaces", return_value=[{"name": "valid0", "description": "Valid"}]):
                with patch("scapy.all.AsyncSniffer") as sniffer:
                    with self.assertRaises(ValueError):
                        monitor.start("invalid0")
                    sniffer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
