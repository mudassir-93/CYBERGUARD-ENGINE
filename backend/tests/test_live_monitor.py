import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from live_monitor import DetectionWindowEngine


class LiveDetectionWindowTests(unittest.TestCase):
    def test_port_scan_requires_distinct_tcp_syn_ports_and_cooldown(self):
        engine = DetectionWindowEngine(port_scan_threshold=3)
        events = []
        for port in (22, 80, 443):
            events.extend(engine.process({
                "source_ip": "192.168.1.10", "destination_ip": "192.168.1.20",
                "protocol": "TCP", "destination_port": port, "tcp_syn": True,
                "packet_bytes": 60,
            }, now=port))
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


if __name__ == "__main__":
    unittest.main()
