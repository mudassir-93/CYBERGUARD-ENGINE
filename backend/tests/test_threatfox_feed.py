import json
import sys
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from threatfox_feed import ThreatFoxError, ThreatFoxFeed, API_URL


class FakeResponse(BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class ThreatFoxFeedTests(unittest.TestCase):
    def test_requires_key_and_validates_days(self):
        with self.assertRaises(ThreatFoxError):
            ThreatFoxFeed(api_key="")
        feed = ThreatFoxFeed(api_key="test-key")
        for days in (0, 8, True, "3"):
            with self.assertRaises(ValueError):
                feed.fetch(days)

    @patch("threatfox_feed.urlopen")
    def test_fetch_normalizes_public_ip_and_domain_and_skips_unsupported(self, mocked):
        payload = {
            "query_status": "ok",
            "data": [
                {"ioc_type": "ip", "ioc": "8.8.8.8", "confidence_level": 95,
                 "threat_type_desc": "C2", "first_seen": "2026-11-20 12:00:00 UTC",
                 "tags": ["botnet"]},
                {"ioc_type": "domain", "ioc": "MALWARE.Example", "confidence_level": 85,
                 "malware_printable": "Example malware", "tags": ["test"]},
                {"ioc_type": "url", "ioc": "https://bad.example/path"},
                {"ioc_type": "ip", "ioc": "192.168.1.1", "confidence_level": 99},
                {"ioc_type": "domain", "ioc": "not a domain"},
            ],
        }
        mocked.return_value = FakeResponse(json.dumps(payload).encode())
        result = ThreatFoxFeed(api_key="secret").fetch(days=2)
        self.assertEqual((result["received"], result["accepted"], result["skipped"]), (5, 2, 3))
        self.assertEqual(result["indicators"][0]["value"], "8.8.8.8")
        self.assertEqual(result["indicators"][0]["severity"], "critical")
        self.assertEqual(result["indicators"][1]["value"], "malware.example")
        request, timeout = mocked.call_args.args
        self.assertEqual(request.full_url, API_URL)
        self.assertEqual(request.get_header("Auth-key"), "secret")
        self.assertEqual(json.loads(request.data), {"query": "get_iocs", "days": 2})
        self.assertEqual(timeout, 20)

    @patch("threatfox_feed.urlopen")
    def test_no_result_is_a_successful_empty_sync(self, mocked):
        mocked.return_value = FakeResponse(b'{"query_status":"no_result"}')
        self.assertEqual(
            ThreatFoxFeed(api_key="secret").fetch(),
            {"indicators": [], "received": 0, "accepted": 0, "skipped": 0},
        )

    @patch("threatfox_feed.urlopen")
    def test_rejects_invalid_and_oversized_responses(self, mocked):
        feed = ThreatFoxFeed(api_key="secret")
        mocked.return_value = FakeResponse(b"not-json")
        with self.assertRaises(ThreatFoxError):
            feed.fetch()
        mocked.return_value = FakeResponse(b"x" * (5 * 1024 * 1024 + 1))
        with self.assertRaises(ThreatFoxError):
            feed.fetch()


if __name__ == "__main__":
    unittest.main()
