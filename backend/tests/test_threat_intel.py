import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from incidents import IncidentStore
from threat_intel import ThreatIntelStore,normalize_indicator
class ThreatIntelTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.path=Path(self.temp.name)/"db.sqlite3"; self.incidents=IncidentStore(self.path); self.intel=ThreatIntelStore(self.path)
 def tearDown(self): self.temp.cleanup()
 def test_indicator_validation_and_normalization(self):
  self.assertEqual(normalize_indicator({"type":"domain","value":"Example.COM."})["value"],"example.com")
  for item in ({"type":"ip","value":"999.1.1.1"},{"type":"domain","value":"not a domain"},{"type":"sha256","value":"abc"},{"type":"ip","value":"8.8.8.8","confidence":101}):
   with self.assertRaises(ValueError): normalize_indicator(item)
 def test_import_idempotency_and_update(self):
  item={"type":"ip","value":"203.0.113.9","source":"feed-a","confidence":70}; self.assertEqual(self.intel.import_indicators([item])["inserted"],1)
  result=self.intel.import_indicators([{**item,"confidence":95}]); self.assertEqual((result["inserted"],result["updated"]),(0,1)); self.assertEqual(self.intel.list_indicators()[0]["confidence"],95)
 def test_exact_ip_and_domain_matches(self):
  incident,_=self.incidents.ingest({"type":"port_scan","source_ip":"203.0.113.9","destination_ip":"10.0.0.2","evidence":{"hostname":"malicious.example"}})
  self.intel.import_indicators([{"type":"ip","value":"203.0.113.9","source":"feed-a"},{"type":"domain","value":"malicious.example","source":"feed-b"}])
  self.assertEqual({(x["type"],x["value"]) for x in self.intel.match_incident(incident)},{("ip","203.0.113.9"),("domain","malicious.example")})
 def test_expired_indicator_is_ignored(self):
  incident,_=self.incidents.ingest({"type":"port_scan","source_ip":"203.0.113.10","destination_ip":"10.0.0.2"})
  self.intel.import_indicators([{"type":"ip","value":"203.0.113.10","expires_at":"2000-01-01T00:00:00Z"}]); self.assertEqual(self.intel.match_incident(incident),[])
 def test_notes_are_append_only_and_scoped(self):
  incident,_=self.incidents.ingest({"type":"port_scan","source_ip":"10.0.0.20","destination_ip":"10.0.0.10"})
  self.intel.add_note(incident["id"],"Reviewed metadata","analyst-1"); self.assertEqual(self.intel.list_notes(incident["id"])[0]["author"],"analyst-1"); self.assertIsNone(self.intel.add_note("missing","No incident"))
if __name__=="__main__": unittest.main()
