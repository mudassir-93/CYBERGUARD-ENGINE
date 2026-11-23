import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ml_anomaly import FEATURES,score_features,train_baseline
class BaselineTests(unittest.TestCase):
 def model(self): return train_baseline([{name:10+i%3 for name in FEATURES} for i in range(40)])
 def test_minimum_training_rows(self):
  with self.assertRaises(ValueError): train_baseline([{name:1 for name in FEATURES} for _ in range(19)])
 def test_normal_observation(self): self.assertFalse(score_features({name:11 for name in FEATURES},self.model())["anomalous"])
 def test_extreme_value_is_explained(self):
  result=score_features({**{name:11 for name in FEATURES},"packet_rate":1000},self.model()); self.assertTrue(result["anomalous"]); self.assertEqual(result["reasons"][0]["feature"],"packet_rate")
 def test_rejects_invalid_feature(self):
  for value in (-1,float("inf"),"bad"):
   with self.assertRaises(ValueError): score_features({"packet_rate":value},self.model())
if __name__=="__main__": unittest.main()
