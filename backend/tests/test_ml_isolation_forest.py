import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
try:
 from ml_isolation_forest import FEATURES,IsolationForestAnalyzer,load_model,save_model,score_observation,train_model
 AVAILABLE=True
except ImportError:
 AVAILABLE=False
@unittest.skipUnless(AVAILABLE,"optional scikit-learn ML dependencies are not installed")
class IsolationForestTests(unittest.TestCase):
 def rows(self):
  return [{name:10+(index%5)*0.2 for name in FEATURES} for index in range(80)]
 def test_trains_saves_loads_and_scores(self):
  model=train_model(self.rows())
  with tempfile.TemporaryDirectory() as directory:
   path=save_model(model,Path(directory)/"model.joblib")
   loaded=load_model(path)
   result=score_observation({name:10.2 for name in FEATURES},loaded)
  self.assertIn("anomalous",result); self.assertEqual(result["algorithm"],"IsolationForest")
 def test_analyzer_object_loads_and_scores(self):
  model=train_model(self.rows())
  with tempfile.TemporaryDirectory() as directory:
   path=save_model(model,Path(directory)/"analyzer.joblib")
   analyzer=IsolationForestAnalyzer.from_file(path)
   result=analyzer.score({name:10.2 for name in FEATURES})
  self.assertEqual(analyzer.training_samples,80)
  self.assertEqual(result["algorithm"],"IsolationForest")
 def test_rejects_small_baseline_and_invalid_parameters(self):
  with self.assertRaises(ValueError): train_model(self.rows()[:49])
  with self.assertRaises(ValueError): train_model(self.rows(),contamination=0.5)
 def test_invalid_observation_is_rejected(self):
  model=train_model(self.rows())
  with self.assertRaises(ValueError): score_observation({"packet_rate":-1},model)
  with self.assertRaises(ValueError): score_observation(None,model)
  with self.assertRaises(ValueError): score_observation({"packet_rate":True},model)
if __name__=="__main__": unittest.main()
