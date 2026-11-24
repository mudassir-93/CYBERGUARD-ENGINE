"""Explainable dependency-free robust anomaly baseline using median/MAD."""
import argparse,csv,json,math
from pathlib import Path
FEATURES=("packet_rate","distinct_ports","failed_attempts","bytes_per_second","destination_fanout")
def _number(value,name):
 if isinstance(value,bool): raise ValueError(f"{name} must be numeric")
 try: result=float(value)
 except (TypeError,ValueError) as exc: raise ValueError(f"{name} must be numeric") from exc
 if not math.isfinite(result) or result<0: raise ValueError(f"{name} must be finite and non-negative")
 return result
def train_baseline(rows):
 rows=list(rows)
 if len(rows)<20: raise ValueError("At least 20 trusted baseline observations are required")
 model={"version":1,"method":"median_mad","samples":len(rows),"features":{}}
 for name in FEATURES:
  values=sorted(_number(row.get(name,0),name) for row in rows); n=len(values)
  median=values[n//2] if n%2 else (values[n//2-1]+values[n//2])/2
  dev=sorted(abs(x-median) for x in values); mad=dev[n//2] if n%2 else (dev[n//2-1]+dev[n//2])/2
  model["features"][name]={"median":median,"mad":mad}
 return model
def score_features(features,model,threshold=6.0):
 if not isinstance(model,dict) or model.get("version")!=1 or model.get("method")!="median_mad": raise ValueError("Unsupported anomaly baseline model")
 if not math.isfinite(float(threshold)) or threshold<1: raise ValueError("threshold must be finite and at least 1")
 scores=[]; reasons=[]
 for name in FEATURES:
  value=_number(features.get(name,0),name); stats=model.get("features",{}).get(name)
  if not isinstance(stats,dict): raise ValueError(f"Model is missing feature {name}")
  median,mad=float(stats["median"]),float(stats["mad"]); scale=max(1.4826*mad,max(abs(median)*.01,1.0)); deviation=abs(value-median)/scale; scores.append(deviation)
  if deviation>=threshold: reasons.append({"feature":name,"observed":value,"baseline_median":median,"robust_deviation":round(deviation,2)})
 maximum=max(scores,default=0.0)
 return {"anomalous":maximum>=threshold,"score":round(min(100.0,maximum/threshold*50),1),"method":"robust-mad-baseline","threshold":threshold,"reasons":reasons,"disclaimer":"Heuristic baseline score, not a calibrated probability or standalone security verdict."}
def main():
 parser=argparse.ArgumentParser(description="Train CyberGuard robust anomaly baseline from trusted CSV telemetry")
 parser.add_argument("csv_file"); parser.add_argument("--output",default="data/anomaly-baseline.json"); args=parser.parse_args()
 with open(args.csv_file,newline="",encoding="utf-8") as handle: model=train_baseline(csv.DictReader(handle))
 target=Path(args.output); target.parent.mkdir(parents=True,exist_ok=True); target.write_text(json.dumps(model,indent=2),encoding="utf-8")
 print(json.dumps({"model":str(target),"samples":model["samples"],"features":list(FEATURES)},indent=2))
if __name__=="__main__": main()
