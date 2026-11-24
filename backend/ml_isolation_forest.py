"""Optional scikit-learn Isolation Forest training and inference pipeline."""
from __future__ import annotations
import argparse,csv,math
from datetime import datetime,timezone
from pathlib import Path
from statistics import median
import joblib
from sklearn.ensemble import IsolationForest
from ml_anomaly import FEATURES,_number

def _features(row):
    return [_number(row.get(name,0),name) for name in FEATURES]

def train_model(rows,contamination=0.03,n_estimators=200):
    rows=list(rows)
    if len(rows)<50: raise ValueError("At least 50 trusted baseline observations are required")
    if not 0.01<=float(contamination)<=0.2: raise ValueError("contamination must be between 0.01 and 0.2")
    if isinstance(n_estimators,bool) or not isinstance(n_estimators,int) or not 100<=n_estimators<=1000:
        raise ValueError("n_estimators must be an integer from 100 to 1000")
    matrix=[_features(row) for row in rows]
    model=IsolationForest(n_estimators=n_estimators,contamination=contamination,random_state=42,n_jobs=1)
    model.fit(matrix)
    stats={}
    for index,name in enumerate(FEATURES):
        values=[row[index] for row in matrix]
        center=median(values)
        stats[name]={"median":center,"mad":median([abs(value-center) for value in values])}
    return {"version":1,"algorithm":"IsolationForest","features":list(FEATURES),
            "training_samples":len(matrix),"contamination":float(contamination),
            "n_estimators":n_estimators,"trained_at":datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "feature_baseline":stats,"estimator":model}

def save_model(model,path):
    target=Path(path); target.parent.mkdir(parents=True,exist_ok=True); joblib.dump(model,target); return target

def load_model(path):
    model=joblib.load(path)
    if not isinstance(model,dict) or model.get("version")!=1 or model.get("algorithm")!="IsolationForest" or model.get("features")!=list(FEATURES):
        raise ValueError("Unsupported Isolation Forest model artifact")
    return model

def score_observation(observation,model):
    if not isinstance(model,dict) or model.get("version")!=1 or model.get("algorithm")!="IsolationForest":
        raise ValueError("Unsupported Isolation Forest model")
    vector=_features(observation)
    estimator=model.get("estimator")
    prediction=int(estimator.predict([vector])[0])
    decision=float(estimator.decision_function([vector])[0])
    reasons=[]
    for index,name in enumerate(FEATURES):
        stats=model["feature_baseline"][name]; center=float(stats["median"]); mad=float(stats["mad"])
        scale=max(1.4826*mad,max(abs(center)*0.01,1.0))
        deviation=abs(vector[index]-center)/scale
        if deviation>=3:
            reasons.append({"feature":name,"observed":vector[index],"baseline_median":center,
                            "robust_deviation":round(deviation,2)})
    reasons.sort(key=lambda item:item["robust_deviation"],reverse=True)
    return {"anomalous":prediction==-1,"decision_function":round(decision,6),
            "score":round(max(0.0,min(100.0,50.0-decision*100.0)),1),
            "algorithm":"IsolationForest","training_samples":model["training_samples"],
            "reasons":reasons[:5],
            "disclaimer":"Model score is not a calibrated probability; validate false positives on representative labeled traffic."}

def main():
    parser=argparse.ArgumentParser(description="Train CyberGuard Isolation Forest from trusted telemetry CSV")
    parser.add_argument("csv_file"); parser.add_argument("--output",default="data/isolation-forest.joblib")
    parser.add_argument("--contamination",type=float,default=0.03); parser.add_argument("--estimators",type=int,default=200)
    args=parser.parse_args()
    with open(args.csv_file,newline="",encoding="utf-8") as handle: model=train_model(csv.DictReader(handle),args.contamination,args.estimators)
    target=save_model(model,args.output)
    print(f"Trained Isolation Forest on {model['training_samples']} observations; model saved to {target}")

if __name__=="__main__": main()
