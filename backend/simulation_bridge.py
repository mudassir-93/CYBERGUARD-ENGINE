"""Run the native C++ simulator and persist its JSONL detections as incidents."""
from __future__ import annotations
import argparse, json, os, subprocess
from pathlib import Path
from typing import Any
from incidents import IncidentStore, default_store
ROOT=Path(__file__).resolve().parent.parent

def find_executable(explicit: str|None=None)->Path:
 configured=explicit or os.environ.get("CYBERGUARD_EXECUTABLE")
 if configured:
  path=Path(configured).expanduser().resolve()
  if not path.is_file(): raise FileNotFoundError(f"CyberGuard executable not found: {path}")
  return path
 candidates=(ROOT/"build"/"CyberGuard",ROOT/"build"/"CyberGuard.exe",ROOT/"build"/"Release"/"CyberGuard.exe",ROOT/"build"/"Debug"/"CyberGuard.exe",ROOT/"build"/"bin"/"CyberGuard",ROOT/"build"/"bin"/"CyberGuard.exe")
 for path in candidates:
  if path.is_file(): return path
 raise FileNotFoundError("CyberGuard executable not found. Build the project first or set CYBERGUARD_EXECUTABLE.")

def ingest_jsonl(output: str, store: IncidentStore)->dict[str,Any]:
 counts:dict[str,int]={};created=correlated=0
 for line_no,line in enumerate(output.splitlines(),1):
  if not line.strip(): continue
  try: event=json.loads(line)
  except json.JSONDecodeError as error: raise ValueError(f"Simulator emitted invalid JSON on line {line_no}") from error
  if not isinstance(event,dict): raise ValueError(f"Simulator output line {line_no} is not a JSON object")
  incident,was_correlated=store.ingest(event)
  counts[incident["type"]]=counts.get(incident["type"],0)+1
  if was_correlated: correlated+=1
  else: created+=1
 return {"detections_received":sum(counts.values()),"incidents_created":created,"detections_correlated":correlated,"by_type":counts,"summary":store.summary()}

def run_simulation(executable: str|None=None, store: IncidentStore|None=None)->dict[str,Any]:
 binary=find_executable(executable)
 result=subprocess.run([str(binary),"--jsonl"],cwd=ROOT,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=60,check=False)
 if result.returncode: raise RuntimeError((result.stderr.strip() or f"Simulator exited with code {result.returncode}")[:2000])
 report=ingest_jsonl(result.stdout,store or default_store())
 expected={"port_scan","brute_force","dos","lateral_movement"}
 missing=expected-set(report["by_type"])
 if missing: raise RuntimeError("Native simulator did not emit expected detection types: "+", ".join(sorted(missing)))
 report["executable"]=str(binary)
 return report

def main()->int:
 parser=argparse.ArgumentParser(description="Run CyberGuard C++ simulation and ingest detections into SQLite.")
 parser.add_argument("--executable",help="Path to compiled CyberGuard executable")
 args=parser.parse_args()
 try: report=run_simulation(args.executable)
 except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error: parser.exit(1,f"Simulation integration failed: {error}\n")
 print(json.dumps(report,indent=2));return 0
if __name__=="__main__": raise SystemExit(main())
