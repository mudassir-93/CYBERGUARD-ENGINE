"""Local-first IOC catalog and append-only analyst notes."""
import ipaddress,json,re,sqlite3
from contextlib import contextmanager
from datetime import datetime,timezone
from pathlib import Path
DOMAIN=re.compile(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")
HASH={"md5":32,"sha1":40,"sha256":64}
def timestamp(v,name):
 if v in (None,""): return None
 if not isinstance(v,str) or len(v)>64: raise ValueError(f"{name} must be an ISO-8601 timestamp")
 try: d=datetime.fromisoformat(v.replace("Z","+00:00"))
 except ValueError as e: raise ValueError(f"{name} must be an ISO-8601 timestamp") from e
 if d.tzinfo is None: d=d.replace(tzinfo=timezone.utc)
 return d.astimezone(timezone.utc).isoformat(timespec="seconds")
def normalize_indicator(x):
 if not isinstance(x,dict): raise ValueError("Each indicator must be a JSON object")
 kind,value=x.get("type"),x.get("value")
 if not isinstance(kind,str) or kind not in {"ip","domain","md5","sha1","sha256"}: raise ValueError("Invalid indicator type")
 if not isinstance(value,str) or not value.strip() or len(value)>253: raise ValueError("Indicator value must contain 1-253 characters")
 value=value.strip()
 if kind=="ip":
  try: value=str(ipaddress.ip_address(value))
  except ValueError as e: raise ValueError("Invalid IP indicator") from e
 elif kind=="domain":
  value=value.rstrip(".").lower()
  if not DOMAIN.fullmatch(value): raise ValueError("Invalid domain indicator")
 else:
  value=value.lower()
  if len(value)!=HASH[kind] or not re.fullmatch("[0-9a-f]+",value): raise ValueError(f"{kind} indicator must be {HASH[kind]} hexadecimal characters")
 confidence=x.get("confidence",50); severity=x.get("severity","medium")
 if isinstance(confidence,bool) or not isinstance(confidence,int) or not 0<=confidence<=100: raise ValueError("confidence must be an integer from 0 to 100")
 if not isinstance(severity,str) or severity not in {"low","medium","high","critical"}: raise ValueError("Invalid indicator severity")
 source=x.get("source","manual-import"); desc=x.get("description",""); tags=x.get("tags",[])
 if not isinstance(source,str) or not source.strip() or len(source)>120: raise ValueError("source must contain 1-120 characters")
 if not isinstance(desc,str) or len(desc)>1000: raise ValueError("description too long")
 if not isinstance(tags,list) or len(tags)>30 or any(not isinstance(t,str) or len(t)>50 for t in tags): raise ValueError("Invalid indicator tags")
 return {"type":kind,"value":value,"confidence":confidence,"severity":severity,"source":source.strip(),"description":desc,"tags":sorted(set(t.strip() for t in tags if t.strip())),"first_seen":timestamp(x.get("first_seen"),"first_seen") or datetime.now(timezone.utc).isoformat(timespec="seconds"),"last_seen":timestamp(x.get("last_seen"),"last_seen"),"expires_at":timestamp(x.get("expires_at"),"expires_at")}
class ThreatIntelStore:
 def __init__(self,path):
  self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
  with self.session() as db:
   db.executescript("""CREATE TABLE IF NOT EXISTS threat_indicators(id INTEGER PRIMARY KEY,type TEXT,value TEXT,confidence INTEGER,severity TEXT,source TEXT,description TEXT,tags_json TEXT,first_seen TEXT,last_seen TEXT,expires_at TEXT,created_at TEXT,UNIQUE(type,value,source)); CREATE INDEX IF NOT EXISTS idx_ioc_value ON threat_indicators(type,value); CREATE TABLE IF NOT EXISTS analyst_notes(id INTEGER PRIMARY KEY,incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,note TEXT NOT NULL,author TEXT NOT NULL,created_at TEXT NOT NULL); CREATE INDEX IF NOT EXISTS idx_notes_incident ON analyst_notes(incident_id,id);""")
 def connect(self):
  db=sqlite3.connect(self.path,timeout=10); db.row_factory=sqlite3.Row; db.execute("PRAGMA foreign_keys=ON"); return db
 @contextmanager
 def session(self):
  db=self.connect()
  try:
   yield db
   db.commit()
  except Exception:
   db.rollback()
   raise
  finally:
   db.close()
 @staticmethod
 def row(r):
  x=dict(r); x["tags"]=json.loads(x.pop("tags_json")); return x
 def import_indicators(self,items):
  if not isinstance(items,list) or not items or len(items)>5000: raise ValueError("indicators must be a non-empty array of at most 5000 entries")
  values=[normalize_indicator(x) for x in items]; now=datetime.now(timezone.utc).isoformat(timespec="seconds"); inserted=updated=0
  with self.connect() as db:
   for x in values:
    old=db.execute("SELECT 1 FROM threat_indicators WHERE type=? AND value=? AND source=?",(x["type"],x["value"],x["source"])).fetchone()
    db.execute("""INSERT INTO threat_indicators(type,value,confidence,severity,source,description,tags_json,first_seen,last_seen,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(type,value,source) DO UPDATE SET confidence=excluded.confidence,severity=excluded.severity,description=excluded.description,tags_json=excluded.tags_json,last_seen=COALESCE(excluded.last_seen,threat_indicators.last_seen),expires_at=excluded.expires_at""",(x["type"],x["value"],x["confidence"],x["severity"],x["source"],x["description"],json.dumps(x["tags"]),x["first_seen"],x["last_seen"],x["expires_at"],now))
    if old: updated+=1
    else: inserted+=1
  return {"inserted":inserted,"updated":updated,"total_processed":len(values)}
 def list_indicators(self,kind=None,limit=100):
  if kind and kind not in {"ip","domain","md5","sha1","sha256"}: raise ValueError("Invalid indicator type")
  limit=max(1,min(int(limit),500)); now=datetime.now(timezone.utc).isoformat(timespec="seconds")
  with self.connect() as db: rows=db.execute("SELECT * FROM threat_indicators WHERE (expires_at IS NULL OR expires_at>?)"+(" AND type=?" if kind else "")+" ORDER BY confidence DESC,id DESC LIMIT ?",(now,kind,limit) if kind else (now,limit)).fetchall()
  return [self.row(r) for r in rows]
 def match_incident(self,incident):
  candidates={("ip",incident.get("source_ip")),("ip",incident.get("destination_ip"))}
  def walk(v,key=""):
   if isinstance(v,dict):
    for k,x in v.items(): walk(x,str(k).lower())
   elif isinstance(v,list):
    for x in v[:500]: walk(x,key)
   elif isinstance(v,str):
    if key in {"domain","hostname","host"}: candidates.add(("domain",v.lower().rstrip(".")))
    elif key in HASH: candidates.add((key,v.lower()))
    elif key in {"indicator","ioc"}:
     try: ipaddress.ip_address(v); candidates.add(("ip",v))
     except ValueError:
      if DOMAIN.fullmatch(v.lower()): candidates.add(("domain",v.lower()))
  walk(incident.get("evidence",{})); candidates.discard(("ip",None)); now=datetime.now(timezone.utc).isoformat(timespec="seconds"); found=[]
  with self.connect() as db:
   for kind,value in candidates:
    if value: found.extend(self.row(r) for r in db.execute("SELECT * FROM threat_indicators WHERE type=? AND value=? AND (expires_at IS NULL OR expires_at>?)",(kind,value,now)).fetchall())
  return found
 def add_note(self,incident_id,note,author="local-analyst"):
  if not isinstance(note,str) or not note.strip() or len(note.strip())>2000: raise ValueError("note must contain 1-2000 characters")
  if not isinstance(author,str) or not author.strip() or len(author)>80: raise ValueError("author must contain 1-80 characters")
  now=datetime.now(timezone.utc).isoformat(timespec="seconds")
  with self.connect() as db:
   if not db.execute("SELECT 1 FROM incidents WHERE id=?",(incident_id,)).fetchone(): return None
   cur=db.execute("INSERT INTO analyst_notes(incident_id,note,author,created_at) VALUES(?,?,?,?)",(incident_id,note.strip(),author.strip(),now))
   return {"id":cur.lastrowid,"incident_id":incident_id,"note":note.strip(),"author":author.strip(),"created_at":now}
 def list_notes(self,incident_id):
  with self.connect() as db: return [dict(r) for r in db.execute("SELECT id,incident_id,note,author,created_at FROM analyst_notes WHERE incident_id=? ORDER BY id",(incident_id,)).fetchall()]
