import sqlite3
from pathlib import Path
from datetime import datetime
BASE_DIR=Path(__file__).resolve().parents[2]; DATA_DIR=BASE_DIR/"data"; DB_PATH=DATA_DIR/"sat_sa.db"; DATA_DIR.mkdir(exist_ok=True)
def connect():
    c=sqlite3.connect(DB_PATH); c.execute("PRAGMA foreign_keys=ON"); return c
def init_db():
    c=connect()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS entities(entity_id INTEGER PRIMARY KEY AUTOINCREMENT,entity_code TEXT UNIQUE,name TEXT);
    CREATE TABLE IF NOT EXISTS assets(asset_id INTEGER PRIMARY KEY AUTOINCREMENT,asset_code TEXT UNIQUE,entity_id INTEGER,criticality TEXT DEFAULT 'Unknown',FOREIGN KEY(entity_id) REFERENCES entities(entity_id));
    CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY,entity_id INTEGER,asset_id INTEGER,timestamp TEXT,severity TEXT,category TEXT,status TEXT,closure_minutes INTEGER,escalation_recorded INTEGER,FOREIGN KEY(entity_id) REFERENCES entities(entity_id),FOREIGN KEY(asset_id) REFERENCES assets(asset_id));
    CREATE TABLE IF NOT EXISTS cases(case_id INTEGER PRIMARY KEY AUTOINCREMENT,alert_id TEXT UNIQUE,investigation_type TEXT,investigator TEXT,remediation_recorded INTEGER,root_cause TEXT,FOREIGN KEY(alert_id) REFERENCES alerts(alert_id));
    CREATE TABLE IF NOT EXISTS escalations(escalation_id INTEGER PRIMARY KEY AUTOINCREMENT,alert_id TEXT UNIQUE,recorded INTEGER,FOREIGN KEY(alert_id) REFERENCES alerts(alert_id));
    CREATE TABLE IF NOT EXISTS findings(finding_id INTEGER PRIMARY KEY AUTOINCREMENT,run_id TEXT,entity_code TEXT,finding_type TEXT,severity TEXT,score REAL,title TEXT,explanation TEXT,recommendation TEXT,status TEXT DEFAULT 'Pending Review',created_at TEXT);
    CREATE TABLE IF NOT EXISTS finding_evidence(finding_id INTEGER,alert_id TEXT,FOREIGN KEY(finding_id) REFERENCES findings(finding_id),FOREIGN KEY(alert_id) REFERENCES alerts(alert_id));
    CREATE TABLE IF NOT EXISTS analytics_runs(run_id TEXT PRIMARY KEY,assessment_code TEXT,rule_version TEXT,model_version TEXT,dataset_records INTEGER,created_at TEXT);
    CREATE TABLE IF NOT EXISTS audit_log(audit_id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT,actor TEXT,action TEXT,object_type TEXT,object_id TEXT,details TEXT);
    CREATE TABLE IF NOT EXISTS rule_versions(rule_id INTEGER PRIMARY KEY AUTOINCREMENT,rule_name TEXT,version TEXT,description TEXT,UNIQUE(rule_name,version));
    CREATE TABLE IF NOT EXISTS model_versions(model_id INTEGER PRIMARY KEY AUTOINCREMENT,model_name TEXT,version TEXT,description TEXT,UNIQUE(model_name,version));
    """)
    c.executemany("INSERT OR IGNORE INTO rule_versions(rule_name,version,description) VALUES(?,?,?)",[
    ("Execution Gap","2.0","Multi-indicator closure, escalation, investigation and remediation analysis"),
    ("Negative Space","2.0","Expected alert-category coverage analysis"),
    ("Repeated Pattern","2.0","Repeated rapid-closure detection"),
    ("Priority Scoring","2.0","Transparent weighted priority model")])
    c.execute("INSERT OR IGNORE INTO model_versions(model_name,version,description) VALUES(?,?,?)",("Isolation Forest","1.0","Unsupervised anomaly detection prototype"))
    c.commit(); c.close()
def audit(action,obj="",oid="",details=""):
    c=connect(); c.execute("INSERT INTO audit_log(timestamp,actor,action,object_type,object_id,details) VALUES(?,?,?,?,?,?)",(datetime.now().isoformat(timespec="seconds"),"SAT-SA",action,obj,str(oid),details)); c.commit(); c.close()
