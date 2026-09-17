import json
import pandas as pd
import streamlit as st
from sat_sa.database.db import connect,init_db,DB_PATH,audit
from sat_sa.ingestion.normalizer import normalize
from sat_sa.analytics.engine import run_analytics
from sat_sa.analytics.ml import isolation_forest_scores
from sat_sa.reports.exporter import csv_bytes,json_bytes,xlsx_bytes,pdf_bytes
st.set_page_config(page_title="SAT-SA",page_icon="🛡️",layout="wide");init_db()
def q(sql,p=()):
 c=connect();d=pd.read_sql_query(sql,c,params=p);c.close();return d
def demo():
 r=[
 ["ALT-001","ENT-001","Alpha Finance","AST-001","2026-09-01 09:12","Critical","Malware",5,"Closed","Yes","Standard IR","Analyst-01","No","Pending review"],
 ["ALT-002","ENT-001","Alpha Finance","AST-002","2026-09-01 10:25","High","Credential Abuse",9,"Closed","No","Template","Analyst-02","No","Pending review"],
 ["ALT-003","ENT-001","Alpha Finance","AST-001","2026-09-01 11:40","Medium","Phishing",45,"Closed","Yes","Standard IR","Analyst-01","Yes","Closed"],
 ["ALT-004","ENT-001","Alpha Finance","AST-001","2026-09-02 08:10","High","Malware",6,"Closed","No","Template","Analyst-02","No","Pending review"],
 ["ALT-005","ENT-002","Beta Energy","AST-003","2026-09-01 09:30","Critical","Malware",22,"Closed","Yes","Standard IR","Analyst-03","Yes","Closed"],
 ["ALT-006","ENT-002","Beta Energy","AST-004","2026-09-01 12:15","High","Credential Abuse",65,"Closed","Yes","Deep Investigation","Analyst-03","Yes","Closed"],
 ["ALT-007","ENT-002","Beta Energy","AST-003","2026-09-02 14:05","Medium","Phishing",55,"Closed","No","Standard IR","Analyst-04","Yes","Closed"],
 ["ALT-008","ENT-002","Beta Energy","AST-004","2026-09-03 09:45","High","Data Exfiltration",47,"Closed","Yes","Deep Investigation","Analyst-03","Yes","Closed"],
 ["ALT-009","ENT-003","Gamma Telecom","AST-005","2026-09-01 08:55","Critical","Malware",6,"Closed","No","Template","Analyst-05","No","Pending review"],
 ["ALT-010","ENT-003","Gamma Telecom","AST-006","2026-09-01 10:10","High","Credential Abuse",8,"Closed","No","Template","Analyst-05","No","Pending review"],
 ["ALT-011","ENT-003","Gamma Telecom","AST-005","2026-09-02 11:25","High","Phishing",9,"Closed","No","Template","Analyst-05","No","Pending review"],
 ["ALT-012","ENT-003","Gamma Telecom","AST-006","2026-09-03 16:20","Medium","Phishing",35,"Closed","No","Standard IR","Analyst-06","Yes","Closed"],
 ["ALT-013","ENT-004","Delta Healthcare","AST-007","2026-09-01 09:05","Critical","Malware",43,"Closed","Yes","Deep Investigation","Analyst-07","Yes","Closed"],
 ["ALT-014","ENT-004","Delta Healthcare","AST-008","2026-09-01 13:10","High","Credential Abuse",50,"Closed","Yes","Deep Investigation","Analyst-07","Yes","Closed"],
 ["ALT-015","ENT-004","Delta Healthcare","AST-007","2026-09-02 10:30","High","Data Exfiltration",0,"Open","Yes","Deep Investigation","Analyst-07","No","In progress"]]
 return pd.DataFrame(r,columns=["alert_id","entity_code","entity_name","asset_code","timestamp","severity","category","closure_minutes","status","escalation_recorded","investigation_type","investigator","remediation_recorded","root_cause"])
def load(raw):
 d,msg,qa=normalize(raw)
 if d is None:return False,msg,qa
 c=connect()
 try:
  for _,r in d.iterrows():
   c.execute("INSERT OR IGNORE INTO entities(entity_code,name) VALUES(?,?)",(r.entity_code,getattr(r,"entity_name",r.entity_code)));eid=c.execute("SELECT entity_id FROM entities WHERE entity_code=?",(r.entity_code,)).fetchone()[0]
   c.execute("INSERT OR IGNORE INTO assets(asset_code,entity_id) VALUES(?,?)",(r.asset_code,eid));aid=c.execute("SELECT asset_id FROM assets WHERE asset_code=?",(r.asset_code,)).fetchone()[0]
   c.execute("INSERT OR REPLACE INTO alerts VALUES(?,?,?,?,?,?,?,?,?)",(r.alert_id,eid,aid,str(r.timestamp),r.severity,r.category,r.status,int(r.closure_minutes),int(r.escalation_recorded)))
   c.execute("INSERT OR REPLACE INTO cases(alert_id,investigation_type,investigator,remediation_recorded,root_cause) VALUES(?,?,?,?,?)",(r.alert_id,r.investigation_type,r.investigator,int(r.remediation_recorded),r.root_cause))
   c.execute("INSERT OR REPLACE INTO escalations(alert_id,recorded) VALUES(?,?)",(r.alert_id,int(r.escalation_recorded)))
  c.commit()
 except Exception as e:c.rollback();c.close();return False,str(e),qa
 c.close();audit("Data Import","dataset","",f"Accepted {len(d)} records");run_analytics();return True,"",qa
st.sidebar.title("🛡️ SAT-SA");st.sidebar.caption("Advanced Offline Supervisory Analytics");st.sidebar.divider()
if st.sidebar.button("Load / Reset Demo Dataset",use_container_width=True):
 c=connect()
 for t in ["finding_evidence","findings","analytics_runs","cases","escalations","alerts","assets","entities"]:c.execute(f"DELETE FROM {t}")
 c.commit();c.close();load(demo());st.session_state.notice="Demo dataset loaded and analytics completed.";st.rerun()
up=st.sidebar.file_uploader("Import Evidence",type=["csv","json"])
if up and st.sidebar.button("Import & Analyze",use_container_width=True):
 try:
  raw=pd.read_csv(up) if up.name.lower().endswith(".csv") else pd.DataFrame(json.load(up));ok,msg,qa=load(raw);st.session_state.notice=(f"Imported {qa.get('records_accepted',0)} records." if ok else "QA failed: "+msg)
 except Exception as e:st.session_state.notice="Import failed: "+str(e)
 st.rerun()
st.sidebar.write("Database:",str(DB_PATH));st.title("🛡️ SAT-SA — Supervisory Analytics Tool");st.caption("Offline, air-gapped supervisory analytics for SOC evidence review");st.warning("ACADEMIC / DEMONSTRATION PROTOTYPE — synthetic evidence only. Priority scores are SAT-SA analytical priorities, not official NCIIPC scores.")
if "notice" in st.session_state:st.success(st.session_state.pop("notice"))
tabs=st.tabs(["Dashboard","Findings & Evidence","Peer Analytics","Anomaly Lab","Data & QA","Runs & Versions","Database","Reports & Audit"])
with tabs[0]:
 a=q("SELECT * FROM alerts");f=q("SELECT * FROM findings");e=q("SELECT * FROM entities");x1,x2,x3,x4=st.columns(4);x1.metric("Entities",len(e));x2.metric("Alerts",len(a));x3.metric("Findings",len(f));x4.metric("High/Critical",len(f[f.severity.isin(["High","Critical"])]))
 if not f.empty:
  z1,z2=st.columns(2)
  with z1:st.subheader("Findings by Type");st.bar_chart(f.finding_type.value_counts())
  with z2:st.subheader("Findings by Entity");st.bar_chart(f.entity_code.value_counts())
  st.subheader("Priority Review Queue");st.dataframe(f[["finding_id","entity_code","finding_type","severity","score","title","status"]].sort_values("score",ascending=False),use_container_width=True,hide_index=True)
with tabs[1]:
 f=q("SELECT * FROM findings ORDER BY score DESC")
 if f.empty:st.info("No findings.")
 else:
  sid=st.selectbox("Finding",f.finding_id.tolist());r=f[f.finding_id==sid].iloc[0];st.subheader(r.title);a,b,c,d=st.columns(4);a.metric("Entity",r.entity_code);b.metric("Severity",r.severity);c.metric("Priority",f"{r.score:.0f}");d.metric("Status",r.status);st.write(r.explanation);st.info("Recommended review: "+r.recommendation)
  ev=q("""SELECT a.alert_id,e.entity_code,s.asset_code,a.timestamp,a.severity,a.category,a.status,a.closure_minutes,a.escalation_recorded,c.investigation_type,c.investigator,c.remediation_recorded,c.root_cause FROM finding_evidence fe JOIN alerts a ON fe.alert_id=a.alert_id JOIN entities e ON a.entity_id=e.entity_id JOIN assets s ON a.asset_id=s.asset_id LEFT JOIN cases c ON a.alert_id=c.alert_id WHERE fe.finding_id=?""",(int(sid),));st.dataframe(ev,use_container_width=True,hide_index=True)
  ns=st.selectbox("Review disposition",["Pending Review","Under Review","Accepted","Rejected","Closed"]); 
  if st.button("Save Disposition"):c=connect();c.execute("UPDATE findings SET status=? WHERE finding_id=?",(ns,int(sid)));c.commit();c.close();audit("Finding Disposition Updated","finding",sid,ns);st.rerun()
with tabs[2]:
 d=q("""SELECT e.entity_code,a.closure_minutes,a.escalation_recorded,c.remediation_recorded FROM alerts a JOIN entities e ON a.entity_id=e.entity_id LEFT JOIN cases c ON a.alert_id=c.alert_id""")
 if not d.empty:
  p=d.groupby("entity_code").agg(alerts=("entity_code","size"),median_closure=("closure_minutes","median"),escalation_rate=("escalation_recorded","mean"),remediation_rate=("remediation_recorded","mean")).reset_index();p["escalation_rate"]=(p.escalation_rate*100).round(1);p["remediation_rate"]=(p.remediation_rate*100).round(1);st.dataframe(p,use_container_width=True,hide_index=True);st.bar_chart(p.set_index("entity_code")[["median_closure"]])
with tabs[3]:
 d=q("SELECT a.*,e.entity_code FROM alerts a JOIN entities e ON a.entity_id=e.entity_id")
 if len(d)>=8:d["anomaly_score"]=isolation_forest_scores(d);st.dataframe(d[["alert_id","entity_code","severity","category","closure_minutes","escalation_recorded","anomaly_score"]].sort_values("anomaly_score",ascending=False),use_container_width=True,hide_index=True)
 else:st.info("Load at least 8 alerts.")
with tabs[4]:
 d=q("SELECT a.alert_id,e.entity_code,s.asset_code,a.timestamp,a.severity,a.category,a.status,a.closure_minutes,a.escalation_recorded FROM alerts a JOIN entities e ON a.entity_id=e.entity_id JOIN assets s ON a.asset_id=s.asset_id")
 if d.empty:st.info("No data loaded.")
 else:
  a,b,c=st.columns(3);a.metric("Records",len(d));b.metric("Entities",d.entity_code.nunique());c.metric("Duplicates",int(d.alert_id.duplicated().sum()));st.dataframe(d,use_container_width=True,hide_index=True)
with tabs[5]:
 st.subheader("Analytics Runs");st.dataframe(q("SELECT * FROM analytics_runs ORDER BY created_at DESC"),use_container_width=True,hide_index=True);st.subheader("Rule Versions");st.dataframe(q("SELECT * FROM rule_versions"),use_container_width=True,hide_index=True);st.subheader("Model Versions");st.dataframe(q("SELECT * FROM model_versions"),use_container_width=True,hide_index=True)
with tabs[6]:
 t=st.selectbox("Table",["entities","assets","alerts","cases","escalations","findings","finding_evidence","analytics_runs","rule_versions","model_versions","audit_log"]);st.dataframe(q(f"SELECT * FROM {t}"),use_container_width=True,hide_index=True)
with tabs[7]:
 f=q("SELECT * FROM findings ORDER BY score DESC")
 if not f.empty:
  st.download_button("CSV",csv_bytes(f),"sat_sa_findings.csv","text/csv");st.download_button("JSON",json_bytes(f),"sat_sa_findings.json","application/json");st.download_button("Excel",xlsx_bytes(f),"sat_sa_findings.xlsx","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");p=pdf_bytes(f)
  if p:st.download_button("PDF",p,"sat_sa_findings.pdf","application/pdf")
 st.subheader("Audit Log");st.dataframe(q("SELECT * FROM audit_log ORDER BY audit_id DESC"),use_container_width=True,hide_index=True)
st.divider();st.caption("SAT-SA v2.0 | Offline / Air-Gapped Academic Proof of Concept | Human-in-the-loop & Explainable Analytics")
