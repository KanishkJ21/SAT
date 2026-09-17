from datetime import datetime
import uuid,pandas as pd
from sat_sa.database.db import connect,audit
def run_analytics():
    c=connect(); a=pd.read_sql_query("SELECT a.*,e.entity_code,e.name AS entity_name,s.asset_code FROM alerts a JOIN entities e ON a.entity_id=e.entity_id JOIN assets s ON a.asset_id=s.asset_id",c); cases=pd.read_sql_query("SELECT * FROM cases",c); c.close()
    if a.empty:return None,0
    run="RUN-"+uuid.uuid4().hex[:8].upper(); now=datetime.now().isoformat(timespec="seconds"); cm=cases.set_index("alert_id").to_dict("index") if not cases.empty else {}; fs=[]
    def add(e,t,s,score,title,exp,rec,ids):fs.append((e,t,s,min(100,max(0,score)),title,exp,rec,ids))
    global_med=float(a.closure_minutes.median() or 1)
    for _,r in a.iterrows():
        z=cm.get(r.alert_id,{}); sev=str(r.severity).lower(); high=sev in ("high","critical"); fast=r.status.lower()=="closed" and r.closure_minutes<=15; noesc=int(r.escalation_recorded)==0; temp=str(z.get("investigation_type","")).lower()=="template"; norem=int(z.get("remediation_recorded",0))==0
        if high and fast and noesc:
            score=60+(15 if sev=="critical" else 8)+(10 if temp else 0)+(10 if norem else 0)
            add(r.entity_code,"Execution Gap",r.severity,score,"Rapid high-severity closure without escalation",f"{r.alert_id} is a {r.severity}-severity {r.category} alert closed in {r.closure_minutes} minutes without recorded escalation. Template investigation={temp}; remediation recorded={not norem}.","Review investigation, escalation, remediation and closure rationale.",[r.alert_id])
        if high and temp:add(r.entity_code,"Investigation Quality",r.severity,76,"Template-like investigation on high-severity alert",f"{r.alert_id} uses a template-like investigation classification for a {r.severity}-severity alert.","Review investigation depth and supporting telemetry.",[r.alert_id])
        if high and r.status.lower()=="closed" and norem:add(r.entity_code,"Remediation Gap",r.severity,84,"Closed high-severity alert without remediation evidence",f"{r.alert_id} was closed without recorded remediation evidence.","Verify remediation action and completion evidence.",[r.alert_id])
    for (e,cat),g in a[a.closure_minutes<=15].groupby(["entity_code","category"]):
        if len(g)>=2:add(e,"Repeated Pattern","High",82,f"Repeated rapid-closure pattern: {cat}",f"{len(g)} {cat} alerts for {e} were closed within 15 minutes.","Compare investigation, escalation and remediation across related records.",g.alert_id.tolist())
    expected=set(a.category.dropna().unique())
    for e,g in a.groupby("entity_code"):
        for cat in sorted(expected-set(g.category.dropna().unique())):add(e,"Negative Space","Medium",68,f"Missing expected alert category: {cat}",f"No {cat} alerts are present for {e} in the loaded period. This may indicate a coverage gap or low activity.","Validate expected telemetry, asset scope and source coverage.",[])
    for e,g in a.groupby("entity_code"):
        if len(g)>=2 and float(g.closure_minutes.median())<global_med*.45:add(e,"Peer Deviation","High",79,"Closure-time deviation from peer baseline",f"{e} median closure time is {g.closure_minutes.median():.1f} minutes versus peer median {global_med:.1f} minutes.","Compare workload, alert mix, severity and handling evidence.",g.sort_values("closure_minutes").head(3).alert_id.tolist())
    c=connect(); c.execute("DELETE FROM finding_evidence"); c.execute("DELETE FROM findings")
    for e,t,s,score,title,exp,rec,ids in fs:
        cur=c.execute("INSERT INTO findings(run_id,entity_code,finding_type,severity,score,title,explanation,recommendation,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",(run,e,t,s,score,title,exp,rec,"Pending Review",now)); fid=cur.lastrowid
        for aid in ids:c.execute("INSERT INTO finding_evidence VALUES(?,?)",(fid,aid))
    c.execute("INSERT OR REPLACE INTO analytics_runs VALUES(?,?,?,?,?,?)",(run,"DEMO-ASSESSMENT","2.0","1.0",len(a),now)); c.commit(); c.close(); audit("Analytics Run","run",run,f"{len(fs)} findings from {len(a)} alerts"); return run,len(fs)
