import pandas as pd
ALIASES={"alert":"alert_id","alertid":"alert_id","asset":"asset_code","assetcode":"asset_code","closure_time":"closure_minutes","time_to_close":"closure_minutes","resolution_time":"closure_minutes","entity":"entity_code","entitycode":"entity_code","escalated":"escalation_recorded","escalation":"escalation_recorded","investigation":"investigation_type","analyst":"investigator","remediation":"remediation_recorded","date":"timestamp","state":"status"}
REQUIRED=["alert_id","asset_code","closure_minutes","entity_code","escalation_recorded","investigation_type","investigator","remediation_recorded","root_cause","status","timestamp"]
def b(v):
    if pd.isna(v) or str(v).strip()=="": return 0
    s=str(v).strip().lower()
    if s in ("1","yes","y","true","t"): return 1
    if s in ("0","no","n","false","f"): return 0
    raise ValueError(f"Invalid boolean value '{v}'. Use Yes/No or 1/0.")
def normalize(df):
    x=df.copy(); x.columns=[str(c).strip().lower().replace(" ","_") for c in x.columns]; x=x.rename(columns={c:ALIASES.get(c,c) for c in x.columns})
    miss=[c for c in REQUIRED if c not in x.columns]
    if miss:return None,"Missing columns: "+", ".join(miss),{}
    x["alert_id"]=x.alert_id.astype(str).str.strip(); x["entity_code"]=x.entity_code.astype(str).str.strip(); x["asset_code"]=x.asset_code.astype(str).str.strip()
    x["severity"]=x.get("severity",pd.Series("Medium",index=x.index)).astype(str).str.title(); x["category"]=x.get("category",pd.Series("Unknown",index=x.index)).astype(str)
    x["status"]=x.status.astype(str).str.title(); x["closure_minutes"]=pd.to_numeric(x.closure_minutes,errors="coerce").fillna(0).astype(int)
    x["escalation_recorded"]=x.escalation_recorded.apply(b); x["remediation_recorded"]=x.remediation_recorded.apply(b); x["timestamp"]=x.timestamp.astype(str)
    x["root_cause"]=x.root_cause.fillna("Under investigation").astype(str); x["investigation_type"]=x.investigation_type.fillna("Unknown").astype(str); x["investigator"]=x.investigator.fillna("Unknown").astype(str)
    dup=int(x.alert_id.duplicated().sum()); x=x.drop_duplicates("alert_id").reset_index(drop=True)
    return x,"",{"records_received":len(df),"records_accepted":len(x),"duplicate_alerts":dup,"missing_timestamps":int(pd.to_datetime(x.timestamp,errors="coerce").isna().sum())}
