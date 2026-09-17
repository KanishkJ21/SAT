import pandas as pd
def isolation_forest_scores(df):
    try:from sklearn.ensemble import IsolationForest
    except Exception:return pd.Series(index=df.index,dtype=float)
    if len(df)<8:return pd.Series(index=df.index,dtype=float)
    x=df[["closure_minutes","escalation_recorded"]].copy(); x["severity_num"]=df.severity.map({"Low":1,"Medium":2,"High":3,"Critical":4}).fillna(2); x["status_num"]=df.status.map({"Open":1,"Closed":0}).fillna(0)
    m=IsolationForest(n_estimators=150,random_state=42); m.fit(x); return pd.Series(-m.score_samples(x),index=df.index)
