# SAT-SA Live + Offline Hybrid

SAT-SA is a local Streamlit prototype for supervisory analytics of SOC evidence.

It supports:
- Offline CSV and JSON evidence import
- Windows Event Log collection
- Linux log-file collection
- Demo log simulation
- SQLite evidence storage
- Execution/anomaly style findings
- Evidence-backed findings and human review
- Fully local/offline operation after dependencies are installed

## Run on Windows

    py -m venv .venv
    .venv\Scripts\python.exe -m pip install -r requirements.txt
    .venv\Scripts\python.exe -m streamlit run sat_sa\app.py

PowerShell execution-policy changes are not required.

## CSV import

The importer accepts common SOC/evidence column names such as:
timestamp, host, hostname, asset_code, source, log_source, event_code,
event_id, alert_id, level, severity, category, investigation_type,
username, investigator, message, description, root_cause.

The original columns are retained as raw evidence.
