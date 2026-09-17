# SAT-SA Full Working Prototype

Offline proof-of-concept based on the SAT-SA brief.

Features:
- SQLite database
- CSV ingestion and QA
- Synthetic demo dataset
- Execution-gap detection
- Negative-space detection
- Anomaly/peer scoring
- Explainable findings
- Manual-review queue and statuses
- Evidence drill-down
- Peer analytics
- Database explorer
- Audit log
- CSV/JSON/XLSX/PDF exports

Windows:
1. python -m venv .venv
2. .\.venv\Scripts\Activate.ps1
3. python -m pip install -r requirements.txt
4. python -m streamlit run sat_sa/app.py

Demo data is synthetic and not production NCIIPC/CSE data.
