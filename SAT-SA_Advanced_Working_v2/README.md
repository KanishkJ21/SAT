# SAT-SA v2.0
Advanced offline/air-gapped SOC supervisory analytics proof of concept.

Features: CSV/JSON ingestion, schema normalization, QA, SQLite evidence store, execution-gap detection, negative-space detection, repeated patterns, remediation/investigation gaps, peer benchmarking, Isolation Forest anomaly lab, explainable evidence-backed findings, human review/disposition, analytics run/version metadata, audit logs, CSV/JSON/XLSX/PDF reports.

Run:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run sat_sa/app.py
```
Open http://localhost:8501.

Academic/demo only; synthetic data; priority scores are not official NCIIPC scores.
