# SAT-SA — Supervisory Analytics Tool

**SAT-SA** is an offline, air-gapped supervisory analytics platform designed to assist SOC assessment by analyzing security alerts, event logs, and investigation evidence.

It provides a unified workflow for **evidence ingestion, normalization, local storage, analytics, explainable findings, visualization, and human-in-the-loop assessment**.

### Key Features

- Offline CSV and JSON evidence analysis
- Live Windows Event Log collection
- Linux log-file collection
- Controlled Demo Simulator
- SQLite-based local evidence storage
- Authentication failure detection
- Repeated event pattern detection
- High-severity event concentration detection
- Evidence-backed and explainable findings
- Interactive analytics dashboard
- Finding review and false-positive workflow
- Audit trail for assessment activities
- Designed for local and air-gapped environments

### Architecture

Evidence Sources
       ↓
Ingestion & Normalization
       ↓
Local Evidence Storage
       ↓
SAT-SA Analytics Engine
       ↓
Findings & Risk Indicators
       ↓
Evidence Drill-Down
       ↓
Human Assessor Review

Technology Stack

Python • Streamlit • SQLite • Pandas • NumPy • pywin32

SAT-SA is developed as an academic/prototype implementation demonstrating how offline supervisory analytics can support SOC assessment and reduce the manual effort involved in reviewing large volumes of security evidence.

Author: Kanishk Jha