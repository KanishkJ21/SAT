import json
import platform
import time

import pandas as pd
import streamlit as st

from sat_sa.config import DB_PATH, LIVE_INTERVAL_SECONDS
from sat_sa.db import (
    init_db,
    insert_event,
    recent_events,
    count_events,
    get_findings,
    events_by_ids,
    set_finding_status,
    audit,
    clear_data,
)
from sat_sa.normalizer import normalize
from sat_sa.analytics import analyze_event_ids, analyze_live_window
from sat_sa.collectors import (
    DemoCollector,
    LinuxFileCollector,
    WindowsEventCollector,
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="SAT-SA | Supervisory Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()


# ============================================================
# SESSION STATE
# ============================================================

if "running" not in st.session_state:
    st.session_state.running = False

if "collector" not in st.session_state:
    st.session_state.collector = None

if "collector_name" not in st.session_state:
    st.session_state.collector_name = "None"


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    /* Main page */

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1500px;
    }


    /* Header */

    .sat-header {
        padding: 1rem 0 1.5rem 0;
    }

    .sat-title {
        font-size: 2.1rem;
        font-weight: 700;
        margin-bottom: 0.15rem;
    }

    .sat-subtitle {
        color: #9aa4b2;
        font-size: 0.95rem;
    }


    /* Status */

    .status-online {
        display: inline-block;
        padding: 0.35rem 0.75rem;
        border-radius: 20px;
        background: rgba(0, 180, 100, 0.15);
        color: #55d68a;
        font-weight: 600;
        font-size: 0.82rem;
    }

    .status-offline {
        display: inline-block;
        padding: 0.35rem 0.75rem;
        border-radius: 20px;
        background: rgba(150, 150, 150, 0.15);
        color: #aeb6c2;
        font-weight: 600;
        font-size: 0.82rem;
    }


    /* Metric cards */

    .metric-card {
        border: 1px solid rgba(128, 128, 128, 0.18);
        border-radius: 12px;
        padding: 1rem;
        min-height: 105px;
        background: rgba(128, 128, 128, 0.035);
    }

    .metric-label {
        font-size: 0.78rem;
        color: #9aa4b2;
        margin-bottom: 0.35rem;
    }

    .metric-value {
        font-size: 1.65rem;
        font-weight: 700;
    }


    /* Section headings */

    .section-title {
        font-size: 1.2rem;
        font-weight: 650;
        margin-top: 0.5rem;
        margin-bottom: 0.2rem;
    }

    .section-description {
        color: #8e98a6;
        font-size: 0.86rem;
        margin-bottom: 1rem;
    }


    /* Finding cards */

    .finding-high {
        border-left: 4px solid #ff7b72;
        padding-left: 0.75rem;
    }

    .finding-medium {
        border-left: 4px solid #e3b341;
        padding-left: 0.75rem;
    }


    /* Small footer */

    .sat-footer {
        text-align: center;
        color: #737d8b;
        font-size: 0.75rem;
        padding-top: 2rem;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# HEADER
# ============================================================

status_class = (
    "status-online"
    if st.session_state.running
    else "status-offline"
)

status_text = (
    "● COLLECTING"
    if st.session_state.running
    else "● IDLE"
)

st.markdown(
    f"""
    <div class="sat-header">
        <div class="sat-title">🛡️ SAT-SA</div>
        <div class="sat-subtitle">
            Supervisory Analytics Tool for Offline SOC Assessment
        </div>
        <br>
        <span class="{status_class}">
            {status_text}
        </span>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## Evidence Sources")

    # --------------------------------------------------------
    # OFFLINE IMPORT
    # --------------------------------------------------------

    st.markdown("### Offline Evidence")

    upload = st.file_uploader(
        "Upload evidence",
        type=["csv", "json"],
        help="Import SOC evidence for offline analysis.",
    )

    if st.button(
        "Import & Analyze",
        disabled=upload is None,
        use_container_width=True,
    ):

        try:

            if upload.name.lower().endswith(".csv"):

                df = pd.read_csv(upload)

            else:

                raw = json.load(upload)

                if isinstance(raw, dict):
                    raw = raw.get("events", [raw])

                df = pd.DataFrame(raw)

            imported_ids = []

            for _, row in df.iterrows():

                event = normalize(
                    row.to_dict(),
                    f"Imported: {upload.name}",
                )

                event_id = insert_event(event)

                if event_id:
                    imported_ids.append(event_id)

            analyze_event_ids(imported_ids)

            audit(
                "Evidence import",
                f"{upload.name}: {len(imported_ids)} new events",
            )

            st.success(
                f"Imported {len(imported_ids)} new events."
            )

            time.sleep(0.5)

            st.rerun()

        except Exception as exc:

            st.error(
                f"Import failed: {exc}"
            )


    # --------------------------------------------------------
    # LIVE COLLECTION
    # --------------------------------------------------------

    st.divider()

    st.markdown("### Live Collection")

    collector_type = st.selectbox(
        "Collector",
        [
            "Demo Simulator",
            "Windows Event Log",
            "Linux Log File",
        ],
    )

    linux_path = ""

    if collector_type == "Linux Log File":

        linux_path = st.text_input(
            "Log file path",
            "/var/log/auth.log",
        )


    col_start, col_stop = st.columns(2)


    # START

    if col_start.button(
        "Start",
        use_container_width=True,
    ):

        try:

            if collector_type == "Demo Simulator":

                st.session_state.collector = DemoCollector()

            elif collector_type == "Windows Event Log":

                st.session_state.collector = (
                    WindowsEventCollector()
                )

            else:

                st.session_state.collector = (
                    LinuxFileCollector(linux_path)
                )

            st.session_state.running = True

            st.session_state.collector_name = (
                collector_type
            )

            audit(
                "Collector started",
                collector_type,
            )

            st.rerun()

        except Exception as exc:

            st.error(str(exc))


    # STOP

    if col_stop.button(
        "Stop",
        use_container_width=True,
    ):

        st.session_state.running = False

        st.session_state.collector = None

        st.session_state.collector_name = "None"

        audit(
            "Collector stopped"
        )

        st.rerun()


    # CLEAR

    if st.button(
        "Clear Local Evidence",
        use_container_width=True,
    ):

        clear_data()

        st.session_state.running = False

        st.session_state.collector = None

        st.session_state.collector_name = "None"

        audit(
            "Evidence cleared"
        )

        st.rerun()


    # --------------------------------------------------------
    # SYSTEM INFO
    # --------------------------------------------------------

    st.divider()

    st.markdown("### System")

    st.caption(
        f"Platform: {platform.system()}"
    )

    st.caption(
        f"Database: {DB_PATH}"
    )

    st.caption(
        "Mode: Local / Offline"
    )


# ============================================================
# LIVE COLLECTION LOOP
# ============================================================

if (
    st.session_state.running
    and st.session_state.collector
):

    try:

        event = (
            st.session_state.collector.collect()
        )

        if event:

            new_id = insert_event(event)

            if new_id:

                analyze_live_window()

                audit(
                    "Live event",
                    (
                        f"Event {new_id} "
                        f"from {event['source']}"
                    ),
                )

    except Exception as exc:

        st.error(
            f"Collector error: {exc}"
        )

    time.sleep(
        LIVE_INTERVAL_SECONDS
    )

    st.rerun()


# ============================================================
# LOAD DATA
# ============================================================

events = recent_events(100)

findings = get_findings()


# ============================================================
# SUMMARY METRICS
# ============================================================

total_events = count_events()

open_findings = sum(
    1
    for finding in findings
    if finding.get("status") == "Open"
)

high_findings = sum(
    1
    for finding in findings
    if finding.get("severity")
    in {"High", "Critical"}
)

reviewed_findings = sum(
    1
    for finding in findings
    if finding.get("status") == "Reviewed"
)


m1, m2, m3, m4 = st.columns(4)


with m1:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">
                EVENTS ANALYZED
            </div>
            <div class="metric-value">
                {total_events:,}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


with m2:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">
                OPEN FINDINGS
            </div>
            <div class="metric-value">
                {open_findings:,}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


with m3:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">
                HIGH / CRITICAL
            </div>
            <div class="metric-value">
                {high_findings:,}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


with m4:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">
                REVIEWED
            </div>
            <div class="metric-value">
                {reviewed_findings:,}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


st.write("")


# ============================================================
# TABS
# ============================================================

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "📡 Live Event Stream",
        "🔎 Findings & Evidence",
        "📊 Assessment Analytics",
        "⚙️ System Information",
    ]
)


# ============================================================
# TAB 1 — LIVE EVENTS
# ============================================================

with tab1:

    st.markdown(
        '<div class="section-title">Live Evidence Stream</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="section-description">
        Normalized evidence collected from live sources or imported
        assessment data.
        </div>
        """,
        unsafe_allow_html=True,
    )

    if events:

        event_df = pd.DataFrame(events)

        columns = [
            "id",
            "timestamp",
            "host",
            "source",
            "event_code",
            "level",
            "category",
            "username",
            "message",
        ]

        available_columns = [
            column
            for column in columns
            if column in event_df.columns
        ]

        st.dataframe(
            event_df[available_columns],
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info(
            "No evidence available. "
            "Start the Demo Simulator or import a CSV."
        )


# ============================================================
# TAB 2 — FINDINGS
# ============================================================

with tab2:

    st.markdown(
        '<div class="section-title">Explainable Findings</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="section-description">
        Every finding is linked to supporting evidence so that the
        assessor can validate the analytical result.
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not findings:

        st.info(
            "No findings have been generated yet."
        )

    for finding in findings:

        severity = finding.get(
            "severity",
            "Unknown",
        )

        title = finding.get(
            "title",
            "Unnamed Finding",
        )

        status = finding.get(
            "status",
            "Open",
        )

        label = (
            f"{severity} | {title} | {status}"
        )

        with st.expander(label):

            left, right = st.columns(2)

            with left:

                st.write(
                    "**Finding Type:**",
                    finding.get(
                        "finding_type",
                        "Unknown",
                    ),
                )

                st.write(
                    "**Severity:**",
                    severity,
                )

                st.write(
                    "**Status:**",
                    status,
                )

            with right:

                st.write(
                    "**Created:**",
                    finding.get(
                        "created_at",
                        "Unknown",
                    ),
                )

            st.divider()

            st.write(
                "**Analytical Rationale**"
            )

            st.info(
                finding.get(
                    "rationale",
                    "No rationale available.",
                )
            )

            try:

                evidence_ids = json.loads(
                    finding.get(
                        "evidence_ids",
                        "[]",
                    )
                )

            except Exception:

                evidence_ids = []

            evidence = events_by_ids(
                evidence_ids
            )

            st.write(
                f"**Supporting Evidence ({len(evidence)})**"
            )

            if evidence:

                evidence_df = pd.DataFrame(
                    evidence
                )

                st.dataframe(
                    evidence_df,
                    use_container_width=True,
                    hide_index=True,
                )

            else:

                st.warning(
                    "Supporting evidence is unavailable."
                )


            st.divider()

            b1, b2, b3 = st.columns(3)


            if b1.button(
                "✓ Mark Reviewed",
                key=f"review_{finding['id']}",
                use_container_width=True,
            ):

                set_finding_status(
                    finding["id"],
                    "Reviewed",
                )

                audit(
                    "Finding reviewed",
                    str(finding["id"]),
                )

                st.rerun()


            if b2.button(
                "⚠ False Positive",
                key=f"fp_{finding['id']}",
                use_container_width=True,
            ):

                set_finding_status(
                    finding["id"],
                    "False Positive",
                )

                audit(
                    "Finding marked false positive",
                    str(finding["id"]),
                )

                st.rerun()


            if b3.button(
                "↻ Reopen",
                key=f"reopen_{finding['id']}",
                use_container_width=True,
            ):

                set_finding_status(
                    finding["id"],
                    "Open",
                )

                audit(
                    "Finding reopened",
                    str(finding["id"]),
                )

                st.rerun()


# ============================================================
# TAB 3 — ASSESSMENT ANALYTICS
# ============================================================

with tab3:

    st.markdown(
        '<div class="section-title">Supervisory Assessment Analytics</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="section-description">
        Analytical views of collected evidence and detected
        supervisory patterns.
        </div>
        """,
        unsafe_allow_html=True,
    )


    if not events:

        st.info(
            "Charts will appear after evidence is collected."
        )

    else:

        df = pd.DataFrame(events)


        # ----------------------------------------------------
        # TIMESTAMP
        # ----------------------------------------------------

        if "timestamp" in df.columns:

            df["timestamp"] = pd.to_datetime(
                df["timestamp"],
                utc=True,
                errors="coerce",
            )

            df = df.dropna(
                subset=["timestamp"]
            )


        # ----------------------------------------------------
        # EVENT TIMELINE
        # ----------------------------------------------------

        if not df.empty:

            timeline = (
                df.set_index("timestamp")
                .resample("1min")
                .size()
                .rename("events")
            )

            st.subheader(
                "Event Activity"
            )

            st.line_chart(
                timeline,
                height=280,
                use_container_width=True,
            )

            st.caption(
                "Event volume over time"
            )


        # ----------------------------------------------------
        # SEVERITY
        # ----------------------------------------------------

        c1, c2 = st.columns(2)


        with c1:

            st.subheader(
                "Events by Severity"
            )

            severity_series = (
                df["level"]
                .fillna("UNKNOWN")
                .astype(str)
                .str.upper()
                .value_counts()
            )

            st.bar_chart(
                severity_series,
                height=280,
                use_container_width=True,
            )


        # ----------------------------------------------------
        # SOURCE
        # ----------------------------------------------------

        with c2:

            st.subheader(
                "Events by Source"
            )

            source_series = (
                df["source"]
                .fillna("Unknown")
                .astype(str)
                .value_counts()
            )

            st.bar_chart(
                source_series,
                height=280,
                use_container_width=True,
            )


        # ----------------------------------------------------
        # CATEGORY
        # ----------------------------------------------------

        c3, c4 = st.columns(2)


        with c3:

            st.subheader(
                "Events by Category"
            )

            category_series = (
                df["category"]
                .fillna("General")
                .astype(str)
                .value_counts()
            )

            st.bar_chart(
                category_series,
                height=280,
                use_container_width=True,
            )


        # ----------------------------------------------------
        # FINDING TYPES
        # ----------------------------------------------------

        with c4:

            st.subheader(
                "Findings by Type"
            )

            if findings:

                finding_df = pd.DataFrame(
                    findings
                )

                type_series = (
                    finding_df[
                        "finding_type"
                    ]
                    .fillna("Unknown")
                    .value_counts()
                )

                st.bar_chart(
                    type_series,
                    height=280,
                    use_container_width=True,
                )

            else:

                st.info(
                    "No findings available."
                )


        # ----------------------------------------------------
        # FINDING SEVERITY
        # ----------------------------------------------------

        if findings:

            c5, c6 = st.columns(2)


            with c5:

                st.subheader(
                    "Findings by Severity"
                )

                finding_df = pd.DataFrame(
                    findings
                )

                severity_series = (
                    finding_df[
                        "severity"
                    ]
                    .fillna("Unknown")
                    .value_counts()
                )

                st.bar_chart(
                    severity_series,
                    height=280,
                    use_container_width=True,
                )


            # ------------------------------------------------
            # REVIEW STATUS
            # ------------------------------------------------

            with c6:

                st.subheader(
                    "Review Status"
                )

                status_series = (
                    finding_df[
                        "status"
                    ]
                    .fillna("Unknown")
                    .value_counts()
                )

                st.bar_chart(
                    status_series,
                    height=280,
                    use_container_width=True,
                )


    # ========================================================
    # ASSESSMENT QUEUE
    # ========================================================

    st.divider()

    st.subheader(
        "Assessment Queue"
    )

    if findings:

        summary = pd.DataFrame(
            findings
        )

        columns = [
            "id",
            "finding_type",
            "severity",
            "title",
            "status",
            "created_at",
        ]

        available = [
            column
            for column in columns
            if column in summary.columns
        ]

        st.dataframe(
            summary[available],
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info(
            "Assessment queue is empty."
        )


# ============================================================
# TAB 4 — SYSTEM INFORMATION
# ============================================================

with tab4:

    st.markdown(
        '<div class="section-title">SAT-SA System Information</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="section-description">
        Operational information about the local supervisory
        analytics environment.
        </div>
        """,
        unsafe_allow_html=True,
    )


    info1, info2 = st.columns(2)


    with info1:

        st.markdown("### Runtime")

        st.write(
            "**Operating System:**",
            platform.system(),
        )

        st.write(
            "**OS Version:**",
            platform.release(),
        )

        st.write(
            "**Collector:**",
            st.session_state.collector_name,
        )

        st.write(
            "**Collection Status:**",
            "Running"
            if st.session_state.running
            else "Stopped",
        )


    with info2:

        st.markdown("### Storage")

        st.write(
            "**Database:**",
            str(DB_PATH),
        )

        st.write(
            "**Events Stored:**",
            f"{total_events:,}",
        )

        st.write(
            "**Findings Generated:**",
            f"{len(findings):,}",
        )

        st.write(
            "**Execution Mode:**",
            "Local / Offline",
        )


    st.divider()

    st.markdown("### Architecture")

    st.code(
        """
Evidence Sources
      ↓
CSV / JSON / Windows Event Log / Linux Logs
      ↓
Normalization & Evidence Storage
      ↓
SAT-SA Analytics Engine
      ↓
Finding Generation
      ↓
Evidence-backed Assessment
      ↓
Human Review
""",
        language="text",
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="sat-footer">
        SAT-SA • Offline Supervisory Analytics • Human-in-the-loop Assessment
    </div>
    """,
    unsafe_allow_html=True,
)