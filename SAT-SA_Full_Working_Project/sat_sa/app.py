
import sqlite3
from pathlib import Path
from datetime import datetime
import io
import json

import pandas as pd
import streamlit as st

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
except Exception:
    canvas = None


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "sat_sa.db"

DATA_DIR.mkdir(exist_ok=True)

st.set_page_config(
    page_title="SAT-SA",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# DATABASE
# ============================================================

def db():
    return sqlite3.connect(DB_PATH)


def init_db():
    con = db()
    cur = con.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS entities (
        entity_id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_code TEXT UNIQUE,
        name TEXT
    );

    CREATE TABLE IF NOT EXISTS assets (
        asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_code TEXT UNIQUE,
        entity_id INTEGER,
        FOREIGN KEY(entity_id) REFERENCES entities(entity_id)
    );

    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        entity_id INTEGER,
        asset_id INTEGER,
        timestamp TEXT,
        severity TEXT,
        category TEXT,
        status TEXT,
        closure_minutes INTEGER,
        escalation_recorded INTEGER,
        FOREIGN KEY(entity_id) REFERENCES entities(entity_id),
        FOREIGN KEY(asset_id) REFERENCES assets(asset_id)
    );

    CREATE TABLE IF NOT EXISTS cases (
        case_id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT,
        investigation_type TEXT,
        investigator TEXT,
        remediation_recorded INTEGER,
        root_cause TEXT,
        FOREIGN KEY(alert_id) REFERENCES alerts(alert_id)
    );

    CREATE TABLE IF NOT EXISTS escalations (
        escalation_id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT,
        recorded INTEGER,
        FOREIGN KEY(alert_id) REFERENCES alerts(alert_id)
    );

    CREATE TABLE IF NOT EXISTS findings (
        finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_code TEXT,
        finding_type TEXT,
        severity TEXT,
        score INTEGER,
        title TEXT,
        explanation TEXT,
        status TEXT DEFAULT 'Pending Review',
        created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS finding_evidence (
        finding_id INTEGER,
        alert_id TEXT,
        FOREIGN KEY(finding_id) REFERENCES findings(finding_id),
        FOREIGN KEY(alert_id) REFERENCES alerts(alert_id)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        actor TEXT,
        action TEXT,
        object_type TEXT,
        object_id TEXT,
        details TEXT
    );

    CREATE TABLE IF NOT EXISTS rule_versions (
        rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_name TEXT,
        version TEXT,
        description TEXT
    );

    CREATE TABLE IF NOT EXISTS model_versions (
        model_id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_name TEXT,
        version TEXT,
        description TEXT
    );
    """)

    # Default metadata
    cur.execute("""
        INSERT OR IGNORE INTO rule_versions
        (rule_name, version, description)
        VALUES (?, ?, ?)
    """, (
        "Execution Gap Detection",
        "1.0",
        "Detects unusually fast high-severity closures and missing escalation."
    ))

    cur.execute("""
        INSERT OR IGNORE INTO rule_versions
        (rule_name, version, description)
        VALUES (?, ?, ?)
    """, (
        "Negative Space Detection",
        "1.0",
        "Detects missing alert categories across monitored entities."
    ))

    cur.execute("""
        INSERT OR IGNORE INTO model_versions
        (model_name, version, description)
        VALUES (?, ?, ?)
    """, (
        "Peer Deviation Scoring",
        "1.0",
        "Prototype statistical peer-deviation scoring."
    ))

    con.commit()
    con.close()


init_db()


# ============================================================
# HELPERS
# ============================================================

def query(sql, params=()):
    con = db()
    df = pd.read_sql_query(sql, con, params=params)
    con.close()
    return df


def audit(action, object_type="", object_id="", details=""):
    con = db()
    con.execute("""
        INSERT INTO audit_log
        (timestamp, actor, action, object_type, object_id, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(timespec="seconds"),
        "SAT-SA",
        action,
        object_type,
        str(object_id),
        details
    ))
    con.commit()
    con.close()


def to_bool(value):
    """
    Converts common boolean representations to 0/1.

    Accepted:
        1, 0
        Yes, No
        True, False
        Y, N
        T, F
    """

    if pd.isna(value):
        return 0

    value = str(value).strip().lower()

    if value in ("1", "yes", "y", "true", "t"):
        return 1

    if value in ("0", "no", "n", "false", "f"):
        return 0

    raise ValueError(
        f"Invalid boolean value '{value}'. "
        f"Use Yes/No or 1/0."
    )


def to_int(value, default=0):
    if pd.isna(value) or str(value).strip() == "":
        return default

    try:
        return int(float(value))
    except Exception:
        raise ValueError(
            f"Invalid numeric value '{value}'."
        )


# ============================================================
# REQUIRED CSV SCHEMA
# ============================================================

REQUIRED_COLUMNS = [
    "alert_id",
    "asset_code",
    "closure_minutes",
    "entity_code",
    "escalation_recorded",
    "investigation_type",
    "investigator",
    "remediation_recorded",
    "root_cause",
    "status",
    "timestamp"
]


# ============================================================
# DATA GENERATOR
# ============================================================

def generate_demo_data():
    rows = [
        ["ALT-001","ENT-001","Alpha Finance","AST-001",
         "2026-09-01 09:12","Critical","Malware",5,
         "Closed","Yes","Standard IR","Analyst-01","No",
         "Pending review"],

        ["ALT-002","ENT-001","Alpha Finance","AST-002",
         "2026-09-01 10:25","High","Credential Abuse",9,
         "Closed","No","Template","Analyst-02","No",
         "Pending review"],

        ["ALT-003","ENT-001","Alpha Finance","AST-001",
         "2026-09-01 11:40","Medium","Phishing",45,
         "Closed","Yes","Standard IR","Analyst-01","Yes",
         "Closed"],

        ["ALT-004","ENT-001","Alpha Finance","AST-001",
         "2026-09-02 08:10","High","Malware",6,
         "Closed","No","Template","Analyst-02","No",
         "Pending review"],

        ["ALT-005","ENT-002","Beta Energy","AST-003",
         "2026-09-01 09:30","Critical","Malware",22,
         "Closed","Yes","Standard IR","Analyst-03","Yes",
         "Closed"],

        ["ALT-006","ENT-002","Beta Energy","AST-004",
         "2026-09-01 12:15","High","Credential Abuse",65,
         "Closed","Yes","Deep Investigation","Analyst-03","Yes",
         "Closed"],

        ["ALT-007","ENT-002","Beta Energy","AST-003",
         "2026-09-02 14:05","Medium","Phishing",55,
         "Closed","No","Standard IR","Analyst-04","Yes",
         "Closed"],

        ["ALT-008","ENT-002","Beta Energy","AST-004",
         "2026-09-03 09:45","High","Data Exfiltration",47,
         "Closed","Yes","Deep Investigation","Analyst-03","Yes",
         "Closed"],

        ["ALT-009","ENT-003","Gamma Telecom","AST-005",
         "2026-09-01 08:55","Critical","Malware",6,
         "Closed","No","Template","Analyst-05","No",
         "Pending review"],

        ["ALT-010","ENT-003","Gamma Telecom","AST-006",
         "2026-09-01 10:10","High","Credential Abuse",8,
         "Closed","No","Template","Analyst-05","No",
         "Pending review"],

        ["ALT-011","ENT-003","Gamma Telecom","AST-005",
         "2026-09-02 11:25","High","Phishing",9,
         "Closed","No","Template","Analyst-05","No",
         "Pending review"],

        ["ALT-012","ENT-003","Gamma Telecom","AST-006",
         "2026-09-03 16:20","Medium","Phishing",35,
         "Closed","No","Standard IR","Analyst-06","Yes",
         "Closed"],

        ["ALT-013","ENT-004","Delta Healthcare","AST-007",
         "2026-09-01 09:05","Critical","Malware",43,
         "Closed","Yes","Deep Investigation","Analyst-07","Yes",
         "Closed"],

        ["ALT-014","ENT-004","Delta Healthcare","AST-008",
         "2026-09-01 13:10","High","Credential Abuse",50,
         "Closed","Yes","Deep Investigation","Analyst-07","Yes",
         "Closed"],

        ["ALT-015","ENT-004","Delta Healthcare","AST-007",
         "2026-09-02 10:30","High","Data Exfiltration",None,
         "Open","Yes","Deep Investigation","Analyst-07","No",
         "In progress"]
    ]

    columns = [
        "alert_id",
        "entity_code",
        "entity_name",
        "asset_code",
        "timestamp",
        "severity",
        "category",
        "closure_minutes",
        "status",
        "escalation_recorded",
        "investigation_type",
        "investigator",
        "remediation_recorded",
        "root_cause"
    ]

    return pd.DataFrame(rows, columns=columns)


# ============================================================
# LOAD DATA
# ============================================================

def load(df):
    missing = [
        c for c in REQUIRED_COLUMNS
        if c not in df.columns
    ]

    if missing:
        return False, (
            "Missing columns: " +
            ", ".join(missing)
        ), 0

    con = db()
    cur = con.cursor()

    inserted = 0

    try:

        for _, r in df.iterrows():

            # --------------------------------------------
            # Basic conversions
            # --------------------------------------------

            entity_code = str(r.entity_code).strip()
            asset_code = str(r.asset_code).strip()
            alert_id = str(r.alert_id).strip()

            if not entity_code or not asset_code or not alert_id:
                continue

            escalation = to_bool(
                r.escalation_recorded
            )

            remediation = to_bool(
                r.remediation_recorded
            )

            closure = to_int(
                r.closure_minutes,
                default=0
            )

            # --------------------------------------------
            # Entity
            # --------------------------------------------

            entity_name = (
                str(r.entity_name)
                if "entity_name" in df.columns
                and not pd.isna(r.entity_name)
                else entity_code
            )

            cur.execute("""
                INSERT OR IGNORE INTO entities
                (entity_code, name)
                VALUES (?, ?)
            """, (
                entity_code,
                entity_name
            ))

            eid = cur.execute("""
                SELECT entity_id
                FROM entities
                WHERE entity_code = ?
            """, (
                entity_code,
            )).fetchone()[0]

            # --------------------------------------------
            # Asset
            # --------------------------------------------

            cur.execute("""
                INSERT OR IGNORE INTO assets
                (asset_code, entity_id)
                VALUES (?, ?)
            """, (
                asset_code,
                eid
            ))

            aid = cur.execute("""
                SELECT asset_id
                FROM assets
                WHERE asset_code = ?
            """, (
                asset_code,
            )).fetchone()[0]

            # --------------------------------------------
            # Alert
            # --------------------------------------------

            cur.execute("""
                INSERT OR REPLACE INTO alerts
                (
                    alert_id,
                    entity_id,
                    asset_id,
                    timestamp,
                    severity,
                    category,
                    status,
                    closure_minutes,
                    escalation_recorded
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_id,
                eid,
                aid,
                str(r.timestamp),
                str(r.severity),
                str(r.category)
                if "category" in df.columns
                else "Unknown",
                str(r.status),
                closure,
                escalation
            ))

            # --------------------------------------------
            # Case
            # --------------------------------------------

            cur.execute("""
                DELETE FROM cases
                WHERE alert_id = ?
            """, (alert_id,))

            cur.execute("""
                INSERT INTO cases
                (
                    alert_id,
                    investigation_type,
                    investigator,
                    remediation_recorded,
                    root_cause
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                alert_id,
                str(r.investigation_type),
                str(r.investigator),
                remediation,
                str(r.root_cause)
            ))

            # --------------------------------------------
            # Escalation
            # --------------------------------------------

            cur.execute("""
                DELETE FROM escalations
                WHERE alert_id = ?
            """, (alert_id,))

            cur.execute("""
                INSERT INTO escalations
                (
                    alert_id,
                    recorded
                )
                VALUES (?, ?)
            """, (
                alert_id,
                escalation
            ))

            inserted += 1

        con.commit()

    except Exception as e:

        con.rollback()
        con.close()

        return False, str(e), inserted

    con.close()

    audit(
        "Data Import",
        "dataset",
        "",
        f"Imported {inserted} records."
    )

    analyze()

    return True, "", inserted


# ============================================================
# ANALYTICS ENGINE
# ============================================================

def analyze():

    con = db()
    cur = con.cursor()

    cur.execute("DELETE FROM finding_evidence")
    cur.execute("DELETE FROM findings")

    alerts = pd.read_sql_query("""
        SELECT
            a.*,
            e.entity_code,
            e.name AS entity_name,
            s.asset_code
        FROM alerts a
        JOIN entities e
            ON a.entity_id = e.entity_id
        JOIN assets s
            ON a.asset_id = s.asset_id
    """, con)

    cases = pd.read_sql_query("""
        SELECT *
        FROM cases
    """, con)

    if alerts.empty:
        con.commit()
        con.close()
        return

    cases_map = cases.set_index(
        "alert_id"
    ).to_dict("index")

    # ========================================================
    # 1. EXECUTION GAP DETECTION
    # ========================================================

    for _, r in alerts.iterrows():

        severity = str(r.severity).lower()

        high_severity = severity in (
            "critical",
            "high"
        )

        fast_closure = (
            r.status.lower() == "closed"
            and r.closure_minutes <= 15
        )

        no_escalation = (
            int(r.escalation_recorded) == 0
        )

        if high_severity and fast_closure and no_escalation:

            score = 92 if severity == "critical" else 88

            title = (
                "Rapid high-severity closure without escalation"
            )

            explanation = (
                f"{r.alert_id} is a {r.severity}-severity "
                f"{r.category} alert closed in "
                f"{r.closure_minutes} minutes without "
                f"recorded escalation. This pattern is "
                f"flagged for supervisory review."
            )

            cur.execute("""
                INSERT INTO findings
                (
                    entity_code,
                    finding_type,
                    severity,
                    score,
                    title,
                    explanation,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.entity_code,
                "Execution Gap",
                r.severity,
                score,
                title,
                explanation,
                "Pending Review",
                datetime.now().isoformat(timespec="seconds")
            ))

            fid = cur.lastrowid

            cur.execute("""
                INSERT INTO finding_evidence
                VALUES (?, ?)
            """, (
                fid,
                r.alert_id
            ))

    # ========================================================
    # 2. TEMPLATE-LIKE INVESTIGATION
    # ========================================================

    for _, r in alerts.iterrows():

        case = cases_map.get(
            r.alert_id,
            {}
        )

        investigation = str(
            case.get(
                "investigation_type",
                ""
            )
        ).lower()

        severity = str(
            r.severity
        ).lower()

        if (
            investigation == "template"
            and severity in ("high", "critical")
        ):

            cur.execute("""
                INSERT INTO findings
                (
                    entity_code,
                    finding_type,
                    severity,
                    score,
                    title,
                    explanation,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.entity_code,
                "Investigation Quality",
                r.severity,
                74,
                "Template-like investigation on high-severity alert",
                (
                    f"{r.alert_id} uses a template-like "
                    f"investigation classification for a "
                    f"{r.severity}-severity alert. Review "
                    f"the investigation depth and evidence."
                ),
                "Pending Review",
                datetime.now().isoformat(timespec="seconds")
            ))

            fid = cur.lastrowid

            cur.execute("""
                INSERT INTO finding_evidence
                VALUES (?, ?)
            """, (
                fid,
                r.alert_id
            ))

    # ========================================================
    # 3. MISSING REMEDIATION
    # ========================================================

    for _, r in alerts.iterrows():

        case = cases_map.get(
            r.alert_id,
            {}
        )

        remediation = int(
            case.get(
                "remediation_recorded",
                0
            )
        )

        severity = str(
            r.severity
        ).lower()

        if (
            severity in ("high", "critical")
            and r.status.lower() == "closed"
            and remediation == 0
        ):

            cur.execute("""
                INSERT INTO findings
                (
                    entity_code,
                    finding_type,
                    severity,
                    score,
                    title,
                    explanation,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.entity_code,
                "Remediation Gap",
                r.severity,
                82,
                "Closed high-severity alert without remediation evidence",
                (
                    f"{r.alert_id} was closed without recorded "
                    f"remediation evidence. Supervisory review "
                    f"is recommended."
                ),
                "Pending Review",
                datetime.now().isoformat(timespec="seconds")
            ))

            fid = cur.lastrowid

            cur.execute("""
                INSERT INTO finding_evidence
                VALUES (?, ?)
            """, (
                fid,
                r.alert_id
            ))

    # ========================================================
    # 4. REPEATED FAST CLOSURE PATTERN
    # ========================================================

    grouped = alerts[
        alerts["closure_minutes"] <= 15
    ].groupby(
        ["entity_code", "category"]
    ).size()

    for (entity, category), count in grouped.items():

        if count >= 2:

            subset = alerts[
                (alerts.entity_code == entity) &
                (alerts.category == category) &
                (alerts.closure_minutes <= 15)
            ]

            for _, r in subset.iterrows():

                cur.execute("""
                    INSERT INTO findings
                    (
                        entity_code,
                        finding_type,
                        severity,
                        score,
                        title,
                        explanation,
                        status,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entity,
                    "Repeated Pattern",
                    r.severity,
                    78,
                    "Repeated rapid-closure pattern",
                    (
                        f"{count} {category} alerts for "
                        f"{entity} were closed within 15 minutes. "
                        f"The repeated pattern may warrant "
                        f"manual review."
                    ),
                    "Pending Review",
                    datetime.now().isoformat(timespec="seconds")
                ))

                fid = cur.lastrowid

                cur.execute("""
                    INSERT INTO finding_evidence
                    VALUES (?, ?)
                """, (
                    fid,
                    r.alert_id
                ))

    # ========================================================
    # 5. NEGATIVE SPACE DETECTION
    # ========================================================

    categories = set(
        alerts.category.dropna()
    )

    entity_categories = (
        alerts.groupby("entity_code")["category"]
        .apply(set)
        .to_dict()
    )

    for entity, present in entity_categories.items():

        missing_categories = (
            categories - present
        )

        for category in missing_categories:

            cur.execute("""
                INSERT INTO findings
                (
                    entity_code,
                    finding_type,
                    severity,
                    score,
                    title,
                    explanation,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entity,
                "Negative Space",
                "Medium",
                68,
                "Missing expected alert category",
                (
                    f"{entity} has no recorded alerts for "
                    f"the '{category}' category within the "
                    f"loaded observation period. This may "
                    f"represent a coverage gap or genuinely "
                    f"low activity and requires contextual review."
                ),
                "Pending Review",
                datetime.now().isoformat(timespec="seconds")
            ))

    con.commit()
    con.close()

    audit(
        "Analytics Run",
        "analytics",
        "",
        "Execution-gap, investigation, remediation, "
        "repeated-pattern and negative-space rules executed."
    )


# ============================================================
# RESET DATABASE
# ============================================================

def reset_demo():

    con = db()
    cur = con.cursor()

    for table in [
        "finding_evidence",
        "findings",
        "escalations",
        "cases",
        "alerts",
        "assets",
        "entities"
    ]:
        cur.execute(
            f"DELETE FROM {table}"
        )

    con.commit()
    con.close()

    audit(
        "Dataset Reset",
        "dataset",
        "",
        "Operational dataset reset."
    )


# ============================================================
# EXPORT FUNCTIONS
# ============================================================

def findings_df():

    return query("""
        SELECT
            finding_id,
            entity_code,
            finding_type,
            severity,
            score,
            title,
            explanation,
            status,
            created_at
        FROM findings
        ORDER BY score DESC
    """)


def export_pdf(df):

    if canvas is None:
        return None

    buffer = io.BytesIO()

    pdf = canvas.Canvas(
        buffer,
        pagesize=A4
    )

    width, height = A4

    pdf.setFont(
        "Helvetica-Bold",
        16
    )

    pdf.drawString(
        40,
        height - 50,
        "SAT-SA Supervisory Analytics Report"
    )

    pdf.setFont(
        "Helvetica",
        9
    )

    y = height - 80

    for _, row in df.head(35).iterrows():

        text = (
            f"{row.finding_id} | "
            f"{row.entity_code} | "
            f"{row.severity} | "
            f"{row.score} | "
            f"{row.title}"
        )

        pdf.drawString(
            40,
            y,
            text[:120]
        )

        y -= 16

        if y < 40:

            pdf.showPage()

            pdf.setFont(
                "Helvetica",
                9
            )

            y = height - 50

    pdf.save()

    buffer.seek(0)

    return buffer


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🛡️ SAT-SA")

st.sidebar.caption(
    "Offline Supervisory Analytics"
)

st.sidebar.divider()

if st.sidebar.button(
    "Load / Reset Demo Dataset",
    use_container_width=True
):

    reset_demo()

    demo = generate_demo_data()

    load(demo)

    st.session_state.msg = (
        "Demo dataset loaded successfully."
    )

    st.rerun()


uploaded = st.sidebar.file_uploader(
    "Import CSV Evidence",
    type=["csv"]
)

if uploaded is not None:

    if st.sidebar.button(
        "Import Uploaded CSV",
        use_container_width=True
    ):

        try:

            df_upload = pd.read_csv(
                uploaded
            )

            ok, msg, n = load(
                df_upload
            )

            if ok:

                st.session_state.msg = (
                    f"Imported {n} records successfully."
                )

            else:

                st.session_state.msg = (
                    "QA failed: " + msg
                )

            st.rerun()

        except Exception as e:

            st.session_state.msg = (
                "Import failed: " + str(e)
            )

            st.rerun()


st.sidebar.divider()

st.sidebar.info(
    f"Local SQLite database:\n{DB_PATH}"
)


# ============================================================
# HEADER
# ============================================================

st.title(
    "🛡️ SAT-SA — Supervisory Analytics Tool"
)

st.caption(
    "Offline, air-gapped supervisory analytics "
    "for SOC evidence review"
)

st.warning(
    "DEMONSTRATION PROTOTYPE — synthetic evidence only. "
    "No production NCIIPC/CSE data is included."
)


if "msg" in st.session_state:

    st.success(
        st.session_state.msg
    )

    del st.session_state.msg


# ============================================================
# NAVIGATION
# ============================================================

tabs = st.tabs([
    "Executive Dashboard",
    "Findings & Evidence",
    "Peer Analytics",
    "Data & QA",
    "Database",
    "Reports & Audit"
])


# ============================================================
# DASHBOARD
# ============================================================

with tabs[0]:

    alerts = query("""
        SELECT *
        FROM alerts
    """)

    findings = findings_df()

    entities = query("""
        SELECT *
        FROM entities
    """)

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Entities",
        len(entities)
    )

    col2.metric(
        "Alerts",
        len(alerts)
    )

    col3.metric(
        "Findings",
        len(findings)
    )

    high = len(
        findings[
            findings.severity.isin(
                ["High", "Critical"]
            )
        ]
    )

    col4.metric(
        "High/Critical Findings",
        high
    )

    st.divider()

    if not findings.empty:

        c1, c2 = st.columns(2)

        with c1:

            st.subheader(
                "Findings by Type"
            )

            st.bar_chart(
                findings[
                    "finding_type"
                ].value_counts()
            )

        with c2:

            st.subheader(
                "Findings by Entity"
            )

            st.bar_chart(
                findings[
                    "entity_code"
                ].value_counts()
            )

        st.subheader(
            "Priority Review Queue"
        )

        st.dataframe(
            findings[
                [
                    "finding_id",
                    "entity_code",
                    "finding_type",
                    "severity",
                    "score",
                    "title",
                    "status"
                ]
            ].head(15),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No findings yet. Load the demo dataset "
            "or import a CSV."
        )


# ============================================================
# FINDINGS
# ============================================================

with tabs[1]:

    findings = findings_df()

    if findings.empty:

        st.info(
            "No findings available."
        )

    else:

        st.subheader(
            "Actionable Review Queue"
        )

        selected = st.selectbox(
            "Select finding",
            findings.finding_id.tolist()
        )

        row = findings[
            findings.finding_id == selected
        ].iloc[0]

        st.markdown(
            f"### {row.title}"
        )

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Entity",
            row.entity_code
        )

        c2.metric(
            "Severity",
            row.severity
        )

        c3.metric(
            "Priority Score",
            row.score
        )

        c4.metric(
            "Status",
            row.status
        )

        st.write(
            row.explanation
        )

        st.subheader(
            "Supporting Evidence"
        )

        evidence = query("""
            SELECT
                a.alert_id,
                e.entity_code,
                s.asset_code,
                a.timestamp,
                a.severity,
                a.category,
                a.status,
                a.closure_minutes,
                a.escalation_recorded,
                c.investigation_type,
                c.investigator,
                c.remediation_recorded,
                c.root_cause
            FROM finding_evidence fe
            JOIN alerts a
                ON fe.alert_id = a.alert_id
            JOIN entities e
                ON a.entity_id = e.entity_id
            JOIN assets s
                ON a.asset_id = s.asset_id
            LEFT JOIN cases c
                ON a.alert_id = c.alert_id
            WHERE fe.finding_id = ?
        """, (
            int(selected),
        ))

        st.dataframe(
            evidence,
            use_container_width=True,
            hide_index=True
        )

        new_status = st.selectbox(
            "Update review status",
            [
                "Pending Review",
                "Under Review",
                "Accepted",
                "Rejected",
                "Closed"
            ],
            index=[
                "Pending Review",
                "Under Review",
                "Accepted",
                "Rejected",
                "Closed"
            ].index(row.status)
        )

        if st.button(
            "Save Finding Status"
        ):

            con = db()

            con.execute("""
                UPDATE findings
                SET status = ?
                WHERE finding_id = ?
            """, (
                new_status,
                int(selected)
            ))

            con.commit()
            con.close()

            audit(
                "Finding Status Updated",
                "finding",
                selected,
                new_status
            )

            st.success(
                "Finding status updated."
            )

            st.rerun()


# ============================================================
# PEER ANALYTICS
# ============================================================

with tabs[2]:

    st.subheader(
        "Peer Analytics"
    )

    alerts = query("""
        SELECT
            a.*,
            e.entity_code,
            e.name AS entity_name
        FROM alerts a
        JOIN entities e
            ON a.entity_id = e.entity_id
    """)

    if alerts.empty:

        st.info(
            "Load data to perform peer analysis."
        )

    else:

        peer = alerts.groupby(
            "entity_code"
        ).agg(
            alerts=("alert_id", "count"),
            avg_closure=("closure_minutes", "mean"),
            escalations=("escalation_recorded", "sum")
        ).reset_index()

        peer["escalation_rate"] = (
            peer["escalations"] /
            peer["alerts"] * 100
        ).round(1)

        st.dataframe(
            peer,
            use_container_width=True,
            hide_index=True
        )

        st.subheader(
            "Average Closure Time by Entity"
        )

        st.bar_chart(
            peer.set_index(
                "entity_code"
            )["avg_closure"]
        )

        st.subheader(
            "Escalation Rate by Entity"
        )

        st.bar_chart(
            peer.set_index(
                "entity_code"
            )["escalation_rate"]
        )

        st.caption(
            "Peer metrics are descriptive prototype analytics "
            "and are not official NCIIPC risk scores."
        )


# ============================================================
# DATA & QA
# ============================================================

with tabs[3]:

    st.subheader(
        "Data & Quality Assurance"
    )

    alerts = query("""
        SELECT
            a.alert_id,
            e.entity_code,
            e.name AS entity_name,
            s.asset_code,
            a.timestamp,
            a.severity,
            a.category,
            a.status,
            a.closure_minutes,
            a.escalation_recorded
        FROM alerts a
        JOIN entities e
            ON a.entity_id = e.entity_id
        JOIN assets s
            ON a.asset_id = s.asset_id
    """)

    if alerts.empty:

        st.info(
            "No data loaded."
        )

    else:

        st.metric(
            "Records Loaded",
            len(alerts)
        )

        missing = alerts.isna().sum()

        st.subheader(
            "Missing Values"
        )

        st.dataframe(
            missing.rename(
                "missing_values"
            ),
            use_container_width=True
        )

        duplicates = alerts.alert_id.duplicated().sum()

        st.metric(
            "Duplicate Alert IDs",
            int(duplicates)
        )

        st.subheader(
            "Loaded Evidence"
        )

        st.dataframe(
            alerts,
            use_container_width=True,
            hide_index=True
        )


# ============================================================
# DATABASE
# ============================================================

with tabs[4]:

    st.subheader(
        "Database Explorer"
    )

    tables = [
        "entities",
        "assets",
        "alerts",
        "cases",
        "escalations",
        "findings",
        "finding_evidence",
        "audit_log",
        "rule_versions",
        "model_versions"
    ]

    selected_table = st.selectbox(
        "Select database table",
        tables
    )

    table_df = query(
        f"SELECT * FROM {selected_table}"
    )

    st.dataframe(
        table_df,
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# REPORTS & AUDIT
# ============================================================

with tabs[5]:

    st.subheader(
        "Reports & Audit"
    )

    findings = findings_df()

    if findings.empty:

        st.info(
            "No findings available for export."
        )

    else:

        csv_data = findings.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "Download Findings CSV",
            csv_data,
            "sat_sa_findings.csv",
            "text/csv"
        )

        json_data = json.dumps(
            findings.to_dict(
                orient="records"
            ),
            indent=2,
            default=str
        ).encode("utf-8")

        st.download_button(
            "Download Findings JSON",
            json_data,
            "sat_sa_findings.json",
            "application/json"
        )

        excel_buffer = io.BytesIO()

        with pd.ExcelWriter(
            excel_buffer,
            engine="openpyxl"
        ) as writer:

            findings.to_excel(
                writer,
                index=False,
                sheet_name="Findings"
            )

        st.download_button(
            "Download Findings Excel",
            excel_buffer.getvalue(),
            "sat_sa_findings.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

        pdf_data = export_pdf(
            findings
        )

        if pdf_data:

            st.download_button(
                "Download Findings PDF",
                pdf_data,
                "sat_sa_findings.pdf",
                "application/pdf"
            )

    st.divider()

    st.subheader(
        "Audit Log"
    )

    audit_df = query("""
        SELECT *
        FROM audit_log
        ORDER BY audit_id DESC
    """)

    st.dataframe(
        audit_df,
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "SAT-SA v1.0.0 | Academic / Proof-of-Concept Prototype | "
    "Offline & Air-Gapped Design"
)
