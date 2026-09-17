from datetime import datetime, timezone, timedelta
import hashlib

from sat_sa.db import events_by_ids, insert_finding


# ============================================================
# TIMESTAMP HANDLING
# ============================================================

def parse_ts(value):
    """
    Convert a timestamp into timezone-aware UTC.

    Handles:
    - ISO timestamps
    - Z timestamps
    - timezone-naive timestamps
    - pandas-compatible timestamps
    """

    try:
        dt = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    except ValueError:

        try:
            import pandas as pd

            dt = pd.to_datetime(
                value,
                utc=True
            ).to_pydatetime()

        except Exception:
            return datetime.now(timezone.utc)

    # If timestamp has no timezone, assume UTC.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


# ============================================================
# FINDING FINGERPRINT
# ============================================================

def _fingerprint(kind, ids):
    """
    Generate a unique fingerprint for a finding.

    This prevents the same live finding from being inserted
    repeatedly every time the dashboard refreshes.
    """

    value = (
        str(kind)
        + ":"
        + ",".join(
            map(str, sorted(ids))
        )
    )

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


# ============================================================
# FINDING CREATION
# ============================================================

def _finding(
    kind,
    severity,
    title,
    rationale,
    ids
):
    """
    Create a standardized SAT-SA finding.
    """

    return {
        "fingerprint": _fingerprint(
            kind,
            ids
        ),

        "created_at":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "finding_type": kind,

        "severity": severity,

        "title": title,

        "rationale": rationale,

        "evidence_ids": ids,
    }


# ============================================================
# ANALYZE IMPORTED EVENTS
# ============================================================

def analyze_event_ids(ids):
    """
    Analyze a specific set of imported event IDs.
    """

    if not ids:
        return []

    events = events_by_ids(ids)

    if not events:
        return []

    return analyze_events(events)


# ============================================================
# ANALYZE LIVE EVENTS
# ============================================================

def analyze_live_window(minutes=10):
    """
    Analyze events collected during the last N minutes.
    """

    from sat_sa.db import recent_events

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(minutes=minutes)
    )

    events = []

    for event in recent_events(1000):

        try:

            event_time = parse_ts(
                event.get("timestamp")
            )

            if event_time >= cutoff:
                events.append(event)

        except Exception:
            continue

    return analyze_events(events)


# ============================================================
# MAIN ANALYTICS ENGINE
# ============================================================

def analyze_events(events):
    """
    Run SAT-SA analytics against normalized evidence.
    """

    if not events:
        return []

    findings = []

    # ========================================================
    # 1. AUTHENTICATION FAILURE DETECTION
    # ========================================================

    failures = []

    for event in events:

        message = str(
            event.get(
                "message",
                ""
            )
        ).lower()

        event_code = str(
            event.get(
                "event_code",
                ""
            )
        )

        # Windows authentication failure IDs
        windows_auth_ids = {
            "4625",
            "4771",
            "4776"
        }

        if (
            "failed login" in message
            or "authentication failure" in message
            or "login failure" in message
            or "authentication failed" in message
            or "4625" in message
            or "4771" in message
            or event_code in windows_auth_ids
        ):

            failures.append(event)

    # Trigger after 5 or more authentication failures.
    if len(failures) >= 5:

        ids = [
            event["id"]
            for event in failures[-20:]
        ]

        findings.append(
            _finding(
                "Authentication Burst",
                "High",
                "Repeated authentication failures detected",
                (
                    f"{len(failures)} "
                    "authentication-failure events "
                    "were observed in the analyzed evidence."
                ),
                ids
            )
        )


    # ========================================================
    # 2. REPEATED EVENT PATTERN
    # ========================================================

    message_groups = {}

    for event in events:

        host = str(
            event.get(
                "host",
                "Unknown"
            )
        )

        message = str(
            event.get(
                "message",
                ""
            )
        ).strip()

        if not message:
            continue

        key = (
            host,
            message
        )

        if key not in message_groups:
            message_groups[key] = []

        message_groups[key].append(event)


    for (
        host,
        message
    ), group in message_groups.items():

        if len(group) >= 4:

            ids = [
                event["id"]
                for event in group
            ]

            findings.append(
                _finding(
                    "Repeated Pattern",
                    "Medium",
                    f"Repeated event pattern on {host}",
                    (
                        f"The same event message "
                        f"occurred {len(group)} times "
                        "for the same host."
                    ),
                    ids
                )
            )


    # ========================================================
    # 3. HIGH-SEVERITY / ERROR BURST
    # ========================================================
    #
    # IMPORTANT:
    #
    # The SAT-SA events table stores the normalized field:
    #
    #     level
    #
    # It does NOT store:
    #
    #     severity
    #
    # Therefore we ONLY use event.get("level").
    #
    # This is the section that previously caused:
    #
    # KeyError: 'severity'
    #
    # ========================================================

    severe = []

    for event in events:

        level = str(
            event.get(
                "level",
                ""
            )
        ).upper()

        if level in {
            "CRITICAL",
            "HIGH",
            "ERROR"
        }:

            severe.append(event)


    # Trigger after 6 or more severe events.
    if len(severe) >= 6:

        ids = [
            event["id"]
            for event in severe[-20:]
        ]

        findings.append(
            _finding(
                "High Severity Burst",
                "High",
                "High-severity event concentration detected",
                (
                    f"{len(severe)} high-severity "
                    "events were observed in "
                    "the analyzed evidence."
                ),
                ids
            )
        )


    # ========================================================
    # SAVE FINDINGS
    # ========================================================

    for finding in findings:

        try:
            insert_finding(finding)

        except Exception:
            # Prevent one database issue from crashing
            # the live collection loop.
            pass


    return findings