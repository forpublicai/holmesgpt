import re
from typing import Dict, List

from holmes.plugins.toolsets.kubernetes_fast.models import Severity
from holmes.plugins.toolsets.kubernetes_logs_fast.models import (
    BehavioralFinding,
    ParsedLogEntry,
)

_RETRY_RE = re.compile(
    r"\b(?:retrying|retry\s+attempt|back-?off|reconnecting|reconnect\s+attempt|attempt\s+\d+\s+of\s+\d+)\b",
    re.IGNORECASE,
)
_AUTH_FAIL_RE = re.compile(
    r"\b(?:authentication\s+failed|authorization\s+failed|invalid\s+credentials|invalid\s+token|"
    r"unauthorized|401\s+unauthorized|403\s+forbidden|access\s+denied)\b",
    re.IGNORECASE,
)
_HEALTHY_STATE_RE = re.compile(
    r"\b(?:connected\s+to|connection\s+established|marked\s+healthy|readiness\s+probe\s+succeeded|became\s+ready)\b",
    re.IGNORECASE,
)
_UNHEALTHY_STATE_RE = re.compile(
    r"\b(?:disconnected\s+from|connection\s+lost|marked\s+unhealthy|probe\s+failed|readiness\s+failed|liveness\s+failed)\b",
    re.IGNORECASE,
)
_STARTUP_RE = re.compile(
    r"\b(?:starting\s+|server\s+started|listening\s+on|application\s+initialized|booting)\b",
    re.IGNORECASE,
)
_ROLLBACK_RE = re.compile(
    r"\b(?:transaction\s+rolled\s+back|rolling\s+back\s+transaction|rollback\s+completed|aborted\s+transaction)\b",
    re.IGNORECASE,
)


def detect_behavioral_anomalies(
    namespace: str,
    workload: str,
    pod: str,
    entries: List[ParsedLogEntry],
) -> List[BehavioralFinding]:
    """Analyze sequences of log entries per container for suspicious behavioural patterns (Section C)."""
    findings: List[BehavioralFinding] = []
    if not entries:
        return findings

    by_container: Dict[str, List[ParsedLogEntry]] = {}
    for e in entries:
        by_container.setdefault(e.container, []).append(e)

    for container, c_entries in by_container.items():
        retry_count = 0
        auth_fail_count = 0
        rollback_count = 0
        flaps = 0
        last_state: str = ""
        first_retry_ts = None
        last_retry_ts = None

        for entry in c_entries:
            txt = entry.content
            if _RETRY_RE.search(txt):
                retry_count += 1
                if first_retry_ts is None:
                    first_retry_ts = entry.timestamp_str
                last_retry_ts = entry.timestamp_str

            if _AUTH_FAIL_RE.search(txt):
                auth_fail_count += 1

            if _ROLLBACK_RE.search(txt):
                rollback_count += 1

            if _HEALTHY_STATE_RE.search(txt):
                if last_state == "down":
                    flaps += 1
                last_state = "up"
            elif _UNHEALTHY_STATE_RE.search(txt):
                if last_state == "up":
                    flaps += 1
                last_state = "down"

        # 1. Rapid Retry / Backoff Loop
        if retry_count >= 8:
            findings.append(
                BehavioralFinding(
                    id="BEHAV-001",
                    severity=Severity.HIGH if retry_count >= 20 else Severity.MEDIUM,
                    pattern="Repeated Retry / Backoff Loop",
                    namespace=namespace,
                    workload=workload,
                    pod=pod,
                    container=container,
                    description=(
                        f"Container '{container}' emitted {retry_count} retry/reconnection/backoff messages."
                    ),
                    evidence={
                        "retryCount": retry_count,
                        "firstSeen": first_retry_ts,
                        "lastSeen": last_retry_ts,
                    },
                )
            )

        # 2. Connection / Health State Flapping
        if flaps >= 3:
            findings.append(
                BehavioralFinding(
                    id="BEHAV-002",
                    severity=Severity.HIGH,
                    pattern="Connection or Health State Flapping",
                    namespace=namespace,
                    workload=workload,
                    pod=pod,
                    container=container,
                    description=(
                        f"Container '{container}' alternated between healthy/connected and "
                        f"unhealthy/disconnected states {flaps} times."
                    ),
                    evidence={"stateTransitions": flaps},
                )
            )

        # 3. Authentication Failure Spike
        if auth_fail_count >= 5:
            findings.append(
                BehavioralFinding(
                    id="BEHAV-003",
                    severity=Severity.HIGH,
                    pattern="Authentication / Authorization Failure Spike",
                    namespace=namespace,
                    workload=workload,
                    pod=pod,
                    container=container,
                    description=(
                        f"Container '{container}' logged {auth_fail_count} authentication/authorization failures."
                    ),
                    evidence={"authFailureCount": auth_fail_count},
                )
            )

        # 4. Startup Followed Immediately by Exit (in previous terminated container logs)
        prev_entries = [e for e in c_entries if e.source == "previous"]
        if 0 < len(prev_entries) <= 15 and any(
            _STARTUP_RE.search(e.content) for e in prev_entries
        ):
            findings.append(
                BehavioralFinding(
                    id="BEHAV-004",
                    severity=Severity.HIGH,
                    pattern="Application Starts and Immediately Exits",
                    namespace=namespace,
                    workload=workload,
                    pod=pod,
                    container=container,
                    description=(
                        f"Previous instance of container '{container}' logged startup and exited "
                        f"after only {len(prev_entries)} log lines."
                    ),
                    evidence={
                        "previousContainerLines": len(prev_entries),
                        "lastLine": prev_entries[-1].content[:250],
                    },
                )
            )

        # 5. Repeated Transaction Rollbacks
        if rollback_count >= 2:
            findings.append(
                BehavioralFinding(
                    id="BEHAV-005",
                    severity=Severity.MEDIUM,
                    pattern="Repeated Transaction Rollbacks",
                    namespace=namespace,
                    workload=workload,
                    pod=pod,
                    container=container,
                    description=(
                        f"Container '{container}' logged {rollback_count} transaction rollback events."
                    ),
                    evidence={"rollbackCount": rollback_count},
                )
            )

    return findings

