from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from pydantic import Field

from holmes.plugins.toolsets.kubernetes_fast.models import SEVERITY_ORDER, Severity
from holmes.utils.pydantic_utils import ToolsetConfig


class LogsFastConfig(ToolsetConfig):
    """Configuration for the Kubernetes Fast Log Analysis Engine (`kubernetes/logs_fast`)."""

    lines_per_container: int = Field(
        default=500,
        title="Max Lines Per Container",
        description="Maximum tail log lines fetched per container.",
    )
    lines_per_pod: int = Field(
        default=1500,
        title="Max Lines Per Pod",
        description="Maximum total log lines examined per Pod across its containers.",
    )
    lines_per_namespace: int = Field(
        default=10000,
        title="Max Lines Per Namespace",
        description="Maximum total log lines examined per namespace.",
    )
    total_lines_per_scan: int = Field(
        default=30000,
        title="Max Total Lines Per Scan",
        description="Hard limit on total log lines examined across a single scan.",
    )
    max_log_size_mb: int = Field(
        default=20,
        title="Max Log Size (MB)",
        description="Maximum cumulative log payload size in MB per scan.",
    )
    since_seconds: int = Field(
        default=3600,
        title="Historical Window (seconds)",
        description="Retrieve logs emitted within this many seconds (default 3600 = 1 hour).",
    )
    concurrent_workers: int = Field(
        default=8,
        title="Concurrent Collection Workers",
        description="Number of parallel worker threads for fetching container logs.",
    )
    include_previous_on_restart: bool = Field(
        default=True,
        title="Include Previous Container Logs",
        description="Fetch --previous terminated container logs when restartCount > 0 (or in single-pod mode).",
    )
    include_init_containers: bool = Field(
        default=True,
        title="Include Init Container Logs",
        description="Inspect init container logs in addition to app containers.",
    )
    include_warnings: bool = Field(
        default=True,
        title="Include Warning Rules",
        description="Include medium/warning severity rules (WARN, retry, backoff, timeout).",
    )
    enabled_languages: List[str] = Field(
        default_factory=lambda: ["java", "python", "nodejs", "go", "dotnet"],
        title="Enabled Language Pattern Libraries",
        description="Language-specific runtime exception libraries to enable.",
    )
    disabled_rule_ids: List[str] = Field(
        default_factory=list,
        title="Disabled Rule IDs",
        description="List of built-in rule IDs (e.g. ['LOG-WARN-001']) to disable.",
    )
    disabled_categories: List[str] = Field(
        default_factory=list,
        title="Disabled Categories",
        description="List of rule categories (e.g. ['warning']) to disable.",
    )
    custom_rules_file: Optional[str] = Field(
        default=None,
        title="Custom Rules YAML File Path",
        description="Optional filesystem path to a YAML file containing additional log rules.",
    )
    custom_rules: List[Dict[str, Any]] = Field(
        default_factory=list,
        title="Inline Custom Rules",
        description="Optional inline list of rule dictionaries to append to the built-in library.",
    )
    custom_exclude_patterns: List[str] = Field(
        default_factory=list,
        title="Custom False-Positive Exclude Patterns",
        description="Additional substrings or regexes that should be ignored as benign.",
    )
    max_findings_per_pod: int = Field(
        default=15,
        title="Max Findings Per Pod",
        description="Maximum deduplicated findings returned per Pod.",
    )
    max_total_findings: int = Field(
        default=40,
        title="Max Total Findings Per Scan",
        description="Maximum deduplicated findings returned in a single tool response.",
    )
    max_pods_per_sweep: int = Field(
        default=30,
        title="Max Pods Per Sweep",
        description="Maximum Pods to scrape when sweeping a namespace or cluster (unhealthy/restarting Pods are prioritized first).",
    )


@dataclass
class ParsedLogEntry:
    content: str
    container: str
    source: str  # "current", "previous", or "init"
    timestamp_str: Optional[str] = None
    timestamp_ms: Optional[int] = None
    is_json: bool = False
    json_level: Optional[str] = None
    json_message: Optional[str] = None
    json_error: Optional[str] = None
    json_error_code: Optional[str] = None
    is_benign_json: bool = False


@dataclass
class LogRule:
    id: str
    name: str
    category: str
    severity: Severity
    patterns: List[str]
    match_mode: str = "any"  # "any", "all", "regex"
    case_insensitive: bool = True
    enabled: bool = True
    language: Optional[str] = None
    exclude_patterns: List[str] = field(default_factory=list)
    min_occurrences: int = 1
    description: str = ""
    recommendation: str = ""


@dataclass
class LogFinding:
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    namespace: str
    workload: str
    pod: str
    container: str
    source: str
    matched_pattern: str
    sample_log: str
    occurrences: int = 1
    first_timestamp: Optional[str] = None
    last_timestamp: Optional[str] = None
    description: str = ""
    recommendation: str = ""
    error_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "ruleId": self.rule_id,
            "ruleName": self.rule_name,
            "category": self.category,
            "severity": self.severity.value,
            "namespace": self.namespace,
            "workload": self.workload,
            "pod": self.pod,
            "container": self.container,
            "source": self.source,
            "matchedPattern": self.matched_pattern,
            "occurrences": self.occurrences,
        }
        if self.first_timestamp:
            out["firstTimestamp"] = self.first_timestamp
        if self.last_timestamp:
            out["lastTimestamp"] = self.last_timestamp
        if self.error_code:
            out["errorCode"] = self.error_code
        if self.description:
            out["description"] = self.description
        if self.recommendation:
            out["recommendation"] = self.recommendation
        out["sampleLog"] = self.sample_log
        return out


@dataclass
class BehavioralFinding:
    id: str
    severity: Severity
    pattern: str
    namespace: str
    workload: str
    pod: str
    container: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "id": self.id,
            "severity": self.severity.value,
            "pattern": self.pattern,
            "namespace": self.namespace,
            "workload": self.workload,
            "pod": self.pod,
            "container": self.container,
            "description": self.description,
        }
        if self.evidence:
            res["evidence"] = self.evidence
        return res


@dataclass
class CollectionError:
    namespace: str
    pod: str
    container: str
    reason: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "namespace": self.namespace,
            "pod": self.pod,
            "container": self.container,
            "reason": self.reason,
            "message": self.message,
        }


def format_log_scan_report(
    scope: Dict[str, Any],
    pods_scanned: int,
    containers_scanned: int,
    pods_with_issues: int,
    total_entries_examined: int,
    total_error_matches: int,
    total_warning_matches: int,
    findings: List[LogFinding],
    behavioral_findings: List[BehavioralFinding],
    collection_errors: List[CollectionError],
    max_total_findings: int = 40,
) -> Dict[str, Any]:
    """Build the token-efficient log analysis report (Section 14 of logs.md)."""
    # Sort findings by severity and occurrence count
    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity.value, 99),
            -f.occurrences,
        )
    )

    # Determine overall log health status
    has_crit = any(f.severity == Severity.CRITICAL for f in findings) or any(
        b.severity == Severity.CRITICAL for b in behavioral_findings
    )
    has_high = any(f.severity == Severity.HIGH for f in findings) or any(
        b.severity == Severity.HIGH for b in behavioral_findings
    )
    has_med = any(f.severity == Severity.MEDIUM for f in findings) or any(
        b.severity == Severity.MEDIUM for b in behavioral_findings
    )

    if has_crit:
        log_health = "critical"
    elif has_high:
        log_health = "degraded"
    elif has_med:
        log_health = "warning"
    elif pods_scanned == 0 and collection_errors:
        log_health = "collection_failed"
    elif total_entries_examined == 0 and collection_errors:
        log_health = "unverified"
    else:
        log_health = "healthy"

    # Build grouped rollups (by namespace, workload, container, category)
    by_namespace: Dict[str, int] = {}
    by_workload: Dict[str, int] = {}
    by_container: Dict[str, int] = {}
    by_category: Dict[str, int] = {}

    for f in findings:
        by_namespace[f.namespace] = by_namespace.get(f.namespace, 0) + f.occurrences
        by_workload[f"{f.namespace}/{f.workload}"] = (
            by_workload.get(f"{f.namespace}/{f.workload}", 0) + f.occurrences
        )
        by_container[f"{f.pod}/{f.container}"] = (
            by_container.get(f"{f.pod}/{f.container}", 0) + f.occurrences
        )
        by_category[f.category] = by_category.get(f.category, 0) + f.occurrences

    truncated_count = 0
    if len(findings) > max_total_findings:
        truncated_count = len(findings) - max_total_findings
        displayed_findings = findings[:max_total_findings]
    else:
        displayed_findings = findings

    clean_pods_skipped = max(0, pods_scanned - pods_with_issues)

    report: Dict[str, Any] = {
        "logHealth": log_health,
        "scope": scope,
        "summary": {
            "podsScanned": pods_scanned,
            "containersScanned": containers_scanned,
            "podsWithIssues": pods_with_issues,
            "cleanPodsSkipped": clean_pods_skipped,
            "totalLogEntriesExamined": total_entries_examined,
            "totalErrorMatches": total_error_matches,
            "totalWarningMatches": total_warning_matches,
            "uniqueErrorPatterns": len(findings),
            "collectionFailures": len(collection_errors),
        },
    }

    if findings:
        report["groupedRollups"] = {
            "byNamespace": by_namespace,
            "byWorkload": by_workload,
            "byContainer": by_container,
            "byCategory": by_category,
        }

    if behavioral_findings:
        report["behaviouralFindings"] = [b.to_dict() for b in behavioral_findings]

    report["findings"] = [f.to_dict() for f in displayed_findings]

    if truncated_count > 0:
        report["truncatedFindingsCount"] = truncated_count

    if collection_errors:
        report["collectionErrors"] = [ce.to_dict() for ce in collection_errors[:25]]

    return report

