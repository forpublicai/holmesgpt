from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import Field

from holmes.utils.pydantic_utils import ToolsetConfig


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


SEVERITY_ORDER: Dict[str, int] = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFORMATIONAL.value: 4,
}


class FindingStatus(str, Enum):
    ACTIVE = "active"
    RECURRING = "recurring"
    PREDICTED = "predicted"
    RESOLVED = "resolved"
    UNVERIFIED = "unverified"


class KubernetesFastConfig(ToolsetConfig):
    """Configuration thresholds for the Kubernetes Fast Scanner (`kubernetes/fast`)."""

    restart_warning_threshold: int = Field(
        default=3,
        title="Restart Warning Threshold",
        description="Minimum container restart count to flag as a warning.",
    )
    restart_critical_threshold: int = Field(
        default=10,
        title="Restart Critical Threshold",
        description="Minimum container restart count to flag as high/critical.",
    )
    pending_pod_minutes: int = Field(
        default=5,
        title="Pending Pod Threshold (minutes)",
        description="Minutes a Pod can stay Pending before being flagged.",
    )
    event_lookback_minutes: int = Field(
        default=30,
        title="Warning Event Lookback (minutes)",
        description="Only include Warning events observed within this window (unless recurring).",
    )
    cert_warning_days: int = Field(
        default=30,
        title="TLS Certificate Warning Threshold (days)",
        description="Warn when a certificate expires within this many days.",
    )
    cert_critical_days: int = Field(
        default=7,
        title="TLS Certificate High/Critical Threshold (days)",
        description="Escalate when a certificate expires within this many days.",
    )
    quota_warning_percent: int = Field(
        default=85,
        title="ResourceQuota Warning Percentage",
        description="Warn when namespace ResourceQuota usage exceeds this percentage.",
    )
    node_request_warning_percent: int = Field(
        default=85,
        title="Node Request Commitment Warning Percentage",
        description="Warn when pod CPU/memory requests on a node exceed this percentage of allocatable.",
    )
    node_request_critical_percent: int = Field(
        default=95,
        title="Node Request Commitment High Percentage",
        description="Escalate when pod CPU/memory requests on a node exceed this percentage of allocatable.",
    )
    include_config_risks: bool = Field(
        default=False,
        title="Include Configuration Risks",
        description="Include best-practice / configuration risk checks (missing limits, missing probes, :latest tags).",
    )
    max_findings_per_category: int = Field(
        default=25,
        title="Max Findings Per Category",
        description="Maximum detailed findings returned per category to protect LLM context token budget.",
    )
    api_timeout_seconds: int = Field(
        default=20,
        title="Kubernetes API Timeout (seconds)",
        description="Timeout in seconds for each Kubernetes API list call.",
    )


@dataclass
class RelatedResource:
    type: str
    name: str
    namespace: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {"type": self.type, "name": self.name}
        if self.namespace:
            res["namespace"] = self.namespace
        return res


@dataclass
class Finding:
    id: str
    category: str
    resource_type: str
    resource_name: str
    severity: Severity
    problem: str
    reason: str
    description: str
    namespace: Optional[str] = None
    status: FindingStatus = FindingStatus.ACTIVE
    evidence: Dict[str, Any] = field(default_factory=dict)
    root_cause: Optional[str] = None
    recommendation: Optional[str] = None
    related_resources: List[RelatedResource] = field(default_factory=list)
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "id": self.id,
            "category": self.category,
            "resourceType": self.resource_type,
            "resourceName": self.resource_name,
            "namespace": self.namespace or "cluster-wide",
            "severity": self.severity.value,
            "status": self.status.value,
            "problem": self.problem,
            "reason": self.reason,
            "description": self.description,
        }
        if self.evidence:
            result["evidence"] = self.evidence
        if self.root_cause:
            result["rootCause"] = self.root_cause
        if self.recommendation:
            result["recommendation"] = self.recommendation
        if self.related_resources:
            result["relatedResources"] = [r.to_dict() for r in self.related_resources]
        result["detectedAt"] = self.detected_at
        return result


@dataclass
class CorrelatedIssue:
    id: str
    severity: Severity
    title: str
    root_cause: str
    diagnosis: str
    recommendation: str
    primary_resource: Dict[str, Any]
    affected_resources: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "id": self.id,
            "severity": self.severity.value,
            "problem": self.title,
            "rootCause": self.root_cause,
            "diagnosis": self.diagnosis,
            "recommendation": self.recommendation,
            "primaryResource": self.primary_resource,
            "affectedResources": self.affected_resources,
        }
        if self.evidence:
            out["evidence"] = self.evidence
        return out


ALL_SECTION_KEYS: List[str] = [
    "pods",
    "workloads",
    "nodes",
    "scheduling",
    "services_and_endpoints",
    "dns",
    "ingress_and_gateway",
    "network_policies",
    "storage",
    "quotas_and_autoscaling",
    "config_and_security",
    "certificates",
    "webhooks",
    "namespaces",
    "control_plane_and_system",
    "custom_resources",
    "events",
]


def format_compact_report(
    namespace: Optional[str],
    summary_stats: Dict[str, Any],
    findings: List[Finding],
    correlations: List[CorrelatedIssue],
    scanned_sections: List[str],
    skipped_apis: List[str],
    max_per_category: int = 25,
) -> Dict[str, Any]:
    """Assemble the token-efficient report where healthy sections collapse to 'healthy'."""
    by_category: Dict[str, List[Finding]] = {}
    severity_counts: Dict[str, int] = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
        Severity.INFORMATIONAL.value: 0,
    }

    for f in findings:
        by_category.setdefault(f.category, []).append(f)
        sev = f.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Determine overall cluster health
    if severity_counts[Severity.CRITICAL.value] > 0:
        overall_health = "critical"
    elif severity_counts[Severity.HIGH.value] > 0:
        overall_health = "degraded"
    elif severity_counts[Severity.MEDIUM.value] > 0:
        overall_health = "warning"
    else:
        overall_health = "healthy"

    # Build compact section headings (e.g. "ingress_and_gateway": "healthy")
    section_status: Dict[str, str] = {}
    for sec in scanned_sections:
        cat_findings = by_category.get(sec, [])
        if not cat_findings:
            section_status[sec] = "healthy"
        else:
            cat_sev: Dict[str, int] = {}
            for cf in cat_findings:
                s = cf.severity.value
                cat_sev[s] = cat_sev.get(s, 0) + 1
            breakdown = ", ".join(f"{cnt} {k}" for k, cnt in cat_sev.items())
            word = "issue" if len(cat_findings) == 1 else "issues"
            section_status[sec] = f"{len(cat_findings)} {word} ({breakdown})"

    # Sort findings by severity and cap per category to prevent token overflow
    serialized_findings: List[Dict[str, Any]] = []
    truncated_categories: Dict[str, int] = {}

    for cat in scanned_sections:
        cat_list = by_category.get(cat, [])
        if not cat_list:
            continue
        cat_list.sort(key=lambda x: SEVERITY_ORDER.get(x.severity.value, 99))
        if len(cat_list) > max_per_category:
            truncated_categories[cat] = len(cat_list) - max_per_category
            cat_list = cat_list[:max_per_category]
        for item in cat_list:
            serialized_findings.append(item.to_dict())

    # Include any categories not in scanned_sections (e.g. config_risks)
    for cat, cat_list in by_category.items():
        if cat in scanned_sections or not cat_list:
            continue
        cat_list.sort(key=lambda x: SEVERITY_ORDER.get(x.severity.value, 99))
        section_status[cat] = f"{len(cat_list)} items"
        if len(cat_list) > max_per_category:
            truncated_categories[cat] = len(cat_list) - max_per_category
            cat_list = cat_list[:max_per_category]
        for item in cat_list:
            serialized_findings.append(item.to_dict())

    report: Dict[str, Any] = {
        "clusterHealth": overall_health,
        "scope": {"namespace": namespace or "all"},
        "summary": {
            **summary_stats,
            "findingsBySeverity": {k: v for k, v in severity_counts.items() if v > 0}
            or {"none": 0},
        },
        "sectionStatus": section_status,
    }

    if correlations:
        report["correlatedRootCauses"] = [c.to_dict() for c in correlations]

    if serialized_findings:
        report["findings"] = serialized_findings
    else:
        report["findings"] = []

    if truncated_categories:
        report["truncatedFindingsCountByCategory"] = truncated_categories

    if skipped_apis:
        report["skippedApis"] = skipped_apis

    return report

