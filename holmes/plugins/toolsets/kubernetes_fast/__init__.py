from holmes.plugins.toolsets.kubernetes_fast.engine import run_cluster_health_scan
from holmes.plugins.toolsets.kubernetes_fast.models import (
    CorrelatedIssue,
    Finding,
    FindingStatus,
    KubernetesFastConfig,
    RelatedResource,
    Severity,
)
from holmes.plugins.toolsets.kubernetes_fast.toolset import (
    KubernetesFastTool,
    KubernetesFastToolset,
)

# Backwards-compatible alias
collect_cluster_errors = run_cluster_health_scan

__all__ = [
    "CorrelatedIssue",
    "Finding",
    "FindingStatus",
    "KubernetesFastConfig",
    "KubernetesFastTool",
    "KubernetesFastToolset",
    "RelatedResource",
    "Severity",
    "collect_cluster_errors",
    "run_cluster_health_scan",
]

