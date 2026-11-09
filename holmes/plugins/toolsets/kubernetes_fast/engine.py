import logging
import time
from typing import Any, Dict, List, Optional, Set

from holmes.plugins.toolsets.kubernetes_fast.collector import (
    ClusterSnapshot,
    collect_cluster_snapshot,
)
from holmes.plugins.toolsets.kubernetes_fast.models import (
    ALL_SECTION_KEYS,
    Finding,
    KubernetesFastConfig,
    format_compact_report,
)
from holmes.plugins.toolsets.kubernetes_fast.scanners import (
    build_correlations,
    scan_cluster_ops,
    scan_config_risks,
    scan_config_security_certs_webhooks,
    scan_networking,
    scan_nodes,
    scan_pods,
    scan_quotas_and_autoscaling,
    scan_scheduling,
    scan_storage,
    scan_workloads,
)

logger = logging.getLogger(__name__)


def _parse_requested_sections(categories: Optional[str]) -> List[str]:
    if not categories or categories.strip().lower() in ("all", "*"):
        return list(ALL_SECTION_KEYS)
    requested: Set[str] = {
        c.strip().lower() for c in categories.split(",") if c.strip()
    }
    matched = [s for s in ALL_SECTION_KEYS if s in requested]
    return matched if matched else list(ALL_SECTION_KEYS)


def run_cluster_health_scan(
    namespace: Optional[str] = None,
    categories: Optional[str] = None,
    include_config_risks: Optional[bool] = None,
    config: Optional[KubernetesFastConfig] = None,
    snapshot: Optional[ClusterSnapshot] = None,
) -> Dict[str, Any]:
    """Run all deterministic Kubernetes health scanners and return a compact report."""
    cfg = config or KubernetesFastConfig()
    run_risks = (
        include_config_risks
        if include_config_risks is not None
        else cfg.include_config_risks
    )
    active_sections = _parse_requested_sections(categories)
    active_set = set(active_sections)

    overall_start = time.monotonic()
    logger.info(
        f"[kubernetes/fast] Running cluster health scan "
        f"(namespace={namespace or 'all'}, sections={len(active_sections)}, "
        f"include_config_risks={run_risks})"
    )

    snap = snapshot or collect_cluster_snapshot(
        namespace=namespace,
        timeout_seconds=cfg.api_timeout_seconds,
    )

    findings: List[Finding] = []
    pod_stats: Dict[str, int] = {"total": len(snap.pods)}
    workload_stats: Dict[str, int] = {"deployments": len(snap.deployments)}
    node_stats: Dict[str, int] = {"total": len(snap.nodes)}

    # 1. Pods & Containers
    if "pods" in active_set:
        p_findings, pod_stats = scan_pods(snap, cfg)
        findings.extend(p_findings)

    # 2. Workloads (Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs, CronJobs)
    if "workloads" in active_set:
        w_findings, workload_stats = scan_workloads(snap, cfg)
        findings.extend(w_findings)

    # 3. Nodes
    if "nodes" in active_set:
        n_findings, node_stats = scan_nodes(snap, cfg)
        findings.extend(n_findings)

    # 4. Scheduling
    if "scheduling" in active_set:
        findings.extend(scan_scheduling(snap, cfg))

    # 5. Networking (Services, EndpointSlices, DNS, Ingress, Gateway, NetworkPolicies)
    if active_set.intersection(
        {
            "services_and_endpoints",
            "dns",
            "ingress_and_gateway",
            "network_policies",
        }
    ):
        net_findings = scan_networking(snap, cfg)
        findings.extend([f for f in net_findings if f.category in active_set])

    # 6. Storage (PVCs, PVs, StorageClasses, VolumeAttachments)
    if "storage" in active_set:
        findings.extend(scan_storage(snap, cfg))

    # 7. Quotas & Autoscaling (ResourceQuotas, HPAs, PDBs)
    if "quotas_and_autoscaling" in active_set:
        findings.extend(scan_quotas_and_autoscaling(snap, cfg))

    # 8. ConfigMaps, Secrets, RBAC, TLS Certificates, Admission Webhooks
    if active_set.intersection({"config_and_security", "certificates", "webhooks"}):
        sec_findings = scan_config_security_certs_webhooks(snap, cfg)
        findings.extend([f for f in sec_findings if f.category in active_set])

    # 9. Namespaces, Control Plane, System Components, Events, Custom Resources
    if active_set.intersection(
        {"namespaces", "control_plane_and_system", "events", "custom_resources"}
    ):
        ops_findings = scan_cluster_ops(snap, cfg)
        findings.extend([f for f in ops_findings if f.category in active_set])

    # 10. Optional Configuration Risks (Section 25)
    if run_risks:
        findings.extend(scan_config_risks(snap, cfg))

    # 11. Cross-Resource Root Cause Correlation Engine (Section 26)
    correlations = build_correlations(snap, findings)

    summary_stats: Dict[str, Any] = {
        "nodes": node_stats,
        "pods": pod_stats,
        "workloads": workload_stats,
    }

    report = format_compact_report(
        namespace=namespace,
        summary_stats=summary_stats,
        findings=findings,
        correlations=correlations,
        scanned_sections=active_sections,
        skipped_apis=snap.skipped_apis,
        max_per_category=cfg.max_findings_per_category,
    )

    total_ms = (time.monotonic() - overall_start) * 1000.0
    logger.info(
        f"[kubernetes/fast] Scan completed in {total_ms:.0f}ms: "
        f"clusterHealth={report['clusterHealth']}, "
        f"totalFindings={len(findings)}, "
        f"correlatedRootCauses={len(correlations)}"
    )
    return report

