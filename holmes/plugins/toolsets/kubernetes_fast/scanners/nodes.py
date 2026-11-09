import logging
from typing import Any, Dict, List, Tuple

from holmes.plugins.toolsets.kubernetes_fast.collector import ClusterSnapshot
from holmes.plugins.toolsets.kubernetes_fast.models import (
    Finding,
    KubernetesFastConfig,
    RelatedResource,
    Severity,
)
from holmes.plugins.toolsets.kubernetes_fast.utils import (
    format_iso,
    parse_cpu_millicores,
    parse_memory_bytes,
)

logger = logging.getLogger(__name__)


def _sum_pod_requests_by_node(
    pods: List[Any],
) -> Dict[str, Dict[str, float]]:
    """Aggregate CPU (millicores), memory (bytes), and pod count per node for active pods."""
    usage: Dict[str, Dict[str, float]] = {}
    for pod in pods:
        spec = getattr(pod, "spec", None)
        status = getattr(pod, "status", None)
        if not spec or not status:
            continue
        phase = getattr(status, "phase", None)
        if phase in ("Succeeded", "Failed"):
            continue
        node_name = getattr(spec, "node_name", None)
        if not node_name:
            continue

        entry = usage.setdefault(
            node_name, {"cpu_m": 0.0, "mem_bytes": 0.0, "pods": 0.0}
        )
        entry["pods"] += 1.0

        containers = getattr(spec, "containers", []) or []
        for c in containers:
            res = getattr(c, "resources", None)
            reqs = getattr(res, "requests", None) if res else None
            if reqs:
                entry["cpu_m"] += parse_cpu_millicores(reqs.get("cpu"))
                entry["mem_bytes"] += float(parse_memory_bytes(reqs.get("memory")))
    return usage


def scan_nodes(
    snap: ClusterSnapshot,
    config: KubernetesFastConfig,
) -> Tuple[List[Finding], Dict[str, int]]:
    """Scan Node health, conditions, taints, and resource commitment (Section 8)."""
    findings: List[Finding] = []
    stats: Dict[str, int] = {
        "total": len(snap.nodes),
        "ready": 0,
        "notReady": 0,
        "cordoned": 0,
    }

    node_requests = _sum_pod_requests_by_node(snap.pods)
    idx = 0

    for node in snap.nodes:
        meta = getattr(node, "metadata", None)
        spec = getattr(node, "spec", None)
        status = getattr(node, "status", None)
        if not meta or not status:
            continue

        node_name = getattr(meta, "name", "unknown")
        unschedulable = bool(getattr(spec, "unschedulable", False)) if spec else False
        taints = getattr(spec, "taints", []) or [] if spec else []
        conditions = getattr(status, "conditions", []) or []
        allocatable = getattr(status, "allocatable", {}) or {}

        if unschedulable:
            stats["cordoned"] += 1

        # Evaluate conditions
        ready_cond = next(
            (c for c in conditions if getattr(c, "type", None) == "Ready"), None
        )
        ready_status = getattr(ready_cond, "status", "Unknown") if ready_cond else "Unknown"

        if ready_status == "True":
            stats["ready"] += 1
        else:
            stats["notReady"] += 1
            idx += 1
            r_reason = getattr(ready_cond, "reason", None) if ready_cond else "NodeStatusUnknown"
            r_msg = getattr(ready_cond, "message", None) if ready_cond else None
            last_hb = format_iso(
                getattr(ready_cond, "last_heartbeat_time", None) if ready_cond else None
            )

            # Identify pods running on this node
            affected_pods: List[RelatedResource] = []
            for p in snap.pods:
                p_spec = getattr(p, "spec", None)
                p_meta = getattr(p, "metadata", None)
                if p_spec and p_meta and getattr(p_spec, "node_name", None) == node_name:
                    affected_pods.append(
                        RelatedResource(
                            type="Pod",
                            name=getattr(p_meta, "name", "unknown"),
                            namespace=getattr(p_meta, "namespace", "default"),
                        )
                    )

            findings.append(
                Finding(
                    id=f"NODE-{idx:03d}",
                    category="nodes",
                    resource_type="Node",
                    resource_name=node_name,
                    severity=Severity.CRITICAL,
                    problem=f"Node is NotReady (status={ready_status})",
                    reason=r_reason or "NodeNotReady",
                    description=(
                        f"Node '{node_name}' Ready condition is '{ready_status}' "
                        f"({len(affected_pods)} Pods scheduled on this node)."
                    ),
                    evidence={
                        "readyStatus": ready_status,
                        "reason": r_reason,
                        "message": r_msg,
                        "lastHeartbeatTime": last_hb,
                        "affectedPodCount": len(affected_pods),
                    },
                    root_cause=r_msg or "Kubelet stopped posting node status or node is unreachable.",
                    recommendation="Investigate node infrastructure, VM/host status, and kubelet service logs.",
                    related_resources=affected_pods[:15],
                )
            )

        # Check pressure conditions
        for pressure_type in (
            "MemoryPressure",
            "DiskPressure",
            "PIDPressure",
            "NetworkUnavailable",
        ):
            p_cond = next(
                (c for c in conditions if getattr(c, "type", None) == pressure_type),
                None,
            )
            if p_cond and getattr(p_cond, "status", "False") == "True":
                idx += 1
                p_sev = (
                    Severity.CRITICAL
                    if pressure_type == "NetworkUnavailable"
                    else Severity.HIGH
                )
                findings.append(
                    Finding(
                        id=f"NODE-{idx:03d}",
                        category="nodes",
                        resource_type="Node",
                        resource_name=node_name,
                        severity=p_sev,
                        problem=f"Node reporting {pressure_type}",
                        reason=getattr(p_cond, "reason", None) or pressure_type,
                        description=(
                            f"Node '{node_name}' has {pressure_type}=True: "
                            f"{getattr(p_cond, 'message', '')}"
                        ),
                        evidence={
                            "condition": pressure_type,
                            "reason": getattr(p_cond, "reason", None),
                            "message": getattr(p_cond, "message", None),
                        },
                        root_cause=f"Node '{node_name}' is experiencing {pressure_type}.",
                        recommendation="Check node resource usage, eviction thresholds, or CNI plugin status.",
                    )
                )

        # Check cordoned state
        if unschedulable:
            idx += 1
            findings.append(
                Finding(
                    id=f"NODE-{idx:03d}",
                    category="nodes",
                    resource_type="Node",
                    resource_name=node_name,
                    severity=Severity.MEDIUM,
                    problem="Node is cordoned (unschedulable)",
                    reason="NodeCordoned",
                    description=f"Node '{node_name}' has spec.unschedulable=true; new Pods cannot be scheduled on it.",
                    evidence={
                        "unschedulable": True,
                        "taints": [
                            {"key": getattr(t, "key", None), "effect": getattr(t, "effect", None)}
                            for t in taints
                        ],
                    },
                    root_cause="Node was cordoned for maintenance or drainage.",
                    recommendation="Uncordon the node (`kubectl uncordon`) once maintenance is complete.",
                )
            )

        # Check resource request commitment vs allocatable
        alloc_cpu = parse_cpu_millicores(allocatable.get("cpu"))
        alloc_mem = float(parse_memory_bytes(allocatable.get("memory")))
        alloc_pods = float(allocatable.get("pods", 110) or 110)

        reqs = node_requests.get(node_name, {"cpu_m": 0.0, "mem_bytes": 0.0, "pods": 0.0})
        cpu_pct = (reqs["cpu_m"] / alloc_cpu * 100.0) if alloc_cpu > 0 else 0.0
        mem_pct = (reqs["mem_bytes"] / alloc_mem * 100.0) if alloc_mem > 0 else 0.0
        pod_pct = (reqs["pods"] / alloc_pods * 100.0) if alloc_pods > 0 else 0.0

        # Live utilization from metrics.k8s.io if available
        live_metrics = snap.node_metrics.get(node_name, {})
        live_cpu_m = parse_cpu_millicores(live_metrics.get("cpu"))
        live_mem_b = float(parse_memory_bytes(live_metrics.get("memory")))
        live_cpu_pct = (live_cpu_m / alloc_cpu * 100.0) if alloc_cpu > 0 and live_cpu_m else 0.0
        live_mem_pct = (live_mem_b / alloc_mem * 100.0) if alloc_mem > 0 and live_mem_b else 0.0

        max_pct = max(cpu_pct, mem_pct, pod_pct, live_cpu_pct, live_mem_pct)
        if max_pct >= config.node_request_warning_percent:
            idx += 1
            sev = (
                Severity.HIGH
                if max_pct >= config.node_request_critical_percent
                else Severity.MEDIUM
            )
            findings.append(
                Finding(
                    id=f"NODE-{idx:03d}",
                    category="nodes",
                    resource_type="Node",
                    resource_name=node_name,
                    severity=sev,
                    problem=f"Node approaching resource capacity ({max_pct:.0f}%)",
                    reason="HighResourceCommitment",
                    description=(
                        f"Node '{node_name}' resource commitment/usage is high: "
                        f"CPU requests={cpu_pct:.1f}%, Memory requests={mem_pct:.1f}%, "
                        f"Pods={int(reqs['pods'])}/{int(alloc_pods)} ({pod_pct:.1f}%)."
                    ),
                    evidence={
                        "cpuRequestsPercent": round(cpu_pct, 1),
                        "memoryRequestsPercent": round(mem_pct, 1),
                        "podCapacityPercent": round(pod_pct, 1),
                        "runningPods": int(reqs["pods"]),
                        "allocatablePods": int(alloc_pods),
                        "liveCpuPercent": round(live_cpu_pct, 1) if live_cpu_pct else None,
                        "liveMemoryPercent": round(live_mem_pct, 1) if live_mem_pct else None,
                    },
                    root_cause="Workloads scheduled on this node have consumed most of its allocatable capacity.",
                    recommendation="Consider scaling out cluster nodes or tuning workload resource requests.",
                )
            )

    logger.info(
        f"[kubernetes/fast] Node scanner finished: {stats['total']} nodes ({stats['ready']} ready, "
        f"{stats['notReady']} notReady), {len(findings)} findings"
    )
    return findings, stats

