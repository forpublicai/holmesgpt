import logging
from typing import Any, List, Optional

from holmes.plugins.toolsets.kubernetes_fast.collector import ClusterSnapshot
from holmes.plugins.toolsets.kubernetes_fast.models import (
    Finding,
    KubernetesFastConfig,
    Severity,
)
from holmes.plugins.toolsets.kubernetes_fast.utils import (
    age_minutes,
    owner_references_to_related,
)

logger = logging.getLogger(__name__)


def _classify_scheduling_message(msg: Optional[str]) -> tuple[str, str, str]:
    """Return (reason_code, root_cause, recommendation) from a scheduler message."""
    if not msg:
        return (
            "Unschedulable",
            "Pod has not been assigned to any node by the scheduler.",
            "Check scheduler events and cluster capacity.",
        )

    low = msg.lower()
    causes: List[str] = []
    code = "Unschedulable"

    if "insufficient cpu" in low:
        causes.append("Insufficient allocatable CPU across nodes")
        code = "InsufficientCPU"
    if "insufficient memory" in low:
        causes.append("Insufficient allocatable memory across nodes")
        code = "InsufficientMemory" if code == "Unschedulable" else code
    if "insufficient ephemeral-storage" in low:
        causes.append("Insufficient ephemeral storage on nodes")
        code = "InsufficientEphemeralStorage"
    if "gpu" in low and "insufficient" in low:
        causes.append("Insufficient GPU resources on nodes")
        code = "InsufficientGPU"
    if "untolerated taint" in low or "had taint" in low:
        causes.append("Nodes have taints that the Pod does not tolerate")
        if code == "Unschedulable":
            code = "UntoleratedTaint"
    if "node affinity" in low or "node selector" in low or "nodeselector" in low:
        causes.append("No nodes match the Pod's nodeSelector or nodeAffinity rules")
        if code == "Unschedulable":
            code = "NodeAffinityMismatch"
    if "anti-affinity" in low:
        causes.append("Pod anti-affinity rules prevent co-locating on available nodes")
        if code == "Unschedulable":
            code = "PodAntiAffinityConflict"
    if "topology spread" in low:
        causes.append("Topology spread constraints cannot be satisfied")
        if code == "Unschedulable":
            code = "TopologySpreadConstraint"
    if "persistentvolumeclaim" in low or "unbound" in low or "volume node affinity" in low:
        causes.append("Referenced PersistentVolumeClaim is unbound or has conflicting volume node affinity")
        if code == "Unschedulable":
            code = "UnboundPVCOrVolumeConflict"
    if "too many pods" in low:
        causes.append("Nodes have reached their maximum Pod capacity")
        if code == "Unschedulable":
            code = "MaxPodsPerNodeReached"

    if not causes:
        return (
            "Unschedulable",
            msg,
            "Review Pod scheduling constraints and cluster node capacity.",
        )

    return (
        code,
        "; ".join(causes),
        "Adjust Pod resource requests/scheduling constraints, bind pending PVCs, or scale out nodes.",
    )


def scan_scheduling(
    snap: ClusterSnapshot,
    config: KubernetesFastConfig,
) -> List[Finding]:
    """Scan for Pending / Unschedulable Pods and scheduling bottlenecks (Section 9)."""
    findings: List[Finding] = []
    idx = 0

    for pod in snap.pods:
        meta = getattr(pod, "metadata", None)
        spec = getattr(pod, "spec", None)
        status = getattr(pod, "status", None)
        if not meta or not status:
            continue

        phase = getattr(status, "phase", None)
        if phase != "Pending":
            continue

        pod_name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        node_name = getattr(spec, "node_name", None) if spec else None
        pod_age = age_minutes(getattr(meta, "creation_timestamp", None))

        conditions = getattr(status, "conditions", []) or []
        sched_cond = next(
            (c for c in conditions if getattr(c, "type", None) == "PodScheduled"),
            None,
        )

        is_unschedulable = (
            sched_cond
            and getattr(sched_cond, "status", "True") == "False"
            and getattr(sched_cond, "reason", None) == "Unschedulable"
        )

        # Report immediately if explicitly Unschedulable, or if Pending without a node past threshold
        if is_unschedulable or (
            not node_name
            and pod_age is not None
            and pod_age >= config.pending_pod_minutes
        ):
            idx += 1
            s_msg = getattr(sched_cond, "message", None) if sched_cond else None
            code, root_cause, recommendation = _classify_scheduling_message(s_msg)
            related = owner_references_to_related(meta, ns)

            findings.append(
                Finding(
                    id=f"SCHED-{idx:03d}",
                    category="scheduling",
                    resource_type="Pod",
                    resource_name=pod_name,
                    namespace=ns,
                    severity=Severity.HIGH,
                    problem=f"Pod cannot be scheduled ({code})",
                    reason=code,
                    description=(
                        f"Pod '{pod_name}' is Pending and cannot be scheduled: "
                        f"{s_msg or 'no node assigned'}."
                    ),
                    evidence={
                        "ageMinutes": round(pod_age, 1) if pod_age is not None else None,
                        "schedulerReason": getattr(sched_cond, "reason", None)
                        if sched_cond
                        else "PendingNoNode",
                        "schedulerMessage": s_msg,
                        "nodeSelector": getattr(spec, "node_selector", None) if spec else None,
                    },
                    root_cause=root_cause,
                    recommendation=recommendation,
                    related_resources=related,
                )
            )

    logger.info(
        f"[kubernetes/fast] Scheduling scanner finished: {len(findings)} scheduling findings"
    )
    return findings

