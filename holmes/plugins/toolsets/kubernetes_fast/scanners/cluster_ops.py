import logging
from typing import Any, Dict, List, Optional, Tuple

from holmes.plugins.toolsets.kubernetes_fast.collector import ClusterSnapshot
from holmes.plugins.toolsets.kubernetes_fast.models import (
    Finding,
    FindingStatus,
    KubernetesFastConfig,
    RelatedResource,
    Severity,
)
from holmes.plugins.toolsets.kubernetes_fast.utils import age_minutes, format_iso

logger = logging.getLogger(__name__)

HIGH_PRIORITY_EVENT_REASONS = frozenset(
    {
        "FailedScheduling",
        "FailedCreate",
        "FailedMount",
        "FailedAttachVolume",
        "FailedMapVolume",
        "BackOff",
        "Failed",
        "Unhealthy",
        "Evicted",
        "OOMKilling",
        "FailedPull",
        "ErrImagePull",
        "ImagePullBackOff",
        "FailedCreatePodSandBox",
        "NetworkNotReady",
        "NodeNotReady",
        "NodeHasInsufficientMemory",
        "NodeHasInsufficientDisk",
        "Rebooted",
        "FailedToRetrieveImagePullSecret",
    }
)


def scan_cluster_ops(
    snap: ClusterSnapshot,
    config: KubernetesFastConfig,
) -> List[Finding]:
    """Scan Namespaces, Control Plane, System Components, Events, and Custom Resources (Sections 18–22)."""
    findings: List[Finding] = []

    # 1. Namespaces (Section 18)
    ns_idx = 0
    for ns_obj in snap.namespaces:
        meta = getattr(ns_obj, "metadata", None)
        spec = getattr(ns_obj, "spec", None)
        status = getattr(ns_obj, "status", None)
        if not meta or not status:
            continue

        ns_name = getattr(meta, "name", "unknown")
        phase = getattr(status, "phase", "Active")
        del_ts = getattr(meta, "deletion_timestamp", None)

        if phase == "Terminating" or del_ts:
            ns_idx += 1
            spec_finalizers = list(getattr(spec, "finalizers", []) or []) if spec else []
            meta_finalizers = list(getattr(meta, "finalizers", []) or [])
            conds = getattr(status, "conditions", []) or []
            cond_msgs = [
                f"{getattr(c, 'type', '')}: {getattr(c, 'message', '')}"
                for c in conds
                if getattr(c, "status", "") == "True" and getattr(c, "message", None)
            ]

            findings.append(
                Finding(
                    id=f"NS-{ns_idx:03d}",
                    category="namespaces",
                    resource_type="Namespace",
                    resource_name=ns_name,
                    severity=Severity.HIGH,
                    problem="Namespace stuck in Terminating state",
                    reason="NamespaceStuckTerminating",
                    description=(
                        f"Namespace '{ns_name}' is stuck Terminating. "
                        f"Finalizers: {spec_finalizers + meta_finalizers}."
                    ),
                    evidence={
                        "phase": phase,
                        "deletionTimestamp": format_iso(del_ts),
                        "finalizers": spec_finalizers + meta_finalizers,
                        "conditions": cond_msgs,
                    },
                    root_cause=(
                        "; ".join(cond_msgs)
                        if cond_msgs
                        else "Remaining resources with finalizers or unavailable APIService blocking namespace deletion."
                    ),
                    recommendation="Inspect remaining resources or broken APIServices blocking finalizer removal.",
                )
            )

    # 2. Control Plane & System Component Health (Sections 19 & 20)
    cp_idx = 0
    readyz = snap.api_server_health.get("readyz")
    readyz_err = snap.api_server_health.get("readyz_error")
    if readyz_err or (readyz and readyz.lower() != "ok"):
        cp_idx += 1
        findings.append(
            Finding(
                id=f"CP-{cp_idx:03d}",
                category="control_plane_and_system",
                resource_type="APIServer",
                resource_name="kube-apiserver",
                severity=Severity.CRITICAL,
                problem="Kubernetes API Server /readyz check did not return ok",
                reason="APIServerNotReady",
                description=f"API Server readiness endpoint reported: {readyz_err or readyz}",
                evidence=snap.api_server_health,
                root_cause="One or more API server readiness checks failed.",
                recommendation="Check API server and etcd health immediately.",
            )
        )

    # Check kube-system Pods for control-plane & system component failures
    for pod in snap.kube_system_pods:
        meta = getattr(pod, "metadata", None)
        status = getattr(pod, "status", None)
        if not meta or not status:
            continue
        p_name = getattr(meta, "name", "unknown")
        phase = getattr(status, "phase", "Unknown")
        if phase == "Succeeded":
            continue

        c_statuses = list(getattr(status, "container_statuses", []) or []) + list(
            getattr(status, "init_container_statuses", []) or []
        )
        unhealthy_cs = []
        for cs in c_statuses:
            ready = bool(getattr(cs, "ready", False))
            restarts = getattr(cs, "restart_count", 0) or 0
            state = getattr(cs, "state", None)
            waiting = getattr(state, "waiting", None) if state else None
            w_reason = getattr(waiting, "reason", None) if waiting else None
            if not ready or w_reason or restarts >= config.restart_warning_threshold:
                unhealthy_cs.append(
                    {
                        "container": getattr(cs, "name", ""),
                        "ready": ready,
                        "restartCount": restarts,
                        "waitingReason": w_reason,
                    }
                )

        if phase in ("Failed", "Unknown", "Pending") or unhealthy_cs:
            cp_idx += 1
            findings.append(
                Finding(
                    id=f"SYS-{cp_idx:03d}",
                    category="control_plane_and_system",
                    resource_type="Pod",
                    resource_name=p_name,
                    namespace="kube-system",
                    severity=(
                        Severity.CRITICAL
                        if any(
                            k in p_name
                            for k in (
                                "etcd",
                                "apiserver",
                                "scheduler",
                                "controller-manager",
                                "coredns",
                                "calico",
                                "cilium",
                                "flannel",
                                "kube-proxy",
                            )
                        )
                        else Severity.HIGH
                    ),
                    problem=f"System component Pod '{p_name}' in kube-system is unhealthy",
                    reason=phase if phase != "Running" else "SystemPodContainersUnhealthy",
                    description=(
                        f"kube-system Pod '{p_name}' (phase={phase}) has unhealthy container state."
                    ),
                    evidence={"phase": phase, "containers": unhealthy_cs},
                    root_cause="Critical cluster infrastructure or control-plane component is degraded.",
                    recommendation="Inspect kube-system Pod logs and events.",
                )
            )

    # 3. Events & Warning Detection (Section 21)
    ev_idx = 0
    grouped_events: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    for ev in snap.events:
        ev_type = getattr(ev, "type", "Normal")
        if ev_type != "Warning":
            continue

        reason = getattr(ev, "reason", "Warning") or "Warning"
        message = getattr(ev, "message", "") or ""
        involved = getattr(ev, "involved_object", None)
        obj_kind = getattr(involved, "kind", "Unknown") if involved else "Unknown"
        obj_name = getattr(involved, "name", "unknown") if involved else "unknown"
        obj_ns = (
            getattr(involved, "namespace", None)
            or getattr(getattr(ev, "metadata", None), "namespace", "default")
        )

        last_ts = (
            getattr(ev, "last_timestamp", None)
            or getattr(ev, "event_time", None)
            or getattr(getattr(ev, "metadata", None), "creation_timestamp", None)
        )
        first_ts = getattr(ev, "first_timestamp", None) or last_ts
        count = getattr(ev, "count", 1) or 1

        # Filter out stale warning events older than event_lookback_minutes
        ev_age = age_minutes(last_ts)
        if ev_age is not None and ev_age > config.event_lookback_minutes:
            continue

        key = (obj_ns or "cluster-wide", obj_kind, obj_name, reason)
        if key not in grouped_events:
            grouped_events[key] = {
                "namespace": obj_ns,
                "kind": obj_kind,
                "name": obj_name,
                "reason": reason,
                "count": count,
                "firstTimestamp": format_iso(first_ts),
                "lastTimestamp": format_iso(last_ts),
                "message": message[:300],
            }
        else:
            entry = grouped_events[key]
            entry["count"] += count
            if format_iso(last_ts) and (
                not entry["lastTimestamp"]
                or str(format_iso(last_ts)) > str(entry["lastTimestamp"])
            ):
                entry["lastTimestamp"] = format_iso(last_ts)
                entry["message"] = message[:300]

    for (obj_ns, obj_kind, obj_name, reason), info in grouped_events.items():
        ev_idx += 1
        total_cnt = info["count"]
        is_high_prio = reason in HIGH_PRIORITY_EVENT_REASONS
        if reason in ("OOMKilling", "NodeNotReady", "FailedAttachVolume", "FailedMount"):
            sev = Severity.HIGH
        elif is_high_prio or total_cnt >= 5:
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW

        findings.append(
            Finding(
                id=f"EVT-{ev_idx:03d}",
                category="events",
                resource_type=obj_kind,
                resource_name=obj_name,
                namespace=obj_ns,
                severity=sev,
                status=FindingStatus.RECURRING if total_cnt >= 3 else FindingStatus.ACTIVE,
                problem=f"Warning event '{reason}' on {obj_kind}/{obj_name} (x{total_cnt})",
                reason=reason,
                description=f"{obj_kind} '{obj_name}' emitted Warning '{reason}' ({total_cnt}x): {info['message']}",
                evidence={
                    "count": total_cnt,
                    "firstTimestamp": info["firstTimestamp"],
                    "lastTimestamp": info["lastTimestamp"],
                    "message": info["message"],
                },
                root_cause=info["message"],
                recommendation=f"Investigate {obj_kind} '{obj_name}' for {reason}.",
            )
        )

    # 4. Custom Resources & Operators (Section 22)
    cr_idx = 0
    for cr in snap.custom_resources:
        api_ver = cr.get("apiVersion", "")
        # Skip CRDs already handled in dedicated scanners
        if "cert-manager.io" in api_ver or "gateway.networking.k8s.io" in api_ver:
            continue

        kind = cr.get("kind", "CustomResource")
        meta = cr.get("metadata", {})
        c_name = meta.get("name", "unknown")
        c_ns = meta.get("namespace")
        status = cr.get("status", {})
        if not isinstance(status, dict):
            continue

        conds = status.get("conditions", [])
        if not isinstance(conds, list):
            continue

        bad_cond: Optional[Dict[str, Any]] = None
        for cond in conds:
            if not isinstance(cond, dict):
                continue
            c_type = str(cond.get("type", ""))
            c_stat = str(cond.get("status", ""))
            if (
                c_type in ("Ready", "Available", "Healthy", "Synced", "Reconciled")
                and c_stat == "False"
            ) or (c_type in ("Degraded", "Failed", "Error") and c_stat == "True"):
                bad_cond = cond
                break

        if bad_cond:
            cr_idx += 1
            c_type = bad_cond.get("type", "Condition")
            c_stat = bad_cond.get("status", "")
            findings.append(
                Finding(
                    id=f"CRD-{cr_idx:03d}",
                    category="custom_resources",
                    resource_type=kind,
                    resource_name=c_name,
                    namespace=c_ns,
                    severity=Severity.HIGH,
                    problem=f"Custom resource {kind} '{c_name}' has {c_type}={c_stat}",
                    reason=bad_cond.get("reason") or f"{c_type}{c_stat}",
                    description=(
                        f"{kind} '{c_name}' ({api_ver}) reports {c_type}={c_stat}: "
                        f"{bad_cond.get('message', '')}"
                    ),
                    evidence={
                        "apiVersion": api_ver,
                        "condition": bad_cond,
                        "generation": meta.get("generation"),
                        "observedGeneration": status.get("observedGeneration"),
                    },
                    root_cause=bad_cond.get("message")
                    or f"Operator failed to reconcile {kind} '{c_name}'.",
                    recommendation=f"Inspect the {kind} custom resource and its operator controller logs.",
                )
            )

    logger.info(
        f"[kubernetes/fast] Cluster ops scanner finished: {len(findings)} findings "
        f"(namespaces, control-plane, events, CRDs)"
    )
    return findings

