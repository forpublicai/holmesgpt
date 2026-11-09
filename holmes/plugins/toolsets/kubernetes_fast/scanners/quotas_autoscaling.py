import logging
from typing import Any, Dict, List, Set, Tuple

from holmes.plugins.toolsets.kubernetes_fast.collector import ClusterSnapshot
from holmes.plugins.toolsets.kubernetes_fast.models import (
    Finding,
    KubernetesFastConfig,
    RelatedResource,
    Severity,
)
from holmes.plugins.toolsets.kubernetes_fast.utils import parse_quantity_float

logger = logging.getLogger(__name__)


def scan_quotas_and_autoscaling(
    snap: ClusterSnapshot,
    config: KubernetesFastConfig,
) -> List[Finding]:
    """Scan ResourceQuotas, HPAs, and PodDisruptionBudgets (Sections 14 & 15)."""
    findings: List[Finding] = []
    idx = 0

    # 1. ResourceQuotas (Section 14)
    for rq in snap.resource_quotas:
        meta = getattr(rq, "metadata", None)
        status = getattr(rq, "status", None)
        if not meta or not status:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        hard = getattr(status, "hard", {}) or {}
        used = getattr(status, "used", {}) or {}

        exhausted_keys: Dict[str, Any] = {}
        warning_keys: Dict[str, Any] = {}

        for k, hard_val in hard.items():
            used_val = used.get(k)
            if used_val is None:
                continue
            h_f = parse_quantity_float(str(hard_val))
            u_f = parse_quantity_float(str(used_val))
            if h_f <= 0:
                continue
            pct = (u_f / h_f) * 100.0
            if pct >= 100.0:
                exhausted_keys[k] = {
                    "used": str(used_val),
                    "hard": str(hard_val),
                    "percent": round(pct, 1),
                }
            elif pct >= config.quota_warning_percent:
                warning_keys[k] = {
                    "used": str(used_val),
                    "hard": str(hard_val),
                    "percent": round(pct, 1),
                }

        if exhausted_keys or warning_keys:
            idx += 1
            is_exhausted = bool(exhausted_keys)
            findings.append(
                Finding(
                    id=f"QUOTA-{idx:03d}",
                    category="quotas_and_autoscaling",
                    resource_type="ResourceQuota",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.HIGH if is_exhausted else Severity.MEDIUM,
                    problem=(
                        f"Namespace ResourceQuota exhausted ({', '.join(exhausted_keys.keys())})"
                        if is_exhausted
                        else f"Namespace ResourceQuota approaching limit ({', '.join(warning_keys.keys())})"
                    ),
                    reason="QuotaExhausted" if is_exhausted else "QuotaNearLimit",
                    description=(
                        f"ResourceQuota '{name}' in namespace '{ns}' has reached or exceeded thresholds."
                    ),
                    evidence={
                        "exhausted": exhausted_keys,
                        "approachingLimit": warning_keys,
                    },
                    root_cause="Workloads in this namespace have consumed the configured ResourceQuota.",
                    recommendation="Increase the ResourceQuota hard limits or reduce namespace workload usage.",
                )
            )

    # Index existing scalable workloads by (namespace, kind, name)
    scalable_targets: Set[Tuple[str, str, str]] = set()
    for d in snap.deployments:
        m = getattr(d, "metadata", None)
        if m:
            scalable_targets.add(
                (getattr(m, "namespace", "default"), "Deployment", getattr(m, "name", ""))
            )
    for s in snap.stateful_sets:
        m = getattr(s, "metadata", None)
        if m:
            scalable_targets.add(
                (getattr(m, "namespace", "default"), "StatefulSet", getattr(m, "name", ""))
            )
    for rs in snap.replica_sets:
        m = getattr(rs, "metadata", None)
        if m:
            scalable_targets.add(
                (getattr(m, "namespace", "default"), "ReplicaSet", getattr(m, "name", ""))
            )

    # 2. HorizontalPodAutoscalers (Section 15)
    for hpa in snap.hpas:
        meta = getattr(hpa, "metadata", None)
        spec = getattr(hpa, "spec", None)
        status = getattr(hpa, "status", None)
        if not meta or not spec or not status:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        target_ref = getattr(spec, "scale_target_ref", None)
        t_kind = getattr(target_ref, "kind", None) if target_ref else None
        t_name = getattr(target_ref, "name", None) if target_ref else None
        max_reps = getattr(spec, "max_replicas", 0) or 0
        cur_reps = getattr(status, "current_replicas", 0) or 0
        des_reps = getattr(status, "desired_replicas", 0) or 0

        related = (
            [RelatedResource(type=t_kind, name=t_name, namespace=ns)]
            if t_kind and t_name
            else []
        )

        if (
            t_kind in ("Deployment", "StatefulSet", "ReplicaSet")
            and t_name
            and scalable_targets
            and (ns, t_kind, t_name) not in scalable_targets
        ):
            idx += 1
            findings.append(
                Finding(
                    id=f"HPA-{idx:03d}",
                    category="quotas_and_autoscaling",
                    resource_type="HorizontalPodAutoscaler",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.HIGH,
                    problem=f"HPA targets non-existent {t_kind} '{t_name}'",
                    reason="MissingScaleTarget",
                    description=(
                        f"HPA '{name}' scaleTargetRef points to {t_kind} '{t_name}', "
                        f"which does not exist in namespace '{ns}'."
                    ),
                    evidence={"targetKind": t_kind, "targetName": t_name},
                    root_cause=f"Target {t_kind} '{t_name}' was deleted or renamed.",
                    recommendation="Update HPA scaleTargetRef or delete the orphaned HPA.",
                )
            )
            continue

        conditions = getattr(status, "conditions", []) or []
        able_cond = next(
            (c for c in conditions if getattr(c, "type", None) == "AbleToScale"), None
        )
        active_cond = next(
            (c for c in conditions if getattr(c, "type", None) == "ScalingActive"), None
        )
        limited_cond = next(
            (c for c in conditions if getattr(c, "type", None) == "ScalingLimited"),
            None,
        )

        if able_cond and getattr(able_cond, "status", "True") == "False":
            idx += 1
            findings.append(
                Finding(
                    id=f"HPA-{idx:03d}",
                    category="quotas_and_autoscaling",
                    resource_type="HorizontalPodAutoscaler",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.HIGH,
                    problem="HPA is unable to scale target workload",
                    reason=getattr(able_cond, "reason", None) or "AbleToScaleFalse",
                    description=f"HPA '{name}' AbleToScale=False: {getattr(able_cond, 'message', '')}",
                    evidence={
                        "currentReplicas": cur_reps,
                        "desiredReplicas": des_reps,
                        "maxReplicas": max_reps,
                        "reason": getattr(able_cond, "reason", None),
                        "message": getattr(able_cond, "message", None),
                    },
                    root_cause=getattr(able_cond, "message", None)
                    or "HPA cannot update the target scale subresource.",
                    recommendation="Check target workload and HPA controller logs.",
                    related_resources=related,
                )
            )
        elif active_cond and getattr(active_cond, "status", "True") == "False":
            idx += 1
            findings.append(
                Finding(
                    id=f"HPA-{idx:03d}",
                    category="quotas_and_autoscaling",
                    resource_type="HorizontalPodAutoscaler",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.HIGH,
                    problem="HPA scaling is inactive (metrics unavailable)",
                    reason=getattr(active_cond, "reason", None) or "ScalingActiveFalse",
                    description=f"HPA '{name}' ScalingActive=False: {getattr(active_cond, 'message', '')}",
                    evidence={
                        "currentReplicas": cur_reps,
                        "maxReplicas": max_reps,
                        "reason": getattr(active_cond, "reason", None),
                        "message": getattr(active_cond, "message", None),
                    },
                    root_cause=getattr(active_cond, "message", None)
                    or "Metrics API or Pod resource requests required by HPA are missing.",
                    recommendation="Verify metrics-server is healthy and target Pods define CPU/memory requests.",
                    related_resources=related,
                )
            )
        elif (
            limited_cond
            and getattr(limited_cond, "status", "False") == "True"
            and max_reps > 0
            and cur_reps >= max_reps
        ):
            idx += 1
            findings.append(
                Finding(
                    id=f"HPA-{idx:03d}",
                    category="quotas_and_autoscaling",
                    resource_type="HorizontalPodAutoscaler",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.MEDIUM,
                    problem=f"HPA has maxed out at {cur_reps}/{max_replicas if (max_replicas := max_reps) else max_reps} replicas",
                    reason=getattr(limited_cond, "reason", None) or "TooManyReplicas",
                    description=(
                        f"HPA '{name}' is at maxReplicas ({cur_reps}/{max_reps}) and cannot scale further."
                    ),
                    evidence={
                        "currentReplicas": cur_reps,
                        "desiredReplicas": des_reps,
                        "maxReplicas": max_reps,
                        "message": getattr(limited_cond, "message", None),
                    },
                    root_cause="Demand exceeds the HPA maxReplicas ceiling.",
                    recommendation="Consider raising HPA maxReplicas if cluster capacity permits.",
                    related_resources=related,
                )
            )

    # 3. PodDisruptionBudgets (Section 15)
    for pdb in snap.pdbs:
        meta = getattr(pdb, "metadata", None)
        status = getattr(pdb, "status", None)
        if not meta or not status:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        allowed = getattr(status, "disruptions_allowed", 1)
        expected = getattr(status, "expected_pods", 0) or 0
        healthy = getattr(status, "current_healthy", 0) or 0
        desired_healthy = getattr(status, "desired_healthy", 0) or 0

        if expected > 0 and allowed == 0 and healthy < desired_healthy:
            idx += 1
            findings.append(
                Finding(
                    id=f"PDB-{idx:03d}",
                    category="quotas_and_autoscaling",
                    resource_type="PodDisruptionBudget",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.MEDIUM,
                    problem="PDB has 0 disruptionsAllowed (healthy Pods below desiredHealthy)",
                    reason="InsufficientHealthyPods",
                    description=(
                        f"PodDisruptionBudget '{name}' has {healthy}/{desired_healthy} healthy Pods "
                        f"(expected={expected}, disruptionsAllowed=0), blocking voluntary evictions/drains."
                    ),
                    evidence={
                        "currentHealthy": healthy,
                        "desiredHealthy": desired_healthy,
                        "expectedPods": expected,
                        "disruptionsAllowed": allowed,
                    },
                    root_cause="Backing workload has fewer healthy Pods than the PDB minimum availability requirement.",
                    recommendation="Restore healthy replicas on the target workload or review PDB minAvailable/maxUnavailable.",
                )
            )

    logger.info(
        f"[kubernetes/fast] Quotas & autoscaling scanner finished: {len(findings)} findings"
    )
    return findings

