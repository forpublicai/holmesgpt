import logging
from typing import Any, Dict, List, Set, Tuple

from holmes.plugins.toolsets.kubernetes_fast.collector import ClusterSnapshot
from holmes.plugins.toolsets.kubernetes_fast.models import (
    Finding,
    KubernetesFastConfig,
    RelatedResource,
    Severity,
)
from holmes.plugins.toolsets.kubernetes_fast.utils import (
    format_iso,
    owner_references_to_related,
    to_utc_datetime,
)

logger = logging.getLogger(__name__)


def scan_workloads(
    snap: ClusterSnapshot,
    config: KubernetesFastConfig,
) -> Tuple[List[Finding], Dict[str, int]]:
    """Scan Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs, and CronJobs (Sections 3–7)."""
    findings: List[Finding] = []
    stats: Dict[str, int] = {
        "deployments": len(snap.deployments),
        "statefulSets": len(snap.stateful_sets),
        "daemonSets": len(snap.daemon_sets),
        "jobs": len(snap.jobs),
        "cronJobs": len(snap.cron_jobs),
    }

    idx = 0

    # Index existing services by (namespace, name) for StatefulSet governing service check
    existing_services: Set[Tuple[str, str]] = set()
    for svc in snap.services:
        s_meta = getattr(svc, "metadata", None)
        if s_meta:
            existing_services.add(
                (getattr(s_meta, "namespace", "default"), getattr(s_meta, "name", ""))
            )

    # Index existing pod names by namespace for StatefulSet ordinal checks
    pods_by_ns: Dict[str, Set[str]] = {}
    for pod in snap.pods:
        p_meta = getattr(pod, "metadata", None)
        if p_meta:
            pods_by_ns.setdefault(getattr(p_meta, "namespace", "default"), set()).add(
                getattr(p_meta, "name", "")
            )

    # 1. Deployments (Section 3)
    for dep in snap.deployments:
        meta = getattr(dep, "metadata", None)
        spec = getattr(dep, "spec", None)
        status = getattr(dep, "status", None)
        if not meta or not spec or not status:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        desired = getattr(spec, "replicas", 1)
        if desired is None:
            desired = 1
        ready = getattr(status, "ready_replicas", 0) or 0
        available = getattr(status, "available_replicas", 0) or 0
        updated = getattr(status, "updated_replicas", 0) or 0
        unavailable = getattr(status, "unavailable_replicas", 0) or 0
        gen = getattr(meta, "generation", 0) or 0
        obs_gen = getattr(status, "observed_generation", 0) or 0

        conditions = getattr(status, "conditions", []) or []
        progress_cond = next(
            (c for c in conditions if getattr(c, "type", None) == "Progressing"), None
        )
        replica_fail_cond = next(
            (c for c in conditions if getattr(c, "type", None) == "ReplicaFailure"),
            None,
        )

        progress_exceeded = (
            progress_cond
            and getattr(progress_cond, "status", "True") == "False"
            and getattr(progress_cond, "reason", None) == "ProgressDeadlineExceeded"
        )
        replica_failure = (
            replica_fail_cond
            and getattr(replica_fail_cond, "status", "False") == "True"
        )

        if desired > 0 and (
            available < desired
            or ready < desired
            or progress_exceeded
            or replica_failure
            or obs_gen < gen
        ):
            idx += 1
            if available == 0:
                sev = Severity.CRITICAL
                problem = f"Deployment has 0/{desired} available replicas"
                reason = "NoAvailableReplicas"
            elif progress_exceeded:
                sev = Severity.HIGH
                problem = "Deployment rollout stalled (ProgressDeadlineExceeded)"
                reason = "ProgressDeadlineExceeded"
            elif replica_failure:
                sev = Severity.HIGH
                problem = "Deployment failed to create/scale replicas"
                reason = getattr(replica_fail_cond, "reason", None) or "ReplicaFailure"
            else:
                sev = Severity.HIGH if unavailable > 0 else Severity.MEDIUM
                problem = f"Deployment degraded ({available}/{desired} available, {ready}/{desired} ready)"
                reason = "UnavailableReplicas"

            msg = (
                getattr(progress_cond, "message", None)
                if progress_exceeded
                else (
                    getattr(replica_fail_cond, "message", None)
                    if replica_failure
                    else None
                )
            )

            findings.append(
                Finding(
                    id=f"DEP-{idx:03d}",
                    category="workloads",
                    resource_type="Deployment",
                    resource_name=name,
                    namespace=ns,
                    severity=sev,
                    problem=problem,
                    reason=reason,
                    description=(
                        f"Deployment '{name}' expects {desired} replicas but has "
                        f"{available} available, {ready} ready, {updated} updated."
                    ),
                    evidence={
                        "desiredReplicas": desired,
                        "readyReplicas": ready,
                        "availableReplicas": available,
                        "updatedReplicas": updated,
                        "unavailableReplicas": unavailable,
                        "generation": gen,
                        "observedGeneration": obs_gen,
                        "conditionMessage": msg,
                    },
                    root_cause=(
                        msg
                        or "One or more backing Pods are failing, unschedulable, or failing readiness probes."
                    ),
                    recommendation="Check child ReplicaSets and Pods for CrashLoopBackOff, ImagePullBackOff, or scheduling errors.",
                )
            )

    # 2. ReplicaSets (Section 4 — report ReplicaFailure or standalone unhealthy ReplicaSets)
    for rs in snap.replica_sets:
        meta = getattr(rs, "metadata", None)
        spec = getattr(rs, "spec", None)
        status = getattr(rs, "status", None)
        if not meta or not spec or not status:
            continue

        desired = getattr(spec, "replicas", 0) or 0
        if desired == 0:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        ready = getattr(status, "ready_replicas", 0) or 0
        actual = getattr(status, "replicas", 0) or 0
        related = owner_references_to_related(meta, ns)

        conditions = getattr(status, "conditions", []) or []
        rf_cond = next(
            (c for c in conditions if getattr(c, "type", None) == "ReplicaFailure"),
            None,
        )
        has_rf = rf_cond and getattr(rf_cond, "status", "False") == "True"

        # Report if ReplicaFailure=True (e.g. quota/admission error) or if standalone RS is degraded
        if has_rf or (not related and ready < desired):
            idx += 1
            rf_msg = getattr(rf_cond, "message", None) if rf_cond else None
            rf_reason = (
                getattr(rf_cond, "reason", None) if rf_cond else "UnavailableReplicas"
            ) or "ReplicaFailure"
            findings.append(
                Finding(
                    id=f"RS-{idx:03d}",
                    category="workloads",
                    resource_type="ReplicaSet",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.HIGH,
                    problem=f"ReplicaSet failed to maintain replicas ({ready}/{desired} ready)",
                    reason=rf_reason,
                    description=(
                        f"ReplicaSet '{name}' desires {desired} Pods (created={actual}, ready={ready})."
                    ),
                    evidence={
                        "desiredReplicas": desired,
                        "actualReplicas": actual,
                        "readyReplicas": ready,
                        "failureMessage": rf_msg,
                    },
                    root_cause=rf_msg or "ReplicaSet Pods are failing or cannot be created.",
                    recommendation="Inspect ResourceQuota, ServiceAccount permissions, Admission Webhooks, or Pod errors.",
                    related_resources=related,
                )
            )

    # 3. StatefulSets (Section 5)
    for sts in snap.stateful_sets:
        meta = getattr(sts, "metadata", None)
        spec = getattr(sts, "spec", None)
        status = getattr(sts, "status", None)
        if not meta or not spec or not status:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        desired = getattr(spec, "replicas", 1)
        if desired is None:
            desired = 1
        ready = getattr(status, "ready_replicas", 0) or 0
        current = getattr(status, "current_replicas", 0) or 0
        updated = getattr(status, "updated_replicas", 0) or 0
        cur_rev = getattr(status, "current_revision", None)
        upd_rev = getattr(status, "update_revision", None)
        svc_name = getattr(spec, "service_name", None)

        missing_ordinals: List[str] = []
        ns_pods = pods_by_ns.get(ns, set())
        for ordinal in range(desired):
            expected_pod = f"{name}-{ordinal}"
            if expected_pod not in ns_pods:
                missing_ordinals.append(expected_pod)

        missing_governing_svc = bool(
            svc_name and (ns, svc_name) not in existing_services
        )

        if desired > 0 and (ready < desired or missing_ordinals or missing_governing_svc):
            idx += 1
            sev = Severity.CRITICAL if ready == 0 and desired > 0 else Severity.HIGH
            reason = (
                "MissingGoverningService"
                if missing_governing_svc and ready == desired
                else ("StuckUpdate" if cur_rev != upd_rev and ready < desired else "UnavailableReplicas")
            )
            findings.append(
                Finding(
                    id=f"STS-{idx:03d}",
                    category="workloads",
                    resource_type="StatefulSet",
                    resource_name=name,
                    namespace=ns,
                    severity=sev,
                    problem=f"StatefulSet degraded ({ready}/{desired} ready)",
                    reason=reason,
                    description=(
                        f"StatefulSet '{name}' has {ready}/{desired} ready replicas."
                        + (
                            f" Governing Service '{svc_name}' is missing."
                            if missing_governing_svc
                            else ""
                        )
                    ),
                    evidence={
                        "desiredReplicas": desired,
                        "readyReplicas": ready,
                        "currentReplicas": current,
                        "updatedReplicas": updated,
                        "currentRevision": cur_rev,
                        "updateRevision": upd_rev,
                        "missingOrdinalPods": missing_ordinals,
                        "governingService": svc_name,
                        "governingServiceExists": not missing_governing_svc,
                    },
                    root_cause=(
                        f"Governing headless Service '{svc_name}' does not exist in namespace '{ns}'."
                        if missing_governing_svc
                        else "StatefulSet ordinal Pod or its PersistentVolumeClaim is unhealthy/pending."
                    ),
                    recommendation="Check ordinal Pods and their volumeClaimTemplates / PVCs.",
                )
            )

    # 4. DaemonSets (Section 6)
    for ds in snap.daemon_sets:
        meta = getattr(ds, "metadata", None)
        status = getattr(ds, "status", None)
        if not meta or not status:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        desired = getattr(status, "desired_number_scheduled", 0) or 0
        current = getattr(status, "current_number_scheduled", 0) or 0
        ready = getattr(status, "number_ready", 0) or 0
        available = getattr(status, "number_available", 0) or 0
        unavailable = getattr(status, "number_unavailable", 0) or 0
        misscheduled = getattr(status, "number_misscheduled", 0) or 0

        if desired > 0 and (ready < desired or unavailable > 0 or misscheduled > 0):
            idx += 1
            sev = (
                Severity.CRITICAL
                if ready == 0 or ns == "kube-system"
                else Severity.HIGH
            )
            findings.append(
                Finding(
                    id=f"DS-{idx:03d}",
                    category="workloads",
                    resource_type="DaemonSet",
                    resource_name=name,
                    namespace=ns,
                    severity=sev,
                    problem=f"DaemonSet incomplete ({ready}/{desired} nodes ready)",
                    reason="DaemonSetDegraded",
                    description=(
                        f"DaemonSet '{name}' scheduled {current}/{desired} Pods with "
                        f"{ready} ready and {unavailable} unavailable."
                    ),
                    evidence={
                        "desiredNumberScheduled": desired,
                        "currentNumberScheduled": current,
                        "numberReady": ready,
                        "numberAvailable": available,
                        "numberUnavailable": unavailable,
                        "numberMisscheduled": misscheduled,
                    },
                    root_cause="DaemonSet Pods are crashing, pulling images, or blocked by node taints/resources.",
                    recommendation="Inspect DaemonSet Pods on affected nodes.",
                )
            )

    # 5. Jobs (Section 7)
    for job in snap.jobs:
        meta = getattr(job, "metadata", None)
        spec = getattr(job, "spec", None)
        status = getattr(job, "status", None)
        if not meta or not status:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        failed = getattr(status, "failed", 0) or 0
        succeeded = getattr(status, "succeeded", 0) or 0
        active = getattr(status, "active", 0) or 0
        conditions = getattr(status, "conditions", []) or []
        fail_cond = next(
            (
                c
                for c in conditions
                if getattr(c, "type", None) == "Failed"
                and getattr(c, "status", "False") == "True"
            ),
            None,
        )

        if fail_cond or (failed > 0 and succeeded == 0 and active == 0):
            idx += 1
            f_reason = (
                getattr(fail_cond, "reason", None) if fail_cond else "JobFailed"
            ) or "JobFailed"
            f_msg = getattr(fail_cond, "message", None) if fail_cond else None
            related = owner_references_to_related(meta, ns)
            findings.append(
                Finding(
                    id=f"JOB-{idx:03d}",
                    category="workloads",
                    resource_type="Job",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.HIGH,
                    problem=f"Job failed ({f_reason})",
                    reason=f_reason,
                    description=(
                        f"Job '{name}' failed after {failed} failed attempt(s)."
                    ),
                    evidence={
                        "failed": failed,
                        "succeeded": succeeded,
                        "active": active,
                        "backoffLimit": getattr(spec, "backoff_limit", None) if spec else None,
                        "message": f_msg,
                    },
                    root_cause=f_msg or "Job Pod exited with a non-zero exit code.",
                    recommendation="Check logs of the failed Job Pod(s).",
                    related_resources=related,
                )
            )

    # 6. CronJobs (Section 7)
    for cj in snap.cron_jobs:
        meta = getattr(cj, "metadata", None)
        spec = getattr(cj, "spec", None)
        status = getattr(cj, "status", None)
        if not meta or not spec or not status:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        suspended = bool(getattr(spec, "suspend", False))
        last_sched = getattr(status, "last_schedule_time", None)
        last_succ = getattr(status, "last_successful_time", None)
        active_refs = getattr(status, "active", []) or []

        sched_dt = to_utc_datetime(last_sched)
        succ_dt = to_utc_datetime(last_succ)

        if (
            sched_dt
            and not active_refs
            and (succ_dt is None or succ_dt < sched_dt)
        ):
            idx += 1
            findings.append(
                Finding(
                    id=f"CJ-{idx:03d}",
                    category="workloads",
                    resource_type="CronJob",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.MEDIUM,
                    problem="CronJob's most recent scheduled run did not succeed",
                    reason="LastScheduleFailed",
                    description=(
                        f"CronJob '{name}' last scheduled at {format_iso(last_sched)}, "
                        f"but lastSuccessfulTime is {format_iso(last_succ) or 'never'}."
                    ),
                    evidence={
                        "schedule": getattr(spec, "schedule", None),
                        "lastScheduleTime": format_iso(last_sched),
                        "lastSuccessfulTime": format_iso(last_succ),
                        "suspended": suspended,
                    },
                    root_cause="The Job spawned by the most recent CronJob schedule failed.",
                    recommendation="Inspect child Jobs and Pods created by this CronJob.",
                )
            )

    logger.info(
        f"[kubernetes/fast] Workload scanner finished: {len(findings)} workload findings"
    )
    return findings, stats

