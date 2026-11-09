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
from holmes.plugins.toolsets.kubernetes_fast.utils import (
    age_minutes,
    explain_exit_code,
    format_iso,
    owner_references_to_related,
)

logger = logging.getLogger(__name__)

CRITICAL_WAITING_REASONS = frozenset(
    {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "CreateContainerConfigError",
        "CreateContainerError",
        "InvalidImageName",
        "RunContainerError",
        "CreateContainerSandboxError",
    }
)

STUCK_WAITING_REASONS = frozenset(
    {
        "ContainerCreating",
        "PodInitializing",
    }
)


def _inspect_container_statuses(
    statuses: Optional[List[Any]],
    container_type: str,
    pod_age_mins: Optional[float],
    config: KubernetesFastConfig,
) -> Tuple[List[Dict[str, Any]], Optional[Severity], List[str]]:
    """Inspect a list of V1ContainerStatus objects and extract abnormal states."""
    if not statuses:
        return [], None, []

    problem_containers: List[Dict[str, Any]] = []
    highest_severity: Optional[Severity] = None
    reasons_found: List[str] = []

    def _elevate(sev: Severity) -> None:
        nonlocal highest_severity
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
        }
        if highest_severity is None or order[sev] < order[highest_severity]:
            highest_severity = sev

    for cs in statuses:
        c_name = getattr(cs, "name", "unknown")
        restarts = getattr(cs, "restart_count", 0) or 0
        ready = bool(getattr(cs, "ready", False))
        state = getattr(cs, "state", None)
        last_state = getattr(cs, "last_state", None)

        c_reasons: List[str] = []
        c_message: Optional[str] = None
        exit_code: Optional[int] = None
        term_reason: Optional[str] = None
        last_finished_at: Optional[str] = None
        c_sev: Optional[Severity] = None

        # 1. Current waiting state
        waiting = getattr(state, "waiting", None) if state else None
        if waiting:
            w_reason = getattr(waiting, "reason", None) or "Waiting"
            w_msg = getattr(waiting, "message", None)
            if w_reason in CRITICAL_WAITING_REASONS:
                c_reasons.append(w_reason)
                c_message = w_msg
                c_sev = (
                    Severity.CRITICAL
                    if w_reason in ("CrashLoopBackOff", "CreateContainerConfigError")
                    else Severity.HIGH
                )
            elif (
                w_reason in STUCK_WAITING_REASONS
                and pod_age_mins is not None
                and pod_age_mins >= config.pending_pod_minutes
            ):
                c_reasons.append(f"Stuck{w_reason}")
                c_message = w_msg
                c_sev = Severity.HIGH

        # 2. Current terminated state
        terminated = getattr(state, "terminated", None) if state else None
        if terminated:
            t_code = getattr(terminated, "exit_code", 0) or 0
            t_reason = getattr(terminated, "reason", None) or "Terminated"
            if t_code != 0 or t_reason in ("OOMKilled", "Error", "ContainerCannotRun", "Evicted"):
                c_reasons.append(t_reason)
                exit_code = t_code
                term_reason = t_reason
                c_message = c_message or getattr(terminated, "message", None)
                last_finished_at = format_iso(getattr(terminated, "finished_at", None))
                c_sev = Severity.CRITICAL if t_reason == "OOMKilled" else Severity.HIGH

        # 3. Last termination state (e.g. OOMKilled / non-zero exit during restarts)
        last_term = getattr(last_state, "terminated", None) if last_state else None
        if last_term:
            lt_code = getattr(last_term, "exit_code", 0) or 0
            lt_reason = getattr(last_term, "reason", None)
            lt_finished = getattr(last_term, "finished_at", None)
            last_finished_at = last_finished_at or format_iso(lt_finished)
            if lt_code != 0 or lt_reason == "OOMKilled":
                exit_code = exit_code if exit_code is not None else lt_code
                term_reason = term_reason or lt_reason or "NonZeroExit"
                if not c_reasons and (
                    restarts >= config.restart_warning_threshold or lt_reason == "OOMKilled"
                ):
                    c_reasons.append(term_reason)

        # 4. Restart count evaluation
        if restarts >= config.restart_critical_threshold:
            if "RepeatedRestarts" not in c_reasons and not c_reasons:
                c_reasons.append("RepeatedRestarts")
            if c_sev is None or c_sev in (Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL):
                c_sev = Severity.HIGH
        elif restarts >= config.restart_warning_threshold:
            if not c_reasons:
                c_reasons.append("ElevatedRestarts")
            if c_sev is None:
                c_sev = Severity.MEDIUM
        elif term_reason == "OOMKilled" and c_sev is None:
            c_sev = Severity.HIGH

        # 5. Init container stuck or failed
        if container_type == "init" and not ready and c_reasons:
            c_sev = Severity.CRITICAL

        if c_reasons and c_sev is not None:
            _elevate(c_sev)
            for r in c_reasons:
                if r not in reasons_found:
                    reasons_found.append(r)
            entry: Dict[str, Any] = {
                "container": c_name,
                "type": container_type,
                "ready": ready,
                "restartCount": restarts,
                "reasons": c_reasons,
            }
            if term_reason:
                entry["lastTerminationReason"] = term_reason
            if exit_code is not None:
                entry["exitCode"] = exit_code
                entry["exitCodeMeaning"] = explain_exit_code(exit_code)
            if last_finished_at:
                entry["lastRestartTime"] = last_finished_at
            if c_message:
                entry["message"] = c_message[:300]
            problem_containers.append(entry)

    return problem_containers, highest_severity, reasons_found


def scan_pods(
    snap: ClusterSnapshot,
    config: KubernetesFastConfig,
) -> Tuple[List[Finding], Dict[str, int]]:
    """Scan Pods and container states (Sections 1 & 2)."""
    findings: List[Finding] = []
    stats: Dict[str, int] = {
        "total": len(snap.pods),
        "running": 0,
        "pending": 0,
        "failed": 0,
        "succeeded": 0,
        "crashLooping": 0,
        "terminating": 0,
    }

    idx = 0
    for pod in snap.pods:
        meta = getattr(pod, "metadata", None)
        status = getattr(pod, "status", None)
        spec = getattr(pod, "spec", None)
        if not meta or not status:
            continue

        pod_name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        phase = getattr(status, "phase", "Unknown") or "Unknown"
        pod_reason = getattr(status, "reason", None)
        pod_message = getattr(status, "message", None)
        node_name = getattr(spec, "node_name", None) if spec else None
        pod_age = age_minutes(getattr(meta, "creation_timestamp", None))
        related = owner_references_to_related(meta, ns)
        if node_name:
            related.append(RelatedResource(type="Node", name=node_name))

        # Track phase counts
        if phase == "Running":
            stats["running"] += 1
        elif phase == "Pending":
            stats["pending"] += 1
        elif phase == "Failed":
            stats["failed"] += 1
        elif phase == "Succeeded":
            stats["succeeded"] += 1

        # 1. Check stuck Terminating pods
        deletion_ts = getattr(meta, "deletion_timestamp", None)
        if deletion_ts:
            stats["terminating"] += 1
            del_age = age_minutes(deletion_ts) or 0.0
            grace_secs = (getattr(spec, "termination_grace_period_seconds", 30) if spec else 30) or 30
            if del_age > (grace_secs / 60.0) + 1.0:
                idx += 1
                finalizers = list(getattr(meta, "finalizers", []) or [])
                findings.append(
                    Finding(
                        id=f"POD-{idx:03d}",
                        category="pods",
                        resource_type="Pod",
                        resource_name=pod_name,
                        namespace=ns,
                        severity=Severity.HIGH,
                        problem="Pod stuck in Terminating state",
                        reason="StuckTerminating",
                        description=(
                            f"Pod '{pod_name}' has been terminating for {del_age:.1f} minutes "
                            f"(grace period {grace_secs}s)."
                        ),
                        evidence={
                            "deletionTimestamp": format_iso(deletion_ts),
                            "terminatingMinutes": round(del_age, 1),
                            "finalizers": finalizers,
                            "node": node_name,
                        },
                        root_cause=(
                            f"Blocked by unresolved finalizers: {finalizers}"
                            if finalizers
                            else "Kubelet or container runtime is not completing container stop."
                        ),
                        recommendation=(
                            "Inspect finalizer controller or node kubelet health."
                        ),
                        related_resources=related,
                    )
                )
                continue

        if phase == "Succeeded":
            continue

        # 2. Inspect init, app, and ephemeral containers
        init_issues, init_sev, init_reasons = _inspect_container_statuses(
            getattr(status, "init_container_statuses", None),
            "init",
            pod_age,
            config,
        )
        app_issues, app_sev, app_reasons = _inspect_container_statuses(
            getattr(status, "container_statuses", None),
            "app",
            pod_age,
            config,
        )
        eph_issues, eph_sev, eph_reasons = _inspect_container_statuses(
            getattr(status, "ephemeral_container_statuses", None),
            "ephemeral",
            pod_age,
            config,
        )

        all_container_issues = init_issues + app_issues + eph_issues
        all_reasons = init_reasons + [r for r in app_reasons + eph_reasons if r not in init_reasons]

        if "CrashLoopBackOff" in all_reasons:
            stats["crashLooping"] += 1

        # Determine highest container severity
        sev_candidates = [s for s in (init_sev, app_sev, eph_sev) if s is not None]
        container_sev: Optional[Severity] = None
        if sev_candidates:
            order_map = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
                Severity.INFORMATIONAL: 4,
            }
            container_sev = min(sev_candidates, key=lambda x: order_map[x])

        # 3. Evicted / Failed / Unknown pod phase
        is_evicted = pod_reason == "Evicted"
        is_failed_phase = phase in ("Failed", "Unknown") or is_evicted

        if is_failed_phase or all_container_issues:
            idx += 1
            sev = container_sev or (
                Severity.CRITICAL if phase == "Unknown" else Severity.HIGH
            )
            primary_reason = (
                all_reasons[0]
                if all_reasons
                else (pod_reason or phase)
            )
            root_cause = None
            recommendation = "Inspect container logs and recent Pod events."

            if "OOMKilled" in all_reasons or any(
                c.get("lastTerminationReason") == "OOMKilled" for c in all_container_issues
            ):
                root_cause = "Container exceeded its memory limit (OOMKilled / exit code 137)."
                recommendation = "Investigate application memory consumption and consider increasing resources.limits.memory."
            elif "CreateContainerConfigError" in all_reasons:
                root_cause = "Container configuration references a missing ConfigMap, Secret, or key."
                recommendation = "Check referenced ConfigMaps and Secrets in the namespace."
            elif "ImagePullBackOff" in all_reasons or "ErrImagePull" in all_reasons:
                root_cause = "Container runtime failed to pull the container image."
                recommendation = "Verify image name, tag, registry reachability, and imagePullSecrets."
            elif is_evicted:
                root_cause = f"Pod was evicted from node '{node_name}': {pod_message or 'resource pressure'}"
                recommendation = "Check node disk/memory pressure and pod resource requests/limits."

            findings.append(
                Finding(
                    id=f"POD-{idx:03d}",
                    category="pods",
                    resource_type="Pod",
                    resource_name=pod_name,
                    namespace=ns,
                    severity=sev,
                    status=(
                        FindingStatus.RECURRING
                        if "CrashLoopBackOff" in all_reasons or "RepeatedRestarts" in all_reasons
                        else FindingStatus.ACTIVE
                    ),
                    problem=f"Pod in abnormal state ({primary_reason})",
                    reason=primary_reason,
                    description=(
                        f"Pod '{pod_name}' (phase={phase}) has failing containers or abnormal status: "
                        f"{', '.join(all_reasons) if all_reasons else primary_reason}."
                    ),
                    evidence={
                        "phase": phase,
                        "node": node_name,
                        "podReason": pod_reason,
                        "podMessage": pod_message[:250] if pod_message else None,
                        "containers": all_container_issues,
                    },
                    root_cause=root_cause,
                    recommendation=recommendation,
                    related_resources=related,
                )
            )
            continue

        # 4. Running Pod that is not Ready after startup grace period (2 mins)
        if phase == "Running" and (pod_age is None or pod_age >= 2.0):
            conditions = getattr(status, "conditions", []) or []
            ready_cond = next(
                (c for c in conditions if getattr(c, "type", None) == "Ready"),
                None,
            )
            if ready_cond and getattr(ready_cond, "status", "True") == "False":
                idx += 1
                r_reason = getattr(ready_cond, "reason", None) or "ContainersNotReady"
                r_msg = getattr(ready_cond, "message", None)
                findings.append(
                    Finding(
                        id=f"POD-{idx:03d}",
                        category="pods",
                        resource_type="Pod",
                        resource_name=pod_name,
                        namespace=ns,
                        severity=Severity.MEDIUM,
                        problem="Pod is Running but Ready=False",
                        reason=r_reason,
                        description=(
                            f"Pod '{pod_name}' has been Running for {pod_age:.1f}m "
                            f"but readiness condition is False ({r_reason})."
                        ),
                        evidence={
                            "phase": phase,
                            "node": node_name,
                            "ageMinutes": round(pod_age, 1) if pod_age else None,
                            "readyReason": r_reason,
                            "readyMessage": r_msg,
                        },
                        root_cause="Readiness probe is failing or containers have not become ready.",
                        recommendation="Check readinessProbe configuration and application health endpoint.",
                        related_resources=related,
                    )
                )

    logger.info(
        f"[kubernetes/fast] Pod scanner finished: {stats['total']} pods scanned, "
        f"{len(findings)} pod findings ({stats['crashLooping']} crash-looping)"
    )
    return findings, stats
