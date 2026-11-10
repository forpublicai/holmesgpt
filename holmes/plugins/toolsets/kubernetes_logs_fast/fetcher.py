from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from kubernetes import client
from kubernetes.client.exceptions import ApiException

from holmes.plugins.toolsets.kubernetes_fast.collector import load_k8s_api_client
from holmes.plugins.toolsets.kubernetes_logs_fast.models import (
    CollectionError,
    LogsFastConfig,
    ParsedLogEntry,
)
from holmes.plugins.toolsets.kubernetes_logs_fast.parser import parse_raw_logs

logger = logging.getLogger(__name__)


@dataclass
class ContainerTarget:
    namespace: str
    pod: str
    workload: str
    container: str
    is_init: bool = False
    restart_count: int = 0
    waiting_reason: Optional[str] = None


@dataclass
class PodLogBundle:
    namespace: str
    pod: str
    workload: str
    entries: List[ParsedLogEntry] = field(default_factory=list)
    containers_scanned: int = 0


def _infer_workload_name(pod_meta: Any) -> str:
    if not pod_meta:
        return "standalone"
    for ref in getattr(pod_meta, "owner_references", []) or []:
        kind = getattr(ref, "kind", "")
        name = getattr(ref, "name", "")
        if kind == "ReplicaSet" and "-" in name:
            # Strip ReplicaSet pod-template-hash suffix to show parent Deployment name
            dep_guess = name.rsplit("-", 1)[0]
            return f"Deployment/{dep_guess}"
        if kind and name:
            return f"{kind}/{name}"
    return f"Pod/{getattr(pod_meta, 'name', 'unknown')}"


def _pod_priority_score(pod: Any) -> int:
    """Return lower score for unhealthy/restarting pods so they are scanned first."""
    status = getattr(pod, "status", None)
    if not status:
        return 50
    phase = getattr(status, "phase", "Running")
    if phase in ("Failed", "Unknown"):
        return 0
    c_statuses = list(getattr(status, "container_statuses", []) or []) + list(
        getattr(status, "init_container_statuses", []) or []
    )
    max_restarts = 0
    has_waiting = False
    not_ready = False
    for cs in c_statuses:
        r = getattr(cs, "restart_count", 0) or 0
        if r > max_restarts:
            max_restarts = r
        state = getattr(cs, "state", None)
        if state and getattr(state, "waiting", None):
            has_waiting = True
        if not getattr(cs, "ready", True):
            not_ready = True

    if has_waiting:
        return 1
    if max_restarts >= 3:
        return 2
    if max_restarts > 0 or not_ready:
        return 3
    if phase == "Pending":
        return 4
    return 10


def _classify_api_error(
    e: ApiException, namespace: str, pod: str, container: str
) -> CollectionError:
    status = e.status or 0
    body = str(e.body or e.reason or "")
    if status == 403:
        reason = "RBACDenied"
    elif status == 404:
        reason = "PodOrContainerNotFound"
    elif "ContainerCreating" in body or "waiting to start" in body:
        reason = "ContainerWaitingToStart"
    elif "previous terminated container" in body and "not found" in body:
        reason = "PreviousLogsUnavailable"
    else:
        reason = f"APIError_{status}"
    return CollectionError(
        namespace=namespace,
        pod=pod,
        container=container,
        reason=reason,
        message=body[:250].strip(),
    )


def _fetch_single_container_logs(
    core_v1: client.CoreV1Api,
    target: ContainerTarget,
    previous: bool,
    tail_lines: int,
    since_seconds: Optional[int],
    limit_bytes: int,
) -> Tuple[ContainerTarget, str, str, int, Optional[CollectionError]]:
    """Fetch raw log string for one container (current or previous)."""
    source = "previous" if previous else ("init" if target.is_init else "current")
    kwargs: Dict[str, Any] = {
        "name": target.pod,
        "namespace": target.namespace,
        "container": target.container,
        "previous": previous,
        "tail_lines": tail_lines,
        "limit_bytes": limit_bytes,
        "timestamps": True,
        "_request_timeout": 15,
    }
    if since_seconds and since_seconds > 0 and not previous:
        kwargs["since_seconds"] = since_seconds

    try:
        raw: str = core_v1.read_namespaced_pod_log(**kwargs) or ""
        return target, source, raw, len(raw.encode("utf-8", errors="ignore")), None
    except ApiException as e:
        err = _classify_api_error(e, target.namespace, target.pod, target.container)
        return target, source, "", 0, err
    except Exception as e:
        err = CollectionError(
            namespace=target.namespace,
            pod=target.pod,
            container=target.container,
            reason=type(e).__name__,
            message=str(e)[:250],
        )
        return target, source, "", 0, err


def collect_logs_for_scope(
    config: LogsFastConfig,
    namespace: Optional[str] = None,
    pod_name: Optional[str] = None,
    deployment: Optional[str] = None,
    statefulset: Optional[str] = None,
    daemonset: Optional[str] = None,
    container_filter: Optional[str] = None,
    node_filter: Optional[str] = None,
    system_components_only: bool = False,
    tail_lines_override: Optional[int] = None,
    since_seconds_override: Optional[int] = None,
) -> Tuple[List[PodLogBundle], List[CollectionError]]:
    """Resolve matching Pods/containers and collect logs in parallel with hierarchical limits."""
    start_ts = time.monotonic()
    api_client = load_k8s_api_client()
    core_v1 = client.CoreV1Api(api_client)

    effective_ns = "kube-system" if system_components_only and not namespace else namespace
    if effective_ns in ("all", "*", "None"):
        effective_ns = None

    collection_errors: List[CollectionError] = []
    pods_to_scan: List[Any] = []

    # 1. Discover target Pods
    try:
        if pod_name and effective_ns and "," not in effective_ns:
            p_obj = core_v1.read_namespaced_pod(
                name=pod_name, namespace=effective_ns, _request_timeout=15
            )
            pods_to_scan = [p_obj]
        elif effective_ns and "," not in effective_ns:
            resp = core_v1.list_namespaced_pod(
                namespace=effective_ns, timeout_seconds=20
            )
            pods_to_scan = list(resp.items or [])
        elif effective_ns and "," in effective_ns:
            for ns_part in [n.strip() for n in effective_ns.split(",") if n.strip()]:
                resp = core_v1.list_namespaced_pod(
                    namespace=ns_part, timeout_seconds=20
                )
                pods_to_scan.extend(resp.items or [])
        else:
            resp = core_v1.list_pod_for_all_namespaces(timeout_seconds=20)
            pods_to_scan = list(resp.items or [])
    except ApiException as e:
        collection_errors.append(
            _classify_api_error(
                e, effective_ns or "all", pod_name or "all", container_filter or "all"
            )
        )
        return [], collection_errors
    except Exception as e:
        collection_errors.append(
            CollectionError(
                namespace=effective_ns or "all",
                pod=pod_name or "all",
                container=container_filter or "all",
                reason=type(e).__name__,
                message=str(e)[:250],
            )
        )
        return [], collection_errors

    # 2. Filter Pods by pod_name, deployment, statefulset, daemonset, or node
    filtered_pods: List[Any] = []
    for p in pods_to_scan:
        meta = getattr(p, "metadata", None)
        spec = getattr(p, "spec", None)
        if not meta or not spec:
            continue
        p_name = getattr(meta, "name", "")
        if pod_name and p_name != pod_name:
            continue
        if node_filter and getattr(spec, "node_name", None) != node_filter:
            continue

        workload = _infer_workload_name(meta)
        if deployment and workload != f"Deployment/{deployment}" and not p_name.startswith(f"{deployment}-"):
            continue
        if statefulset and workload != f"StatefulSet/{statefulset}" and not p_name.startswith(f"{statefulset}-"):
            continue
        if daemonset and workload != f"DaemonSet/{daemonset}" and not p_name.startswith(f"{daemonset}-"):
            continue

        filtered_pods.append(p)

    # Sort so unhealthy/restarting pods are scanned first and cap at max_pods_per_sweep
    filtered_pods.sort(key=_pod_priority_score)
    if len(filtered_pods) > config.max_pods_per_sweep:
        logger.info(
            f"[kubernetes/logs_fast] Capping sweep from {len(filtered_pods)} pods to "
            f"top {config.max_pods_per_sweep} priority pods"
        )
        filtered_pods = filtered_pods[: config.max_pods_per_sweep]

    # 3. Build ContainerTarget list
    tasks: List[Tuple[ContainerTarget, bool]] = []
    for p in filtered_pods:
        meta = p.metadata
        spec = p.spec
        status = getattr(p, "status", None)
        p_ns = getattr(meta, "namespace", "default")
        p_name = getattr(meta, "name", "unknown")
        workload = _infer_workload_name(meta)

        status_by_name: Dict[str, Any] = {}
        if status:
            for cs in list(getattr(status, "container_statuses", []) or []) + list(
                getattr(status, "init_container_statuses", []) or []
            ):
                status_by_name[getattr(cs, "name", "")] = cs

        c_specs: List[Tuple[Any, bool]] = [
            (c, False) for c in (getattr(spec, "containers", []) or [])
        ]
        if config.include_init_containers:
            c_specs.extend(
                [(ic, True) for ic in (getattr(spec, "init_containers", []) or [])]
            )

        for c_spec, is_init in c_specs:
            c_name = getattr(c_spec, "name", "")
            if container_filter and c_name != container_filter:
                continue
            cs = status_by_name.get(c_name)
            restarts = getattr(cs, "restart_count", 0) or 0 if cs else 0
            waiting = (
                getattr(getattr(cs, "state", None), "waiting", None) if cs else None
            )
            w_reason = getattr(waiting, "reason", None) if waiting else None

            if w_reason in ("ContainerCreating", "PodInitializing", "ImagePullBackOff", "ErrImagePull") and restarts == 0:
                collection_errors.append(
                    CollectionError(
                        namespace=p_ns,
                        pod=p_name,
                        container=c_name,
                        reason=w_reason,
                        message=f"Container is in '{w_reason}' state and has not produced logs yet.",
                    )
                )
                continue

            t_obj = ContainerTarget(
                namespace=p_ns,
                pod=p_name,
                workload=workload,
                container=c_name,
                is_init=is_init,
                restart_count=restarts,
                waiting_reason=w_reason,
            )
            tasks.append((t_obj, False))
            if config.include_previous_on_restart and (restarts > 0 or pod_name):
                tasks.append((t_obj, True))

    tail_lines = tail_lines_override or config.lines_per_container
    since_secs = (
        since_seconds_override
        if since_seconds_override is not None
        else config.since_seconds
    )
    max_bytes_total = config.max_log_size_mb * 1024 * 1024
    per_call_bytes = min(2 * 1024 * 1024, max_bytes_total)

    logger.info(
        f"[kubernetes/logs_fast] Collecting logs across {len(filtered_pods)} pods "
        f"({len(tasks)} container log streams, tail={tail_lines}, workers={config.concurrent_workers})..."
    )

    # 4. Execute log fetches in parallel and enforce hierarchical limits
    bundles_by_pod: Dict[Tuple[str, str], PodLogBundle] = {}
    ns_line_counts: Dict[str, int] = {}
    total_lines = 0
    total_bytes = 0

    with ThreadPoolExecutor(max_workers=max(1, config.concurrent_workers)) as pool:
        futures = [
            pool.submit(
                _fetch_single_container_logs,
                core_v1,
                t_obj,
                prev,
                tail_lines,
                since_secs,
                per_call_bytes,
            )
            for t_obj, prev in tasks
        ]

        for fut in as_completed(futures):
            t_obj, source, raw_text, byte_len, err = fut.result()
            pod_key = (t_obj.namespace, t_obj.pod)
            bundle = bundles_by_pod.setdefault(
                pod_key,
                PodLogBundle(
                    namespace=t_obj.namespace,
                    pod=t_obj.pod,
                    workload=t_obj.workload,
                ),
            )

            if err:
                # Ignore PreviousLogsUnavailable when restart_count == 0
                if err.reason == "PreviousLogsUnavailable" and t_obj.restart_count == 0:
                    continue
                collection_errors.append(err)
                continue

            if not prev_counted(bundle, t_obj.container, source):
                bundle.containers_scanned += 1

            if total_lines >= config.total_lines_per_scan or total_bytes >= max_bytes_total:
                continue

            ns_used = ns_line_counts.get(t_obj.namespace, 0)
            pod_used = len(bundle.entries)
            remaining_for_pod = max(0, config.lines_per_pod - pod_used)
            remaining_for_ns = max(0, config.lines_per_namespace - ns_used)
            remaining_global = max(0, config.total_lines_per_scan - total_lines)
            allowed_lines = min(
                tail_lines, remaining_for_pod, remaining_for_ns, remaining_global
            )
            if allowed_lines <= 0:
                continue

            parsed = parse_raw_logs(
                raw_text=raw_text,
                default_container=t_obj.container,
                source=source,
                max_lines=allowed_lines,
            )
            bundle.entries.extend(parsed)
            added = len(parsed)
            ns_line_counts[t_obj.namespace] = ns_used + added
            total_lines += added
            total_bytes += byte_len

    elapsed_ms = (time.monotonic() - start_ts) * 1000.0
    logger.info(
        f"[kubernetes/logs_fast] Collected {total_lines} log entries ({total_bytes / 1024:.1f} KB) "
        f"from {len(bundles_by_pod)} pods in {elapsed_ms:.0f}ms "
        f"({len(collection_errors)} collection warnings/errors)"
    )
    return list(bundles_by_pod.values()), collection_errors


def prev_counted(bundle: PodLogBundle, container: str, source: str) -> bool:
    return source == "previous" and any(
        e.container == container for e in bundle.entries
    )

