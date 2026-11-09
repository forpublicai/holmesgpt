import logging
from typing import Any, Dict, List, Optional, Tuple

from kubernetes import client
from kubernetes import config as k8s_config
from kubernetes.client.exceptions import ApiException

from holmes.core.tools import (
    CallablePrerequisite,
    StructuredToolResult,
    StructuredToolResultStatus,
    Tool,
    ToolInvokeContext,
    ToolParameter,
    Toolset,
    ToolsetTag,
)
from holmes.plugins.toolsets.utils import toolset_name_for_one_liner

logger = logging.getLogger(__name__)

# Waiting reasons that indicate a container is failing / crashed
CRASHED_WAITING_REASONS = frozenset(
    {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "CreateContainerConfigError",
        "CreateContainerError",
        "InvalidImageName",
        "RunContainerError",
    }
)


def _load_k8s_core_api() -> client.CoreV1Api:
    """Load in-cluster Kubernetes config, falling back to local kubeconfig."""
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()
    return client.CoreV1Api()


def _extract_crashed_containers(
    container_statuses: Optional[List[client.V1ContainerStatus]],
) -> List[Dict[str, Any]]:
    """Inspect container statuses and return only containers with crash/error state."""
    if not container_statuses:
        return []

    crashed_containers: List[Dict[str, Any]] = []
    for cs in container_statuses:
        reasons: List[str] = []
        last_exit_code: Optional[int] = None
        last_termination_reason: Optional[str] = None
        message: Optional[str] = None

        state = cs.state
        if state and state.waiting and state.waiting.reason in CRASHED_WAITING_REASONS:
            reasons.append(state.waiting.reason)
            message = state.waiting.message

        if state and state.terminated and (state.terminated.exit_code or 0) != 0:
            term_reason = state.terminated.reason or "Terminated"
            reasons.append(term_reason)
            last_exit_code = state.terminated.exit_code
            message = message or state.terminated.message

        last_state = cs.last_state
        if (
            last_state
            and last_state.terminated
            and (last_state.terminated.exit_code or 0) != 0
        ):
            last_termination_reason = last_state.terminated.reason
            last_exit_code = last_state.terminated.exit_code
            if not reasons:
                reasons.append(last_termination_reason or "NonZeroExit")

        if reasons:
            crashed_containers.append(
                {
                    "container": cs.name,
                    "ready": cs.ready,
                    "restart_count": cs.restart_count or 0,
                    "reasons": reasons,
                    "last_termination_reason": last_termination_reason,
                    "last_exit_code": last_exit_code,
                    "message": message,
                }
            )

    return crashed_containers


def collect_cluster_errors(namespace: Optional[str] = None) -> Dict[str, Any]:
    """Query the Kubernetes API and return a condensed JSON summary of errors.

    Currently checks for crashed/failing pods. Additional resource checks
    (deployments, nodes, warning events, etc.) can be added here.
    """
    v1 = _load_k8s_core_api()

    if namespace:
        pod_list = v1.list_namespaced_pod(namespace=namespace, timeout_seconds=30)
    else:
        pod_list = v1.list_pod_for_all_namespaces(timeout_seconds=30)

    crashed_pods: List[Dict[str, Any]] = []
    total_pods_scanned = len(pod_list.items)

    for pod in pod_list.items:
        meta = pod.metadata
        status = pod.status
        if not meta or not status:
            continue

        phase = status.phase or "Unknown"
        crashed_containers = _extract_crashed_containers(
            status.container_statuses
        ) + _extract_crashed_containers(status.init_container_statuses)

        is_pod_failed = phase in ("Failed", "Unknown") or status.reason == "Evicted"

        if is_pod_failed or crashed_containers:
            crashed_pods.append(
                {
                    "namespace": meta.namespace,
                    "pod": meta.name,
                    "node": pod.spec.node_name if pod.spec else None,
                    "phase": phase,
                    "pod_reason": status.reason,
                    "pod_message": status.message,
                    "containers": crashed_containers,
                }
            )

    return {
        "scope": {"namespace": namespace or "all"},
        "total_pods_scanned": total_pods_scanned,
        "crashed_pods_count": len(crashed_pods),
        "crashed_pods": crashed_pods,
    }


class KubernetesFastTool(Tool):
    toolset: "KubernetesFastToolset"

    def __init__(self, toolset: "KubernetesFastToolset"):
        super().__init__(
            name="kubernetes_fast",
            description=(
                "Scans the Kubernetes API in Python and returns a condensed JSON report "
                "containing ONLY unhealthy/crashed pods (e.g. CrashLoopBackOff, OOMKilled, "
                "ImagePullBackOff, Failed, Evicted, non-zero exit codes) instead of raw "
                "cluster objects, saving context tokens."
            ),
            parameters={
                "namespace": ToolParameter(
                    description=(
                        "Optional Kubernetes namespace to scan. "
                        "If omitted, scans all namespaces."
                    ),
                    type="string",
                    required=False,
                ),
            },
            toolset=toolset,  # type: ignore[call-arg]
        )

    def _invoke(self, params: dict, context: ToolInvokeContext) -> StructuredToolResult:
        namespace = params.get("namespace") or None
        if namespace == "None":
            namespace = None

        try:
            report = collect_cluster_errors(namespace=namespace)
            return StructuredToolResult(
                status=StructuredToolResultStatus.SUCCESS,
                data=report,
                params=params,
            )
        except ApiException as e:
            return StructuredToolResult(
                status=StructuredToolResultStatus.ERROR,
                error=(
                    f"Kubernetes API error (status={e.status}, reason={e.reason}, "
                    f"namespace={namespace or 'all'}): {e.body}"
                ),
                params=params,
            )
        except Exception as e:
            return StructuredToolResult(
                status=StructuredToolResultStatus.ERROR,
                error=f"Failed to scan Kubernetes API (namespace={namespace or 'all'}): {e}",
                params=params,
            )

    def get_parameterized_one_liner(self, params: Dict) -> str:
        ns = params.get("namespace") or "all namespaces"
        return f"{toolset_name_for_one_liner(self.toolset.name)}: Scan crashed pods ({ns})"


class KubernetesFastToolset(Toolset):
    """Condensed Kubernetes error-scanning toolset to minimize LLM token usage."""

    def __init__(self):
        super().__init__(
            name="kubernetes/fast",
            description="Fast, token-efficient Kubernetes scanner that returns only crashed pods and cluster errors",
            docs_url="https://holmesgpt.dev/data-sources/builtin-toolsets/kubernetes/",
            icon_url="https://raw.githubusercontent.com/gilbarbara/logos/de2c1f96ff6e74ea7ea979b43202e8d4b863c655/logos/kubernetes.svg",
            prerequisites=[
                CallablePrerequisite(callable=self.prerequisites_callable),
            ],
            tools=[],
            tags=[ToolsetTag.CORE],
            expose_remotely=True,
        )
        self.tools = [KubernetesFastTool(self)]

    def prerequisites_callable(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            _load_k8s_core_api()
            return True, ""
        except Exception as e:
            return False, f"Failed to initialize Kubernetes client: {e}"

