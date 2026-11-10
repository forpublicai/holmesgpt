import logging
from typing import Any, ClassVar, Dict, Optional, Tuple, Type

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
from holmes.plugins.toolsets.kubernetes_fast.collector import load_k8s_api_client
from holmes.plugins.toolsets.kubernetes_logs_fast.engine import run_log_scan
from holmes.plugins.toolsets.kubernetes_logs_fast.models import LogsFastConfig
from holmes.plugins.toolsets.utils import toolset_name_for_one_liner
from holmes.utils.pydantic_utils import ToolsetConfig

logger = logging.getLogger(__name__)


def _parse_optional_bool(val: Any) -> Optional[bool]:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        v = val.strip().lower()
        if v in ("true", "1", "yes"):
            return True
        if v in ("false", "0", "no"):
            return False
    return None


def _parse_optional_int(val: Any) -> Optional[int]:
    if isinstance(val, int) and not isinstance(val, bool):
        return val
    if isinstance(val, str) and val.strip().isdigit():
        return int(val.strip())
    return None


class LogsFastTool(Tool):
    toolset: "KubernetesLogsFastToolset"

    def __init__(self, toolset: "KubernetesLogsFastToolset"):
        super().__init__(
            name="logs_fast",
            description=(
                "Scrapes and analyzes Kubernetes container logs in Python using a configurable "
                "library of error, OOM, crash, database, network, DNS, TLS, storage, HTTP 5xx, "
                "and language runtime patterns. Supports structured JSON logs, multiline stack "
                "traces, and behavioural loop detection. Ignores clean logs and returns ONLY "
                "deduplicated error/warning findings and rollups to save LLM context tokens."
            ),
            parameters={
                "namespace": ToolParameter(
                    description=(
                        "Optional Kubernetes namespace (or comma-separated namespaces) to scan. "
                        "If omitted, scans all namespaces."
                    ),
                    type="string",
                    required=False,
                ),
                "pod_name": ToolParameter(
                    description=(
                        "Optional exact Pod name to scan. If omitted, sweeps recent logs "
                        "across Pods in the target scope (prioritizing unhealthy/restarting Pods)."
                    ),
                    type="string",
                    required=False,
                ),
                "deployment": ToolParameter(
                    description="Optional Deployment name to scan logs for all of its Pods.",
                    type="string",
                    required=False,
                ),
                "statefulset": ToolParameter(
                    description="Optional StatefulSet name to scan logs for all of its Pods.",
                    type="string",
                    required=False,
                ),
                "daemonset": ToolParameter(
                    description="Optional DaemonSet name to scan logs for all of its Pods.",
                    type="string",
                    required=False,
                ),
                "container": ToolParameter(
                    description="Optional container name filter.",
                    type="string",
                    required=False,
                ),
                "node": ToolParameter(
                    description="Optional Node name to scan logs only for Pods on that node.",
                    type="string",
                    required=False,
                ),
                "system_components_only": ToolParameter(
                    description="Optional boolean. Set to true to scan kube-system infrastructure Pods.",
                    type="boolean",
                    required=False,
                ),
                "tail_lines": ToolParameter(
                    description="Optional max lines per container to inspect (default: 500).",
                    type="integer",
                    required=False,
                ),
                "since_seconds": ToolParameter(
                    description="Optional lookback window in seconds (default: 3600 = 1 hour).",
                    type="integer",
                    required=False,
                ),
                "include_warnings": ToolParameter(
                    description="Optional boolean. Include warning/retry/backoff rules (default: true).",
                    type="boolean",
                    required=False,
                ),
                "extra_keywords": ToolParameter(
                    description="Optional comma-separated custom keywords to search for in logs.",
                    type="string",
                    required=False,
                ),
            },
            toolset=toolset,  # type: ignore[call-arg]
        )

    def _invoke(self, params: dict, context: ToolInvokeContext) -> StructuredToolResult:
        namespace = params.get("namespace") or None
        if namespace in ("None", "all", "*"):
            namespace = None

        pod_name = params.get("pod_name") or None
        deployment = params.get("deployment") or None
        statefulset = params.get("statefulset") or None
        daemonset = params.get("daemonset") or None
        container = params.get("container") or None
        node = params.get("node") or None
        system_only = bool(_parse_optional_bool(params.get("system_components_only")))
        tail_lines = _parse_optional_int(params.get("tail_lines"))
        since_seconds = _parse_optional_int(params.get("since_seconds"))
        include_warnings = _parse_optional_bool(params.get("include_warnings"))
        extra_keywords = params.get("extra_keywords") or None

        try:
            report = run_log_scan(
                namespace=namespace,
                pod_name=pod_name,
                deployment=deployment,
                statefulset=statefulset,
                daemonset=daemonset,
                container=container,
                node=node,
                system_components_only=system_only,
                tail_lines=tail_lines,
                since_seconds=since_seconds,
                include_warnings=include_warnings,
                extra_keywords=extra_keywords,
                config=self.toolset.scanner_config,
            )
            return StructuredToolResult(
                status=StructuredToolResultStatus.SUCCESS,
                data=report,
                params=params,
            )
        except ApiException as e:
            logger.error(
                f"[kubernetes/logs_fast] Kubernetes API error (status={e.status}, reason={e.reason})"
            )
            return StructuredToolResult(
                status=StructuredToolResultStatus.ERROR,
                error=(
                    f"Kubernetes API error during log scan (status={e.status}, "
                    f"reason={e.reason}, namespace={namespace or 'all'}): {e.body}"
                ),
                params=params,
            )
        except Exception as e:
            logger.exception(f"[kubernetes/logs_fast] Unexpected error during log scan: {e}")
            return StructuredToolResult(
                status=StructuredToolResultStatus.ERROR,
                error=f"Failed to scan Kubernetes logs (namespace={namespace or 'all'}): {e}",
                params=params,
            )

    def get_parameterized_one_liner(self, params: Dict) -> str:
        target = (
            params.get("pod_name")
            or params.get("deployment")
            or params.get("statefulset")
            or params.get("namespace")
            or "all namespaces"
        )
        return f"{toolset_name_for_one_liner(self.toolset.name)}: Fast log analysis ({target})"


class KubernetesLogsFastToolset(Toolset):
    """Token-efficient Kubernetes log analysis engine in Python."""

    config_classes: ClassVar[list[Type[ToolsetConfig]]] = [LogsFastConfig]
    scanner_config: LogsFastConfig = LogsFastConfig()

    def __init__(self):
        super().__init__(
            name="kubernetes/logs_fast",
            description=(
                "Fast, token-efficient Kubernetes log scraper and pattern analysis engine "
                "that sifts container logs in Python and returns only detected errors and warnings"
            ),
            docs_url="https://holmesgpt.dev/data-sources/builtin-toolsets/kubernetes/",
            icon_url="https://raw.githubusercontent.com/gilbarbara/logos/de2c1f96ff6e74ea7ea979b43202e8d4b863c655/logos/kubernetes.svg",
            prerequisites=[
                CallablePrerequisite(callable=self.prerequisites_callable),
            ],
            tools=[],
            tags=[ToolsetTag.CORE],
            expose_remotely=True,
        )
        self.scanner_config = LogsFastConfig()
        self.tools = [LogsFastTool(self)]

    def prerequisites_callable(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            if config:
                self.scanner_config = LogsFastConfig(**config)
            load_k8s_api_client()
            return True, ""
        except Exception as e:
            return False, f"Failed to initialize Kubernetes client for logs_fast: {e}"

