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
from holmes.plugins.toolsets.kubernetes_fast.engine import run_cluster_health_scan
from holmes.plugins.toolsets.kubernetes_fast.models import KubernetesFastConfig
from holmes.plugins.toolsets.utils import toolset_name_for_one_liner
from holmes.utils.pydantic_utils import ToolsetConfig

logger = logging.getLogger(__name__)


class KubernetesFastTool(Tool):
    toolset: "KubernetesFastToolset"

    def __init__(self, toolset: "KubernetesFastToolset"):
        super().__init__(
            name="kubernetes_fast",
            description=(
                "Runs a comprehensive, token-efficient Kubernetes health scan in Python across "
                "Pods, Containers, Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs, "
                "CronJobs, Nodes, Scheduling, Services, EndpointSlices, CoreDNS, Ingress, "
                "NetworkPolicies, PVCs/PVs/StorageClasses, ResourceQuotas, HPAs, PDBs, "
                "ConfigMap/Secret references, TLS Certificate expiry, Admission Webhooks, "
                "Namespaces, Control Plane, Events, and Custom Resources. "
                "Healthy sections collapse to 'healthy' and only discovered issues and "
                "correlated root causes are returned."
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
                "categories": ToolParameter(
                    description=(
                        "Optional comma-separated list of categories to scan "
                        "(e.g. 'pods,workloads,nodes,scheduling,services_and_endpoints,dns,"
                        "ingress_and_gateway,storage,quotas_and_autoscaling,config_and_security,"
                        "certificates,webhooks,events'). Defaults to 'all'."
                    ),
                    type="string",
                    required=False,
                ),
                "include_config_risks": ToolParameter(
                    description=(
                        "Optional boolean. Set to true to include non-failure configuration risk "
                        "checks (missing resource requests/limits, missing health probes, :latest "
                        "image tags, single replica). Defaults to false."
                    ),
                    type="boolean",
                    required=False,
                ),
            },
            toolset=toolset,  # type: ignore[call-arg]
        )

    def _invoke(self, params: dict, context: ToolInvokeContext) -> StructuredToolResult:
        namespace = params.get("namespace") or None
        if namespace in ("None", "all", "*"):
            namespace = None

        categories = params.get("categories") or None
        raw_risks = params.get("include_config_risks")
        include_config_risks: Optional[bool] = None
        if isinstance(raw_risks, bool):
            include_config_risks = raw_risks
        elif isinstance(raw_risks, str):
            include_config_risks = raw_risks.strip().lower() in ("true", "1", "yes")

        try:
            report = run_cluster_health_scan(
                namespace=namespace,
                categories=categories,
                include_config_risks=include_config_risks,
                config=self.toolset.scanner_config,
            )
            return StructuredToolResult(
                status=StructuredToolResultStatus.SUCCESS,
                data=report,
                params=params,
            )
        except ApiException as e:
            logger.error(
                f"[kubernetes/fast] Kubernetes API error (status={e.status}, reason={e.reason})"
            )
            return StructuredToolResult(
                status=StructuredToolResultStatus.ERROR,
                error=(
                    f"Kubernetes API error (status={e.status}, reason={e.reason}, "
                    f"namespace={namespace or 'all'}): {e.body}"
                ),
                params=params,
            )
        except Exception as e:
            logger.exception(f"[kubernetes/fast] Unexpected error during cluster scan: {e}")
            return StructuredToolResult(
                status=StructuredToolResultStatus.ERROR,
                error=f"Failed to scan Kubernetes API (namespace={namespace or 'all'}): {e}",
                params=params,
            )

    def get_parameterized_one_liner(self, params: Dict) -> str:
        ns = params.get("namespace") or "all namespaces"
        cats = params.get("categories") or "all categories"
        return f"{toolset_name_for_one_liner(self.toolset.name)}: Fast cluster health scan ({ns}, {cats})"


class KubernetesFastToolset(Toolset):
    """Comprehensive, token-efficient Kubernetes health scanner in Python."""

    config_classes: ClassVar[list[Type[ToolsetConfig]]] = [KubernetesFastConfig]
    scanner_config: KubernetesFastConfig = KubernetesFastConfig()

    def __init__(self):
        super().__init__(
            name="kubernetes/fast",
            description=(
                "Fast, token-efficient Kubernetes health scanner that runs 25+ domain checks "
                "and cross-resource root-cause correlations in Python, returning only issues"
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
        self.scanner_config = KubernetesFastConfig()
        self.tools = [KubernetesFastTool(self)]

    def prerequisites_callable(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            if config:
                self.scanner_config = KubernetesFastConfig(**config)
            load_k8s_api_client()
            return True, ""
        except Exception as e:
            return False, f"Failed to initialize Kubernetes client: {e}"

