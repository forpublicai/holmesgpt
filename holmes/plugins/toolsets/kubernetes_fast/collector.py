from dataclasses import dataclass, field
import logging
import time
from typing import Any, Callable, Dict, List, Optional

from kubernetes import client
from kubernetes import config as k8s_config
from kubernetes.client.exceptions import ApiException

logger = logging.getLogger(__name__)


def load_k8s_api_client() -> client.ApiClient:
    """Load in-cluster Kubernetes config, falling back to local kubeconfig."""
    # Prevent kubernetes.client.rest from dumping raw HTTP bodies at DEBUG level
    logging.getLogger("kubernetes.client.rest").setLevel(logging.WARNING)
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()
    return client.ApiClient()


@dataclass
class ClusterSnapshot:
    namespace: Optional[str] = None
    pods: List[Any] = field(default_factory=list)
    nodes: List[Any] = field(default_factory=list)
    namespaces: List[Any] = field(default_factory=list)
    services: List[Any] = field(default_factory=list)
    endpoints: List[Any] = field(default_factory=list)
    endpoint_slices: List[Any] = field(default_factory=list)
    pvcs: List[Any] = field(default_factory=list)
    pvs: List[Any] = field(default_factory=list)
    storage_classes: List[Any] = field(default_factory=list)
    volume_attachments: List[Any] = field(default_factory=list)
    config_maps: List[Any] = field(default_factory=list)
    secrets: List[Any] = field(default_factory=list)
    service_accounts: List[Any] = field(default_factory=list)
    resource_quotas: List[Any] = field(default_factory=list)
    limit_ranges: List[Any] = field(default_factory=list)
    events: List[Any] = field(default_factory=list)
    deployments: List[Any] = field(default_factory=list)
    replica_sets: List[Any] = field(default_factory=list)
    stateful_sets: List[Any] = field(default_factory=list)
    daemon_sets: List[Any] = field(default_factory=list)
    jobs: List[Any] = field(default_factory=list)
    cron_jobs: List[Any] = field(default_factory=list)
    ingresses: List[Any] = field(default_factory=list)
    network_policies: List[Any] = field(default_factory=list)
    hpas: List[Any] = field(default_factory=list)
    pdbs: List[Any] = field(default_factory=list)
    roles: List[Any] = field(default_factory=list)
    role_bindings: List[Any] = field(default_factory=list)
    cluster_roles: List[Any] = field(default_factory=list)
    cluster_role_bindings: List[Any] = field(default_factory=list)
    validating_webhooks: List[Any] = field(default_factory=list)
    mutating_webhooks: List[Any] = field(default_factory=list)
    node_metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    api_server_health: Dict[str, Any] = field(default_factory=dict)
    crds: List[Any] = field(default_factory=list)
    custom_resources: List[Dict[str, Any]] = field(default_factory=list)
    kube_system_pods: List[Any] = field(default_factory=list)
    kube_system_deployments: List[Any] = field(default_factory=list)
    kube_system_daemon_sets: List[Any] = field(default_factory=list)
    kube_system_services: List[Any] = field(default_factory=list)
    kube_system_endpoints: List[Any] = field(default_factory=list)
    skipped_apis: List[str] = field(default_factory=list)


def _safe_list(
    label: str,
    fn: Callable[..., Any],
    skipped_apis: List[str],
    **kwargs: Any,
) -> List[Any]:
    start = time.monotonic()
    try:
        resp = fn(**kwargs)
        items = getattr(resp, "items", None)
        if items is None and isinstance(resp, dict):
            items = resp.get("items", [])
        result = list(items) if items is not None else []
        elapsed_ms = (time.monotonic() - start) * 1000.0
        logger.debug(
            f"[kubernetes/fast] Fetched {len(result)} {label} in {elapsed_ms:.1f}ms"
        )
        return result
    except ApiException as e:
        reason = f"{label} ({e.status} {e.reason})"
        skipped_apis.append(reason)
        logger.debug(f"[kubernetes/fast] Skipped {label}: HTTP {e.status} {e.reason}")
        return []
    except Exception as e:
        skipped_apis.append(f"{label} ({type(e).__name__})")
        logger.debug(f"[kubernetes/fast] Failed fetching {label}: {e}")
        return []


def collect_cluster_snapshot(
    namespace: Optional[str] = None,
    timeout_seconds: int = 20,
) -> ClusterSnapshot:
    """Collect a read-only snapshot of Kubernetes cluster resources for analysis."""
    start_time = time.monotonic()
    scope_desc = f"namespace='{namespace}'" if namespace else "all namespaces"
    logger.info(f"[kubernetes/fast] Starting cluster snapshot collection ({scope_desc})...")

    api_client = load_k8s_api_client()
    core_v1 = client.CoreV1Api(api_client)
    apps_v1 = client.AppsV1Api(api_client)
    batch_v1 = client.BatchV1Api(api_client)
    net_v1 = client.NetworkingV1Api(api_client)
    storage_v1 = client.StorageV1Api(api_client)
    autoscaling_v2 = client.AutoscalingV2Api(api_client)
    policy_v1 = client.PolicyV1Api(api_client)
    rbac_v1 = client.RbacAuthorizationV1Api(api_client)
    admission_v1 = client.AdmissionregistrationV1Api(api_client)
    apiext_v1 = client.ApiextensionsV1Api(api_client)
    custom_api = client.CustomObjectsApi(api_client)
    discovery_v1 = client.DiscoveryV1Api(api_client)

    snap = ClusterSnapshot(namespace=namespace)
    skipped = snap.skipped_apis
    t_kw = {"timeout_seconds": timeout_seconds}

    # 1. API Server health check (/readyz)
    try:
        raw_readyz = api_client.call_api(
            "/readyz",
            "GET",
            response_type="str",
            auth_settings=["BearerToken"],
            _return_http_data_only=True,
            _request_timeout=timeout_seconds,
        )
        snap.api_server_health["readyz"] = str(raw_readyz).strip()
    except Exception as e:
        snap.api_server_health["readyz_error"] = str(e)

    # 2. Cluster-scoped resources
    snap.nodes = _safe_list("Nodes", core_v1.list_node, skipped, **t_kw)
    snap.namespaces = _safe_list("Namespaces", core_v1.list_namespace, skipped, **t_kw)
    snap.pvs = _safe_list("PersistentVolumes", core_v1.list_persistent_volume, skipped, **t_kw)
    snap.storage_classes = _safe_list(
        "StorageClasses", storage_v1.list_storage_class, skipped, **t_kw
    )
    snap.volume_attachments = _safe_list(
        "VolumeAttachments", storage_v1.list_volume_attachment, skipped, **t_kw
    )
    snap.cluster_roles = _safe_list(
        "ClusterRoles", rbac_v1.list_cluster_role, skipped, **t_kw
    )
    snap.cluster_role_bindings = _safe_list(
        "ClusterRoleBindings", rbac_v1.list_cluster_role_binding, skipped, **t_kw
    )
    snap.validating_webhooks = _safe_list(
        "ValidatingWebhookConfigurations",
        admission_v1.list_validating_webhook_configuration,
        skipped,
        **t_kw,
    )
    snap.mutating_webhooks = _safe_list(
        "MutatingWebhookConfigurations",
        admission_v1.list_mutating_webhook_configuration,
        skipped,
        **t_kw,
    )

    # 3. Namespaced resources
    if namespace:
        ns_kw = {"namespace": namespace, **t_kw}
        snap.pods = _safe_list("Pods", core_v1.list_namespaced_pod, skipped, **ns_kw)
        snap.services = _safe_list(
            "Services", core_v1.list_namespaced_service, skipped, **ns_kw
        )
        snap.endpoints = _safe_list(
            "Endpoints", core_v1.list_namespaced_endpoints, skipped, **ns_kw
        )
        snap.endpoint_slices = _safe_list(
            "EndpointSlices", discovery_v1.list_namespaced_endpoint_slice, skipped, **ns_kw
        )
        snap.pvcs = _safe_list(
            "PersistentVolumeClaims",
            core_v1.list_namespaced_persistent_volume_claim,
            skipped,
            **ns_kw,
        )
        snap.config_maps = _safe_list(
            "ConfigMaps", core_v1.list_namespaced_config_map, skipped, **ns_kw
        )
        snap.secrets = _safe_list(
            "Secrets", core_v1.list_namespaced_secret, skipped, **ns_kw
        )
        snap.service_accounts = _safe_list(
            "ServiceAccounts", core_v1.list_namespaced_service_account, skipped, **ns_kw
        )
        snap.resource_quotas = _safe_list(
            "ResourceQuotas", core_v1.list_namespaced_resource_quota, skipped, **ns_kw
        )
        snap.limit_ranges = _safe_list(
            "LimitRanges", core_v1.list_namespaced_limit_range, skipped, **ns_kw
        )
        snap.events = _safe_list(
            "Events", core_v1.list_namespaced_event, skipped, **ns_kw
        )
        snap.deployments = _safe_list(
            "Deployments", apps_v1.list_namespaced_deployment, skipped, **ns_kw
        )
        snap.replica_sets = _safe_list(
            "ReplicaSets", apps_v1.list_namespaced_replica_set, skipped, **ns_kw
        )
        snap.stateful_sets = _safe_list(
            "StatefulSets", apps_v1.list_namespaced_stateful_set, skipped, **ns_kw
        )
        snap.daemon_sets = _safe_list(
            "DaemonSets", apps_v1.list_namespaced_daemon_set, skipped, **ns_kw
        )
        snap.jobs = _safe_list("Jobs", batch_v1.list_namespaced_job, skipped, **ns_kw)
        snap.cron_jobs = _safe_list(
            "CronJobs", batch_v1.list_namespaced_cron_job, skipped, **ns_kw
        )
        snap.ingresses = _safe_list(
            "Ingresses", net_v1.list_namespaced_ingress, skipped, **ns_kw
        )
        snap.network_policies = _safe_list(
            "NetworkPolicies", net_v1.list_namespaced_network_policy, skipped, **ns_kw
        )
        snap.hpas = _safe_list(
            "HorizontalPodAutoscalers",
            autoscaling_v2.list_namespaced_horizontal_pod_autoscaler,
            skipped,
            **ns_kw,
        )
        snap.pdbs = _safe_list(
            "PodDisruptionBudgets",
            policy_v1.list_namespaced_pod_disruption_budget,
            skipped,
            **ns_kw,
        )
        snap.roles = _safe_list("Roles", rbac_v1.list_namespaced_role, skipped, **ns_kw)
        snap.role_bindings = _safe_list(
            "RoleBindings", rbac_v1.list_namespaced_role_binding, skipped, **ns_kw
        )

        # Also fetch kube-system resources if scanning another namespace so CoreDNS/system checks work
        if namespace != "kube-system":
            ks_kw = {"namespace": "kube-system", **t_kw}
            snap.kube_system_pods = _safe_list(
                "kube-system Pods", core_v1.list_namespaced_pod, skipped, **ks_kw
            )
            snap.kube_system_deployments = _safe_list(
                "kube-system Deployments",
                apps_v1.list_namespaced_deployment,
                skipped,
                **ks_kw,
            )
            snap.kube_system_daemon_sets = _safe_list(
                "kube-system DaemonSets",
                apps_v1.list_namespaced_daemon_set,
                skipped,
                **ks_kw,
            )
            snap.kube_system_services = _safe_list(
                "kube-system Services", core_v1.list_namespaced_service, skipped, **ks_kw
            )
            snap.kube_system_endpoints = _safe_list(
                "kube-system Endpoints",
                core_v1.list_namespaced_endpoints,
                skipped,
                **ks_kw,
            )
        else:
            snap.kube_system_pods = snap.pods
            snap.kube_system_deployments = snap.deployments
            snap.kube_system_daemon_sets = snap.daemon_sets
            snap.kube_system_services = snap.services
            snap.kube_system_endpoints = snap.endpoints
    else:
        snap.pods = _safe_list(
            "Pods", core_v1.list_pod_for_all_namespaces, skipped, **t_kw
        )
        snap.services = _safe_list(
            "Services", core_v1.list_service_for_all_namespaces, skipped, **t_kw
        )
        snap.endpoints = _safe_list(
            "Endpoints", core_v1.list_endpoints_for_all_namespaces, skipped, **t_kw
        )
        snap.endpoint_slices = _safe_list(
            "EndpointSlices",
            discovery_v1.list_endpoint_slice_for_all_namespaces,
            skipped,
            **t_kw,
        )
        snap.pvcs = _safe_list(
            "PersistentVolumeClaims",
            core_v1.list_persistent_volume_claim_for_all_namespaces,
            skipped,
            **t_kw,
        )
        snap.config_maps = _safe_list(
            "ConfigMaps", core_v1.list_config_map_for_all_namespaces, skipped, **t_kw
        )
        snap.secrets = _safe_list(
            "Secrets", core_v1.list_secret_for_all_namespaces, skipped, **t_kw
        )
        snap.service_accounts = _safe_list(
            "ServiceAccounts",
            core_v1.list_service_account_for_all_namespaces,
            skipped,
            **t_kw,
        )
        snap.resource_quotas = _safe_list(
            "ResourceQuotas",
            core_v1.list_resource_quota_for_all_namespaces,
            skipped,
            **t_kw,
        )
        snap.limit_ranges = _safe_list(
            "LimitRanges", core_v1.list_limit_range_for_all_namespaces, skipped, **t_kw
        )
        snap.events = _safe_list(
            "Events", core_v1.list_event_for_all_namespaces, skipped, **t_kw
        )
        snap.deployments = _safe_list(
            "Deployments", apps_v1.list_deployment_for_all_namespaces, skipped, **t_kw
        )
        snap.replica_sets = _safe_list(
            "ReplicaSets", apps_v1.list_replica_set_for_all_namespaces, skipped, **t_kw
        )
        snap.stateful_sets = _safe_list(
            "StatefulSets",
            apps_v1.list_stateful_set_for_all_namespaces,
            skipped,
            **t_kw,
        )
        snap.daemon_sets = _safe_list(
            "DaemonSets", apps_v1.list_daemon_set_for_all_namespaces, skipped, **t_kw
        )
        snap.jobs = _safe_list(
            "Jobs", batch_v1.list_job_for_all_namespaces, skipped, **t_kw
        )
        snap.cron_jobs = _safe_list(
            "CronJobs", batch_v1.list_cron_job_for_all_namespaces, skipped, **t_kw
        )
        snap.ingresses = _safe_list(
            "Ingresses", net_v1.list_ingress_for_all_namespaces, skipped, **t_kw
        )
        snap.network_policies = _safe_list(
            "NetworkPolicies",
            net_v1.list_network_policy_for_all_namespaces,
            skipped,
            **t_kw,
        )
        snap.hpas = _safe_list(
            "HorizontalPodAutoscalers",
            autoscaling_v2.list_horizontal_pod_autoscaler_for_all_namespaces,
            skipped,
            **t_kw,
        )
        snap.pdbs = _safe_list(
            "PodDisruptionBudgets",
            policy_v1.list_pod_disruption_budget_for_all_namespaces,
            skipped,
            **t_kw,
        )
        snap.roles = _safe_list(
            "Roles", rbac_v1.list_role_for_all_namespaces, skipped, **t_kw
        )
        snap.role_bindings = _safe_list(
            "RoleBindings", rbac_v1.list_role_binding_for_all_namespaces, skipped, **t_kw
        )

        snap.kube_system_pods = [
            p for p in snap.pods if getattr(p.metadata, "namespace", None) == "kube-system"
        ]
        snap.kube_system_deployments = [
            d
            for d in snap.deployments
            if getattr(d.metadata, "namespace", None) == "kube-system"
        ]
        snap.kube_system_daemon_sets = [
            ds
            for ds in snap.daemon_sets
            if getattr(ds.metadata, "namespace", None) == "kube-system"
        ]
        snap.kube_system_services = [
            s
            for s in snap.services
            if getattr(s.metadata, "namespace", None) == "kube-system"
        ]
        snap.kube_system_endpoints = [
            ep
            for ep in snap.endpoints
            if getattr(ep.metadata, "namespace", None) == "kube-system"
        ]

    # 4. Optional Node Metrics (metrics.k8s.io/v1beta1)
    try:
        metrics_resp = custom_api.list_cluster_custom_object(
            group="metrics.k8s.io",
            version="v1beta1",
            plural="nodes",
            timeout_seconds=timeout_seconds,
        )
        for item in metrics_resp.get("items", []):
            node_name = item.get("metadata", {}).get("name")
            usage = item.get("usage", {})
            if node_name and usage:
                snap.node_metrics[node_name] = usage
        logger.debug(
            f"[kubernetes/fast] Fetched metrics for {len(snap.node_metrics)} nodes"
        )
    except Exception:
        logger.debug("[kubernetes/fast] metrics.k8s.io not available (skipping live node metrics)")

    # 5. Dynamic CRD Discovery & Custom Resource Condition Sampling
    snap.crds = _safe_list(
        "CustomResourceDefinitions",
        apiext_v1.list_custom_resource_definition,
        skipped,
        **t_kw,
    )
    _collect_custom_resources(snap, custom_api, namespace, timeout_seconds)

    elapsed = (time.monotonic() - start_time) * 1000.0
    logger.info(
        f"[kubernetes/fast] Snapshot collected in {elapsed:.0f}ms: "
        f"{len(snap.nodes)} nodes, {len(snap.pods)} pods, "
        f"{len(snap.deployments)} deployments, {len(snap.services)} services, "
        f"{len(snap.pvcs)} pvcs, {len(snap.events)} events, {len(snap.crds)} CRDs"
    )
    return snap


def _collect_custom_resources(
    snap: ClusterSnapshot,
    custom_api: client.CustomObjectsApi,
    namespace: Optional[str],
    timeout_seconds: int,
) -> None:
    """Dynamically query installed CRDs (up to 25 relevant CRDs) for custom resource status checks."""
    if not snap.crds:
        return

    # Prioritize common operational CRDs (cert-manager, gateway, operators, databases, argo, flux)
    # while skipping internal k8s/metrics/cilium-endpoint high-volume internal objects
    skip_groups = {
        "metrics.k8s.io",
        "custom.metrics.k8s.io",
        "external.metrics.k8s.io",
        "coordination.k8s.io",
        "discovery.k8s.io",
        "events.k8s.io",
    }
    skip_plurals = {
        "ciliumendpoints",
        "ciliumidentities",
        "ciliumnodes",
        "caliconodestatuses",
        " bgppeers",
        "leases",
    }

    queried_count = 0
    for crd in snap.crds:
        if queried_count >= 25:
            break
        spec = getattr(crd, "spec", None)
        if not spec:
            continue
        group = getattr(spec, "group", "")
        names = getattr(spec, "names", None)
        plural = getattr(names, "plural", "") if names else ""
        kind = getattr(names, "kind", "") if names else ""
        scope = getattr(spec, "scope", "Namespaced")
        versions = getattr(spec, "versions", []) or []

        if not group or not plural or group in skip_groups or plural in skip_plurals:
            continue

        served_version = None
        for v in versions:
            if getattr(v, "storage", False) and getattr(v, "served", False):
                served_version = getattr(v, "name", None)
                break
        if not served_version and versions:
            served_version = getattr(versions[0], "name", None)
        if not served_version:
            continue

        try:
            if scope == "Namespaced" and namespace:
                resp = custom_api.list_namespaced_custom_object(
                    group=group,
                    version=served_version,
                    namespace=namespace,
                    plural=plural,
                    timeout_seconds=timeout_seconds,
                )
            else:
                resp = custom_api.list_cluster_custom_object(
                    group=group,
                    version=served_version,
                    plural=plural,
                    timeout_seconds=timeout_seconds,
                )
            queried_count += 1
            for item in resp.get("items", []):
                if isinstance(item, dict):
                    item.setdefault("kind", kind or plural)
                    item.setdefault("apiVersion", f"{group}/{served_version}")
                    snap.custom_resources.append(item)
        except Exception:
            continue

