from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from holmes.plugins.toolsets.kubernetes_fast.collector import ClusterSnapshot
from holmes.plugins.toolsets.kubernetes_fast.engine import run_cluster_health_scan
from holmes.plugins.toolsets.kubernetes_fast.models import KubernetesFastConfig
from holmes.plugins.toolsets.kubernetes_fast.toolset import KubernetesFastToolset


def _ns(**kwargs):
    return SimpleNamespace(**kwargs)


def test_healthy_cluster_returns_minimal_healthy_sections():
    now = datetime.now(timezone.utc)
    healthy_node = _ns(
        metadata=_ns(name="node-1"),
        spec=_ns(unschedulable=False, taints=[]),
        status=_ns(
            conditions=[_ns(type="Ready", status="True", reason="KubeletReady", message="")],
            allocatable={"cpu": "4", "memory": "8Gi", "pods": "110"},
        ),
    )
    healthy_pod = _ns(
        metadata=_ns(
            name="web-abc",
            namespace="default",
            labels={"app": "web"},
            creation_timestamp=now - timedelta(minutes=30),
            deletion_timestamp=None,
            owner_references=[],
        ),
        spec=_ns(
            node_name="node-1",
            containers=[
                _ns(
                    name="web",
                    image="nginx:1.27.0",
                    ports=[_ns(container_port=80, name="http")],
                    resources=_ns(
                        requests={"cpu": "100m", "memory": "128Mi"},
                        limits={"memory": "256Mi"},
                    ),
                    readiness_probe=_ns(),
                    liveness_probe=_ns(),
                    security_context=None,
                    env=[],
                    env_from=[],
                )
            ],
            init_containers=[],
            volumes=[],
            image_pull_secrets=[],
            service_account_name="default",
        ),
        status=_ns(
            phase="Running",
            reason=None,
            message=None,
            conditions=[_ns(type="Ready", status="True")],
            container_statuses=[
                _ns(
                    name="web",
                    ready=True,
                    restart_count=0,
                    state=_ns(waiting=None, terminated=None),
                    last_state=_ns(terminated=None),
                )
            ],
            init_container_statuses=[],
            ephemeral_container_statuses=[],
        ),
    )

    snap = ClusterSnapshot(
        nodes=[healthy_node],
        pods=[healthy_pod],
        api_server_health={"readyz": "ok"},
    )

    report = run_cluster_health_scan(snapshot=snap)
    assert report["clusterHealth"] == "healthy"
    assert report["findings"] == []
    assert "correlatedRootCauses" not in report
    assert report["sectionStatus"]["pods"] == "healthy"
    assert report["sectionStatus"]["workloads"] == "healthy"
    assert report["sectionStatus"]["nodes"] == "healthy"
    assert report["sectionStatus"]["ingress_and_gateway"] == "healthy"
    assert report["sectionStatus"]["storage"] == "healthy"


def test_deployment_pod_crashloop_oom_and_correlation():
    now = datetime.now(timezone.utc)
    dep = _ns(
        metadata=_ns(name="payment-api", namespace="prod", generation=2),
        spec=_ns(replicas=3, template=_ns(spec=_ns(containers=[]))),
        status=_ns(
            ready_replicas=1,
            available_replicas=1,
            updated_replicas=3,
            unavailable_replicas=2,
            observed_generation=2,
            conditions=[
                _ns(
                    type="Progressing",
                    status="False",
                    reason="ProgressDeadlineExceeded",
                    message="ReplicaSet payment-api-7f8d9 has timed out progressing.",
                )
            ],
        ),
    )
    rs = _ns(
        metadata=_ns(
            name="payment-api-7f8d9",
            namespace="prod",
            owner_references=[_ns(kind="Deployment", name="payment-api")],
        ),
        spec=_ns(replicas=3),
        status=_ns(replicas=3, ready_replicas=1, conditions=[]),
    )
    crashing_pod = _ns(
        metadata=_ns(
            name="payment-api-7f8d9-pod1",
            namespace="prod",
            labels={"app": "payment-api"},
            creation_timestamp=now - timedelta(minutes=20),
            deletion_timestamp=None,
            owner_references=[_ns(kind="ReplicaSet", name="payment-api-7f8d9")],
        ),
        spec=_ns(
            node_name="node-1",
            containers=[],
            init_containers=[],
            volumes=[],
            image_pull_secrets=[],
            service_account_name=None,
        ),
        status=_ns(
            phase="Running",
            reason=None,
            message=None,
            conditions=[_ns(type="Ready", status="False", reason="ContainersNotReady", message="")],
            container_statuses=[
                _ns(
                    name="app",
                    ready=False,
                    restart_count=15,
                    state=_ns(
                        waiting=_ns(
                            reason="CrashLoopBackOff",
                            message="back-off 5m0s restarting failed container",
                        ),
                        terminated=None,
                    ),
                    last_state=_ns(
                        terminated=_ns(
                            exit_code=137,
                            reason="OOMKilled",
                            finished_at=now - timedelta(minutes=2),
                        )
                    ),
                )
            ],
            init_container_statuses=[],
            ephemeral_container_statuses=[],
        ),
    )

    snap = ClusterSnapshot(
        deployments=[dep],
        replica_sets=[rs],
        pods=[crashing_pod],
        api_server_health={"readyz": "ok"},
    )

    report = run_cluster_health_scan(snapshot=snap)
    assert report["clusterHealth"] == "critical"
    assert report["summary"]["pods"]["crashLooping"] == 1
    assert report["sectionStatus"]["pods"].startswith("1 issue")
    assert report["sectionStatus"]["workloads"].startswith("1 issue")
    assert report["sectionStatus"]["storage"] == "healthy"

    # Verify Pod finding has OOMKilled evidence & exitCode 137 explanation
    pod_finding = next(f for f in report["findings"] if f["category"] == "pods")
    assert pod_finding["severity"] == "critical"
    assert pod_finding["reason"] == "CrashLoopBackOff"
    c_ev = pod_finding["evidence"]["containers"][0]
    assert c_ev["lastTerminationReason"] == "OOMKilled"
    assert c_ev["exitCode"] == 137
    assert "OOMKilled" in pod_finding["rootCause"]

    # Verify Cross-Resource Correlation (Example A)
    corrs = report.get("correlatedRootCauses", [])
    assert any(c["id"] == "CORR-DEP-001" for c in corrs)


def test_node_not_ready_and_missing_secret_and_networking_checks():
    now = datetime.now(timezone.utc)
    bad_node = _ns(
        metadata=_ns(name="worker-03"),
        spec=_ns(unschedulable=False, taints=[]),
        status=_ns(
            conditions=[
                _ns(
                    type="Ready",
                    status="Unknown",
                    reason="NodeStatusUnknown",
                    message="Kubelet stopped posting node status.",
                    last_heartbeat_time=now - timedelta(minutes=10),
                )
            ],
            allocatable={"cpu": "4", "memory": "8Gi", "pods": "110"},
        ),
    )

    # Pod referencing a missing secret on worker-03
    pod_missing_sec = _ns(
        metadata=_ns(
            name="api-pod-1",
            namespace="prod",
            labels={"app": "api"},
            creation_timestamp=now - timedelta(minutes=15),
            deletion_timestamp=None,
            owner_references=[_ns(kind="StatefulSet", name="redis")],
        ),
        spec=_ns(
            node_name="worker-03",
            containers=[
                _ns(
                    name="api",
                    ports=[_ns(container_port=8080, name="http")],
                    env=[
                        _ns(
                            name="DB_PASS",
                            value_from=_ns(
                                secret_key_ref=_ns(
                                    name="deleted-secret", key="password", optional=False
                                ),
                                config_map_key_ref=None,
                            ),
                        )
                    ],
                    env_from=[],
                    resources=None,
                )
            ],
            init_containers=[],
            volumes=[],
            image_pull_secrets=[],
            service_account_name=None,
        ),
        status=_ns(
            phase="Pending",
            reason=None,
            message=None,
            conditions=[],
            container_statuses=[],
            init_container_statuses=[],
            ephemeral_container_statuses=[],
        ),
    )

    # Service with 0 ready endpoints and targetPort mismatch (9090 vs 8080)
    svc = _ns(
        metadata=_ns(name="api-svc", namespace="prod", creation_timestamp=now - timedelta(hours=1)),
        spec=_ns(
            type="ClusterIP",
            selector={"app": "api"},
            ports=[_ns(port=80, target_port=9090, name="http")],
        ),
        status=None,
    )
    ep = _ns(
        metadata=_ns(name="api-svc", namespace="prod"),
        subsets=[_ns(addresses=[], not_ready_addresses=[_ns(ip="10.0.0.5")])],
    )

    # Existing unrelated secret so sec_keys is populated
    existing_sec = _ns(
        metadata=_ns(name="other-secret", namespace="prod"),
        type="Opaque",
        data={"k": "v"},
        string_data={},
    )

    snap = ClusterSnapshot(
        nodes=[bad_node],
        pods=[pod_missing_sec],
        services=[svc],
        endpoints=[ep],
        secrets=[existing_sec],
        api_server_health={"readyz": "ok"},
    )

    report = run_cluster_health_scan(snapshot=snap, config=KubernetesFastConfig())
    assert report["clusterHealth"] == "critical"

    categories_found = {f["category"] for f in report["findings"]}
    assert "nodes" in categories_found
    assert "config_and_security" in categories_found
    assert "services_and_endpoints" in categories_found

    corr_ids = {c["id"] for c in report.get("correlatedRootCauses", [])}
    assert "CORR-NODE-001" in corr_ids
    assert "CORR-CFG-001" in corr_ids


def test_storage_quotas_webhooks_events_and_config_risks():
    now = datetime.now(timezone.utc)

    # StorageClass (Immediate)
    sc = _ns(
        metadata=_ns(name="gp3", annotations={"storageclass.kubernetes.io/is-default-class": "true"}),
        volume_binding_mode="Immediate",
    )
    # Pending PVC mounted by a Pod
    pvc = _ns(
        metadata=_ns(name="db-data", namespace="prod"),
        spec=_ns(storage_class_name="gp3", volume_name=None),
        status=_ns(phase="Pending"),
    )
    pod_mounting_pvc = _ns(
        metadata=_ns(
            name="db-0",
            namespace="prod",
            labels={"app": "db"},
            creation_timestamp=now - timedelta(minutes=15),
            deletion_timestamp=None,
            owner_references=[],
        ),
        spec=_ns(
            node_name=None,
            node_selector={"disk": "nvme"},
            containers=[],
            init_containers=[],
            volumes=[_ns(persistent_volume_claim=_ns(claim_name="db-data"), config_map=None, secret=None, host_path=None)],
            image_pull_secrets=[],
            service_account_name=None,
        ),
        status=_ns(
            phase="Pending",
            reason=None,
            message=None,
            conditions=[
                _ns(
                    type="PodScheduled",
                    status="False",
                    reason="Unschedulable",
                    message="0/3 nodes are available: 3 persistentvolumeclaim 'db-data' is not bound.",
                )
            ],
            container_statuses=[],
            init_container_statuses=[],
            ephemeral_container_statuses=[],
        ),
    )

    # Exhausted ResourceQuota
    rq = _ns(
        metadata=_ns(name="prod-quota", namespace="prod"),
        status=_ns(hard={"requests.cpu": "4", "pods": "10"}, used={"requests.cpu": "4", "pods": "9"}),
    )

    # ValidatingWebhookConfiguration with 0 ready endpoints and failurePolicy=Fail
    vwh = _ns(
        metadata=_ns(name="policy-webhook"),
        webhooks=[
            _ns(
                name="validate.policy.io",
                failure_policy="Fail",
                client_config=_ns(service=_ns(namespace="prod", name="webhook-svc")),
            )
        ],
    )
    wh_svc = _ns(
        metadata=_ns(name="webhook-svc", namespace="prod", creation_timestamp=now - timedelta(hours=2)),
        spec=_ns(type="ClusterIP", selector=None, ports=[]),
        status=None,
    )

    # Warning Event (recent) & Stale Event (2 hours old)
    recent_event = _ns(
        metadata=_ns(namespace="prod", creation_timestamp=now - timedelta(minutes=5)),
        type="Warning",
        reason="FailedScheduling",
        message="persistentvolumeclaim db-data is not bound",
        count=4,
        first_timestamp=now - timedelta(minutes=10),
        last_timestamp=now - timedelta(minutes=2),
        event_time=None,
        involved_object=_ns(kind="Pod", name="db-0", namespace="prod"),
    )
    stale_event = _ns(
        metadata=_ns(namespace="prod", creation_timestamp=now - timedelta(hours=3)),
        type="Warning",
        reason="Unhealthy",
        message="old transient probe warning",
        count=1,
        first_timestamp=now - timedelta(hours=3),
        last_timestamp=now - timedelta(hours=3),
        event_time=None,
        involved_object=_ns(kind="Pod", name="old-pod", namespace="prod"),
    )

    # Deployment with config risks (:latest image, 1 replica, no requests/limits/probes)
    risky_dep = _ns(
        metadata=_ns(name="legacy-app", namespace="prod", generation=1),
        spec=_ns(
            replicas=1,
            template=_ns(
                spec=_ns(
                    host_network=False,
                    host_pid=False,
                    volumes=[],
                    containers=[
                        _ns(
                            name="legacy",
                            image="myrepo/legacy:latest",
                            resources=None,
                            readiness_probe=None,
                            liveness_probe=None,
                            security_context=_ns(privileged=True),
                        )
                    ],
                )
            ),
        ),
        status=_ns(
            ready_replicas=1,
            available_replicas=1,
            updated_replicas=1,
            unavailable_replicas=0,
            observed_generation=1,
            conditions=[],
        ),
    )

    snap = ClusterSnapshot(
        storage_classes=[sc],
        pvcs=[pvc],
        pods=[pod_mounting_pvc],
        resource_quotas=[rq],
        validating_webhooks=[vwh],
        services=[wh_svc],
        events=[recent_event, stale_event],
        deployments=[risky_dep],
        custom_resources=[
            {
                "apiVersion": "postgresql.cnpg.io/v1",
                "kind": "Cluster",
                "metadata": {"name": "pg-main", "namespace": "prod", "generation": 1},
                "status": {
                    "observedGeneration": 1,
                    "conditions": [
                        {
                            "type": "Ready",
                            "status": "False",
                            "reason": "PrimaryDown",
                            "message": "Primary instance is not ready",
                        }
                    ],
                },
            }
        ],
        api_server_health={"readyz": "ok"},
    )

    # 1. Without config risks
    report = run_cluster_health_scan(snapshot=snap, include_config_risks=False)
    cats = {f["category"] for f in report["findings"]}
    assert "storage" in cats
    assert "scheduling" in cats
    assert "quotas_and_autoscaling" in cats
    assert "webhooks" in cats
    assert "events" in cats
    assert "custom_resources" in cats
    assert "configuration_risks" not in cats

    # Stale event should be filtered out, recent event included
    evt_findings = [f for f in report["findings"] if f["category"] == "events"]
    assert len(evt_findings) == 1
    assert evt_findings[0]["reason"] == "FailedScheduling"
    assert evt_findings[0]["status"] == "recurring"

    # Correlations should include CORR-STOR-001 and CORR-WH-001
    corr_ids = {c["id"] for c in report.get("correlatedRootCauses", [])}
    assert "CORR-STOR-001" in corr_ids
    assert "CORR-WH-001" in corr_ids

    # 2. With config risks enabled
    report_with_risks = run_cluster_health_scan(snapshot=snap, include_config_risks=True)
    cats_with_risks = {f["category"] for f in report_with_risks["findings"]}
    assert "configuration_risks" in cats_with_risks


def test_toolset_registration_and_config_classes():
    ts = KubernetesFastToolset()
    assert ts.name == "kubernetes/fast"
    assert len(ts.tools) == 1
    assert ts.tools[0].name == "kubernetes_fast"
    assert ts.config_classes == [KubernetesFastConfig]
