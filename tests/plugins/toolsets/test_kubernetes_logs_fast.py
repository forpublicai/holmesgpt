from holmes.plugins.toolsets.kubernetes_logs_fast import (
    CollectionError,
    KubernetesLogsFastToolset,
    LogsFastConfig,
    run_log_scan,
)
from holmes.plugins.toolsets.kubernetes_logs_fast.fetcher import PodLogBundle
from holmes.plugins.toolsets.kubernetes_logs_fast.parser import parse_raw_logs


def test_clean_logs_and_benign_exclusions_return_healthy():
    raw_clean_logs = "\n".join(
        [
            "2026-11-10T10:00:01Z Starting payment service on port 8080",
            '2026-11-10T10:00:02Z {"timestamp":"2026-11-10T10:00:02Z","level":"info","message":"Worker started","error":null}',
            '2026-11-10T10:00:03Z 10.244.0.1 - - "GET /healthz HTTP/1.1" 200 2',
            '2026-11-10T10:00:04Z 10.244.0.1 - - "GET /readyz HTTP/1.1" 200 2',
            "2026-11-10T10:00:05Z Batch completed: 0 errors, 0 warnings, exit code 0",
        ]
    )
    entries = parse_raw_logs(raw_clean_logs, default_container="app", source="current")
    bundle = PodLogBundle(
        namespace="prod",
        pod="payment-api-1",
        workload="Deployment/payment-api",
        entries=entries,
        containers_scanned=1,
    )

    report = run_log_scan(
        namespace="prod",
        bundles_override=[bundle],
    )
    assert report["logHealth"] == "healthy"
    assert report["findings"] == []
    assert report["summary"]["podsScanned"] == 1
    assert report["summary"]["podsWithIssues"] == 0
    assert report["summary"]["cleanPodsSkipped"] == 1
    assert report["summary"]["totalLogEntriesExamined"] == 5


def test_multiline_stack_traces_json_errors_and_deduplication():
    lines = [
        # 1. Java OOM with multiline stack trace
        "2026-11-10T10:10:00Z Exception in thread \"main\" java.lang.OutOfMemoryError: Java heap space",
        "2026-11-10T10:10:00Z \tat com.example.BatchProcessor.allocate(BatchProcessor.java:88)",
        "2026-11-10T10:10:00Z \tat com.example.BatchProcessor.run(BatchProcessor.java:42)",
        "2026-11-10T10:10:00Z Caused by: java.lang.OutOfMemoryError: Java heap space",
        # 2. Python Traceback
        "2026-11-10T10:11:00Z Traceback (most recent call last):",
        '  File "/app/worker.py", line 19, in <module>',
        "    import non_existent_pkg",
        "ModuleNotFoundError: No module named 'non_existent_pkg'",
        # 3. Structured JSON Database Error
        '2026-11-10T10:12:00Z {"level":"error","message":"database connection failed","error":"connection pool exhausted","error_code":"DB_POOL_01"}',
    ]
    # 4. 25 repeated connection refused lines with varying timestamps and ports
    for i in range(25):
        lines.append(
            f"2026-11-10T10:15:{i:02d}Z ERROR dial tcp 10.96.44.{i}:6379: connect: connection refused (retrying attempt {i})"
        )

    raw_logs = "\n".join(lines)
    entries = parse_raw_logs(raw_logs, default_container="app", source="current")

    # Verify multiline coalescing combined the Java stack trace and Python traceback
    assert len(entries) == 3 + 25
    assert "BatchProcessor.java:88" in entries[0].content
    assert "ModuleNotFoundError" in entries[1].content

    bundle = PodLogBundle(
        namespace="prod",
        pod="payment-api-7f8d9",
        workload="Deployment/payment-api",
        entries=entries,
        containers_scanned=1,
    )

    report = run_log_scan(namespace="prod", bundles_override=[bundle])
    assert report["logHealth"] == "critical"
    assert report["summary"]["podsWithIssues"] == 1

    findings = report["findings"]
    rule_ids = {f["ruleId"] for f in findings}
    assert "LOG-MEM-001" in rule_ids
    assert "LOG-DB-001" in rule_ids
    assert "LOG-NET-001" in rule_ids

    # Check that the 25 repeated connection refused lines collapsed into 1 finding with occurrences=25
    net_finding = next(f for f in findings if f["ruleId"] == "LOG-NET-001")
    assert net_finding["occurrences"] == 25
    assert net_finding["firstTimestamp"] == "2026-11-10T10:15:00Z"
    assert net_finding["lastTimestamp"] == "2026-11-10T10:15:24Z"

    # Check structured JSON error_code preservation
    db_finding = next(f for f in findings if f["ruleId"] == "LOG-DB-001")
    assert db_finding["errorCode"] == "DB_POOL_01"

    # Check behavioural retry loop detection (BEHAV-001)
    behav_ids = {b["id"] for b in report.get("behaviouralFindings", [])}
    assert "BEHAV-001" in behav_ids


def test_behavioral_flapping_auth_spike_and_startup_exit():
    raw_prev = "\n".join(
        [
            "2026-11-10T09:00:01Z Starting server v1.2.0...",
            "2026-11-10T09:00:02Z Fatal: missing environment variable SECRET_KEY, shutting down",
        ]
    )
    raw_curr = "\n".join(
        [
            "2026-11-10T09:05:01Z Readiness probe succeeded",
            "2026-11-10T09:05:10Z Readiness probe failed",
            "2026-11-10T09:05:20Z Readiness probe succeeded",
            "2026-11-10T09:05:30Z Readiness probe failed",
            "2026-11-10T09:06:01Z WARN Authentication failed for user admin (401 Unauthorized)",
            "2026-11-10T09:06:02Z WARN Authentication failed for user admin (401 Unauthorized)",
            "2026-11-10T09:06:03Z WARN Authentication failed for user admin (401 Unauthorized)",
            "2026-11-10T09:06:04Z WARN Authentication failed for user admin (401 Unauthorized)",
            "2026-11-10T09:06:05Z WARN Authentication failed for user admin (401 Unauthorized)",
        ]
    )

    entries = parse_raw_logs(
        raw_prev, default_container="web", source="previous"
    ) + parse_raw_logs(raw_curr, default_container="web", source="current")

    bundle = PodLogBundle(
        namespace="prod",
        pod="web-1",
        workload="Deployment/web",
        entries=entries,
        containers_scanned=1,
    )

    report = run_log_scan(namespace="prod", bundles_override=[bundle])
    behav_ids = {b["id"] for b in report.get("behaviouralFindings", [])}
    assert "BEHAV-002" in behav_ids  # Flapping
    assert "BEHAV-003" in behav_ids  # Auth failure spike
    assert "BEHAV-004" in behav_ids  # Startup and immediate exit


def test_custom_rules_and_collection_errors_prevent_false_healthy():
    # 1. Verify collection failure with 0 log entries reports "unverified", not "healthy"
    col_err = CollectionError(
        namespace="prod",
        pod="locked-pod",
        container="app",
        reason="RBACDenied",
        message="Forbidden: User cannot get pods/log in namespace prod",
    )
    empty_bundle = PodLogBundle(
        namespace="prod", pod="locked-pod", workload="Deployment/locked", entries=[]
    )
    report_err = run_log_scan(
        namespace="prod",
        bundles_override=[empty_bundle],
        collection_errors_override=[col_err],
    )
    assert report_err["logHealth"] == "unverified"
    assert len(report_err["collectionErrors"]) == 1

    # 2. Verify custom YAML rules in LogsFastConfig
    cfg = LogsFastConfig(
        custom_rules=[
            {
                "id": "CUSTOM-BILLING-001",
                "name": "Stripe webhook signature failure",
                "category": "billing",
                "severity": "critical",
                "patterns": ["STRIPE_SIG_MISMATCH"],
                "description": "Stripe webhook signature verification failed.",
                "recommendation": "Check STRIPE_WEBHOOK_SECRET in namespace secrets.",
            }
        ]
    )
    entries = parse_raw_logs(
        "2026-11-10T11:00:00Z Payment gateway rejected event: STRIPE_SIG_MISMATCH",
        default_container="billing",
    )
    b = PodLogBundle(
        namespace="prod",
        pod="billing-1",
        workload="Deployment/billing",
        entries=entries,
        containers_scanned=1,
    )
    report_custom = run_log_scan(namespace="prod", config=cfg, bundles_override=[b])
    assert report_custom["logHealth"] == "critical"
    assert report_custom["findings"][0]["ruleId"] == "CUSTOM-BILLING-001"


def test_fetch_single_container_logs_kwargs():
    from unittest.mock import MagicMock
    from holmes.plugins.toolsets.kubernetes_logs_fast.fetcher import (
        ContainerTarget,
        _fetch_single_container_logs,
    )

    mock_core = MagicMock()
    mock_core.read_namespaced_pod_log.return_value = "2026-11-10T11:00:00Z app started"
    target = ContainerTarget(
        namespace="default",
        pod="pod-1",
        workload="Deployment/app",
        container="main",
    )

    t, source, raw, byte_len, err = _fetch_single_container_logs(
        core_v1=mock_core,
        target=target,
        previous=False,
        tail_lines=100,
        since_seconds=3600,
        limit_bytes=100000,
    )
    assert err is None
    assert "app started" in raw

    # Ensure timeout_seconds is NOT passed (which caused ApiTypeError)
    call_kwargs = mock_core.read_namespaced_pod_log.call_args[1]
    assert "timeout_seconds" not in call_kwargs
    assert call_kwargs["_request_timeout"] == 15
    assert call_kwargs["name"] == "pod-1"
    assert call_kwargs["namespace"] == "default"
    assert call_kwargs["container"] == "main"
    assert call_kwargs["tail_lines"] == 100


def test_toolset_registration():
    ts = KubernetesLogsFastToolset()
    assert ts.name == "kubernetes/logs_fast"
    assert len(ts.tools) == 1
    assert ts.tools[0].name == "logs_fast"
    assert ts.config_classes == [LogsFastConfig]

