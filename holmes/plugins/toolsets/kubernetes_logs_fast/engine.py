import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from holmes.plugins.toolsets.kubernetes_fast.models import SEVERITY_ORDER, Severity
from holmes.plugins.toolsets.kubernetes_logs_fast.behavior import (
    detect_behavioral_anomalies,
)
from holmes.plugins.toolsets.kubernetes_logs_fast.fetcher import (
    PodLogBundle,
    collect_logs_for_scope,
)
from holmes.plugins.toolsets.kubernetes_logs_fast.models import (
    BehavioralFinding,
    CollectionError,
    LogFinding,
    LogsFastConfig,
    format_log_scan_report,
)
from holmes.plugins.toolsets.kubernetes_logs_fast.parser import fingerprint_log_message
from holmes.plugins.toolsets.kubernetes_logs_fast.rule_engine import (
    load_compiled_rules,
    match_entry_against_rules,
)

logger = logging.getLogger(__name__)


def run_log_scan(
    namespace: Optional[str] = None,
    pod_name: Optional[str] = None,
    deployment: Optional[str] = None,
    statefulset: Optional[str] = None,
    daemonset: Optional[str] = None,
    container: Optional[str] = None,
    node: Optional[str] = None,
    system_components_only: bool = False,
    tail_lines: Optional[int] = None,
    since_seconds: Optional[int] = None,
    include_warnings: Optional[bool] = None,
    extra_keywords: Optional[str] = None,
    config: Optional[LogsFastConfig] = None,
    bundles_override: Optional[List[PodLogBundle]] = None,
    collection_errors_override: Optional[List[CollectionError]] = None,
) -> Dict[str, Any]:
    """Run the Kubernetes Fast Log Analysis Engine and return a compact report."""
    overall_start = time.monotonic()
    cfg = config or LogsFastConfig()

    scope: Dict[str, Any] = {"namespace": namespace or "all"}
    if pod_name:
        scope["pod"] = pod_name
    if deployment:
        scope["deployment"] = deployment
    if statefulset:
        scope["statefulset"] = statefulset
    if daemonset:
        scope["daemonset"] = daemonset
    if container:
        scope["container"] = container
    if node:
        scope["node"] = node
    if system_components_only:
        scope["systemComponentsOnly"] = True

    logger.info(f"[kubernetes/logs_fast] Starting log scan with scope={scope}")

    compiled_rules = load_compiled_rules(
        config=cfg,
        include_warnings=include_warnings,
        extra_keywords=extra_keywords,
    )
    custom_excludes_lower = [ex.lower() for ex in cfg.custom_exclude_patterns if ex]

    if bundles_override is not None:
        bundles = bundles_override
        collection_errors = collection_errors_override or []
    else:
        bundles, collection_errors = collect_logs_for_scope(
            config=cfg,
            namespace=namespace,
            pod_name=pod_name,
            deployment=deployment,
            statefulset=statefulset,
            daemonset=daemonset,
            container_filter=container,
            node_filter=node,
            system_components_only=system_components_only,
            tail_lines_override=tail_lines,
            since_seconds_override=since_seconds,
        )

    all_findings: List[LogFinding] = []
    all_behavioral: List[BehavioralFinding] = []
    total_entries_examined = 0
    total_error_matches = 0
    total_warning_matches = 0
    containers_scanned = 0
    pods_with_issues = 0

    for bundle in bundles:
        containers_scanned += max(
            bundle.containers_scanned,
            len({e.container for e in bundle.entries}),
        )
        total_entries_examined += len(bundle.entries)

        # Deduplicate findings per pod by (container, source, rule_id, message_fingerprint)
        pod_groups: Dict[Tuple[str, str, str, str], Tuple[LogFinding, int]] = {}

        for entry in bundle.entries:
            matched = match_entry_against_rules(
                entry, compiled_rules, custom_excludes_lower
            )
            if not matched:
                continue

            rule, matched_pat = matched
            if rule.severity in (Severity.CRITICAL, Severity.HIGH):
                total_error_matches += 1
            else:
                total_warning_matches += 1

            fp = fingerprint_log_message(entry.content)
            g_key = (entry.container, entry.source, rule.id, fp)

            if g_key not in pod_groups:
                finding = LogFinding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    namespace=bundle.namespace,
                    workload=bundle.workload,
                    pod=bundle.pod,
                    container=entry.container,
                    source=entry.source,
                    matched_pattern=matched_pat,
                    sample_log=entry.content[:500],
                    occurrences=1,
                    first_timestamp=entry.timestamp_str,
                    last_timestamp=entry.timestamp_str,
                    description=rule.description,
                    recommendation=rule.recommendation,
                    error_code=entry.json_error_code,
                )
                pod_groups[g_key] = (finding, rule.min_occurrences)
            else:
                existing, min_occ = pod_groups[g_key]
                existing.occurrences += 1
                if entry.timestamp_str:
                    if not existing.first_timestamp:
                        existing.first_timestamp = entry.timestamp_str
                    existing.last_timestamp = entry.timestamp_str

        # Filter by min_occurrences and cap per pod
        pod_findings = [
            f for f, min_occ in pod_groups.values() if f.occurrences >= min_occ
        ]
        pod_findings.sort(
            key=lambda x: (
                SEVERITY_ORDER.get(x.severity.value, 99),
                -x.occurrences,
            )
        )
        if len(pod_findings) > cfg.max_findings_per_pod:
            pod_findings = pod_findings[: cfg.max_findings_per_pod]

        # Run behavioural sequence detectors for this pod
        pod_behav = detect_behavioral_anomalies(
            namespace=bundle.namespace,
            workload=bundle.workload,
            pod=bundle.pod,
            entries=bundle.entries,
        )

        if pod_findings or pod_behav:
            pods_with_issues += 1
            all_findings.extend(pod_findings)
            all_behavioral.extend(pod_behav)

    report = format_log_scan_report(
        scope=scope,
        pods_scanned=len(bundles),
        containers_scanned=containers_scanned,
        pods_with_issues=pods_with_issues,
        total_entries_examined=total_entries_examined,
        total_error_matches=total_error_matches,
        total_warning_matches=total_warning_matches,
        findings=all_findings,
        behavioral_findings=all_behavioral,
        collection_errors=collection_errors,
        max_total_findings=cfg.max_total_findings,
    )

    elapsed_ms = (time.monotonic() - overall_start) * 1000.0
    logger.info(
        f"[kubernetes/logs_fast] Scan completed in {elapsed_ms:.0f}ms: "
        f"logHealth={report['logHealth']}, podsScanned={len(bundles)}, "
        f"podsWithIssues={pods_with_issues}, entriesExamined={total_entries_examined}, "
        f"uniqueFindings={len(all_findings)}, behaviouralFindings={len(all_behavioral)}"
    )
    return report

