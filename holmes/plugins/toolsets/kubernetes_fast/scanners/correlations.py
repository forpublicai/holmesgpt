import logging
from typing import Dict, List, Set, Tuple

from holmes.plugins.toolsets.kubernetes_fast.collector import ClusterSnapshot
from holmes.plugins.toolsets.kubernetes_fast.models import (
    CorrelatedIssue,
    Finding,
    Severity,
)

logger = logging.getLogger(__name__)


def build_correlations(
    snap: ClusterSnapshot,
    findings: List[Finding],
) -> List[CorrelatedIssue]:
    """Correlate individual resource findings into cross-resource root causes (Section 26)."""
    correlations: List[CorrelatedIssue] = []

    # Build ReplicaSet -> Deployment ownership map: (namespace, rs_name) -> deployment_name
    rs_to_dep: Dict[Tuple[str, str], str] = {}
    for rs in snap.replica_sets:
        meta = getattr(rs, "metadata", None)
        if not meta:
            continue
        ns = getattr(meta, "namespace", "default")
        rs_name = getattr(meta, "name", "")
        for oref in getattr(meta, "owner_references", []) or []:
            if getattr(oref, "kind", "") == "Deployment":
                rs_to_dep[(ns, rs_name)] = getattr(oref, "name", "")

    # Index findings by category & resource
    node_not_ready_findings = [
        f for f in findings if f.category == "nodes" and "NotReady" in f.problem
    ]
    dns_findings = [f for f in findings if f.category == "dns"]
    cfg_findings = [
        f
        for f in findings
        if f.category == "config_and_security"
        and f.reason == "MissingReferencedResource"
    ]
    storage_findings = [
        f
        for f in findings
        if f.category == "storage"
        and f.resource_type == "PersistentVolumeClaim"
    ]
    webhook_findings = [
        f
        for f in findings
        if f.category == "webhooks" and f.severity == Severity.CRITICAL
    ]
    dep_findings = [
        f
        for f in findings
        if f.category == "workloads" and f.resource_type == "Deployment"
    ]
    pod_findings_by_ns: Dict[str, List[Finding]] = {}
    for f in findings:
        if f.category == "pods" and f.namespace:
            pod_findings_by_ns.setdefault(f.namespace, []).append(f)

    # 1. Node Failure Cascade (Example B)
    for idx, nf in enumerate(node_not_ready_findings, start=1):
        node_name = nf.resource_name
        affected_resources: List[str] = []
        workloads_set: Set[str] = set()
        pod_count = 0

        for pod in snap.pods:
            spec = getattr(pod, "spec", None)
            meta = getattr(pod, "metadata", None)
            if not spec or not meta or getattr(spec, "node_name", None) != node_name:
                continue
            pod_count += 1
            p_ns = getattr(meta, "namespace", "default")
            p_name = getattr(meta, "name", "unknown")
            affected_resources.append(f"Pod/{p_ns}/{p_name}")
            for oref in getattr(meta, "owner_references", []) or []:
                o_kind = getattr(oref, "kind", "")
                o_name = getattr(oref, "name", "")
                if o_kind == "ReplicaSet" and (p_ns, o_name) in rs_to_dep:
                    workloads_set.add(f"Deployment/{p_ns}/{rs_to_dep[(p_ns, o_name)]}")
                elif o_kind:
                    workloads_set.add(f"{o_kind}/{p_ns}/{o_name}")

        correlations.append(
            CorrelatedIssue(
                id=f"CORR-NODE-{idx:03d}",
                severity=Severity.CRITICAL,
                title=f"Node '{node_name}' is NotReady impacting {pod_count} Pods and {len(workloads_set)} workloads",
                root_cause=nf.root_cause or f"Worker node '{node_name}' is unreachable / NotReady.",
                diagnosis=(
                    f"Single worker node '{node_name}' is NotReady, causing {pod_count} Pods "
                    f"and {len(workloads_set)} workloads to degrade. Investigate the node and kubelet "
                    f"rather than treating each Pod failure as a separate incident."
                ),
                recommendation=nf.recommendation
                or "Investigate node VM/host health and kubelet service.",
                primary_resource={"type": "Node", "name": node_name},
                affected_resources=sorted(workloads_set) + affected_resources[:10],
                evidence=nf.evidence,
            )
        )

    # 2. Cluster DNS Outage Cascade (Example D)
    if dns_findings:
        df = dns_findings[0]
        correlations.append(
            CorrelatedIssue(
                id="CORR-DNS-001",
                severity=df.severity,
                title=df.problem,
                root_cause=df.root_cause or "CoreDNS has insufficient ready replicas/endpoints.",
                diagnosis=(
                    "Cluster DNS (CoreDNS / kube-dns) is degraded or has 0 ready endpoints. "
                    "Application Pods across namespaces will fail internal and external DNS resolution."
                ),
                recommendation=df.recommendation
                or "Restore CoreDNS Pods in kube-system immediately.",
                primary_resource={
                    "type": df.resource_type,
                    "name": df.resource_name,
                    "namespace": df.namespace,
                },
                affected_resources=["Service/kube-system/kube-dns"],
                evidence=df.evidence,
            )
        )

    # 3. Missing ConfigMap / Secret Cascade (Example E)
    for idx, cf in enumerate(cfg_findings, start=1):
        missing_refs = cf.evidence.get("missingReferences", [])
        ns = cf.namespace or "default"
        affected: List[str] = [f"Pod/{ns}/{cf.resource_name}"]
        for rel in cf.related_resources:
            if rel.type == "ReplicaSet" and (ns, rel.name) in rs_to_dep:
                affected.append(f"Deployment/{ns}/{rs_to_dep[(ns, rel.name)]}")
            else:
                affected.append(f"{rel.type}/{ns}/{rel.name}")

        correlations.append(
            CorrelatedIssue(
                id=f"CORR-CFG-{idx:03d}",
                severity=Severity.HIGH,
                title=f"Missing configuration ({', '.join(missing_refs[:2])}) blocking Pod '{cf.resource_name}'",
                root_cause=cf.root_cause or f"Referenced resource {missing_refs} is missing in '{ns}'.",
                diagnosis=(
                    f"Missing {', '.join(missing_refs)} in namespace '{ns}' is preventing "
                    f"Pod '{cf.resource_name}' from starting and stalling its parent workload."
                ),
                recommendation=cf.recommendation
                or "Create the missing Secret/ConfigMap or fix the workload reference.",
                primary_resource={
                    "type": "Pod",
                    "name": cf.resource_name,
                    "namespace": ns,
                },
                affected_resources=affected,
                evidence=cf.evidence,
            )
        )

    # 4. Storage / PVC Pending Cascade (Example C)
    for idx, sf in enumerate(storage_findings, start=1):
        consumers = sf.evidence.get("mountedByPods", [])
        if not consumers:
            continue
        ns = sf.namespace or "default"
        affected = [f"Pod/{ns}/{c}" for c in consumers]
        correlations.append(
            CorrelatedIssue(
                id=f"CORR-STOR-{idx:03d}",
                severity=sf.severity,
                title=f"PVC '{sf.resource_name}' ({sf.reason}) is blocking {len(consumers)} Pod(s)",
                root_cause=sf.root_cause or "PersistentVolumeClaim cannot be bound.",
                diagnosis=(
                    f"Underlying issue is storage provisioning for PVC '{sf.resource_name}' "
                    f"in namespace '{ns}', not the individual Pending Pods ({', '.join(consumers[:3])})."
                ),
                recommendation=sf.recommendation
                or "Check StorageClass and CSI provisioner logs.",
                primary_resource={
                    "type": "PersistentVolumeClaim",
                    "name": sf.resource_name,
                    "namespace": ns,
                },
                affected_resources=affected,
                evidence=sf.evidence,
            )
        )

    # 5. Admission Webhook Blocker Cascade
    for idx, wf in enumerate(webhook_findings, start=1):
        correlations.append(
            CorrelatedIssue(
                id=f"CORR-WH-{idx:03d}",
                severity=Severity.CRITICAL,
                title=wf.problem,
                root_cause=wf.root_cause or "Admission webhook service has 0 ready endpoints.",
                diagnosis=(
                    f"{wf.resource_type} '{wf.resource_name}' has failurePolicy=Fail and 0 ready endpoints, "
                    f"which can block Pod/resource creation across the cluster."
                ),
                recommendation=wf.recommendation
                or "Restore webhook controller Pods in the target namespace.",
                primary_resource={
                    "type": wf.resource_type,
                    "name": wf.resource_name,
                },
                affected_resources=[str(wf.evidence.get("targetService", ""))],
                evidence=wf.evidence,
            )
        )

    # 6. Deployment -> ReplicaSet -> Pod -> Service Failure Chain (Example A)
    for idx, df in enumerate(dep_findings, start=1):
        ns = df.namespace or "default"
        dep_name = df.resource_name
        ns_pod_findings = pod_findings_by_ns.get(ns, [])

        # Find failing pods belonging to this Deployment
        child_pod_findings: List[Finding] = []
        for pf in ns_pod_findings:
            for rel in pf.related_resources:
                if rel.type == "Deployment" and rel.name == dep_name:
                    child_pod_findings.append(pf)
                    break
                if (
                    rel.type == "ReplicaSet"
                    and rs_to_dep.get((ns, rel.name)) == dep_name
                ):
                    child_pod_findings.append(pf)
                    break

        if not child_pod_findings:
            continue

        desired = df.evidence.get("desiredReplicas", 0)
        avail = df.evidence.get("availableReplicas", 0)
        pod_reasons = list(dict.fromkeys(pf.reason for pf in child_pod_findings))
        first_root_cause = next(
            (pf.root_cause for pf in child_pod_findings if pf.root_cause),
            f"Child Pods are failing with {', '.join(pod_reasons)}.",
        )

        correlations.append(
            CorrelatedIssue(
                id=f"CORR-DEP-{idx:03d}",
                severity=df.severity,
                title=(
                    f"Deployment '{ns}/{dep_name}' has {avail}/{desired} available replicas "
                    f"due to {len(child_pod_findings)} failing Pod(s) ({', '.join(pod_reasons)})"
                ),
                root_cause=first_root_cause,
                diagnosis=(
                    f"Deployment '{dep_name}' expects {desired} replicas, but {len(child_pod_findings)} "
                    f"Pod(s) are failing with {', '.join(pod_reasons)} ({avail} healthy replica(s) remaining)."
                ),
                recommendation=child_pod_findings[0].recommendation
                or df.recommendation
                or "Inspect the failing Pod containers.",
                primary_resource={
                    "type": "Deployment",
                    "name": dep_name,
                    "namespace": ns,
                },
                affected_resources=[
                    f"Pod/{ns}/{pf.resource_name} ({pf.reason})"
                    for pf in child_pod_findings[:10]
                ],
                evidence={
                    "desiredReplicas": desired,
                    "availableReplicas": avail,
                    "podFailureReasons": pod_reasons,
                },
            )
        )

    logger.info(
        f"[kubernetes/fast] Correlation engine finished: {len(correlations)} correlated root causes identified"
    )
    return correlations

