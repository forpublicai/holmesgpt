import logging
from typing import Any, Dict, List, Set, Tuple

from holmes.plugins.toolsets.kubernetes_fast.collector import ClusterSnapshot
from holmes.plugins.toolsets.kubernetes_fast.models import (
    Finding,
    KubernetesFastConfig,
    RelatedResource,
    Severity,
)
from holmes.plugins.toolsets.kubernetes_fast.utils import (
    age_minutes,
    labels_match_selector,
)

logger = logging.getLogger(__name__)


def _count_ready_endpoints(
    snap: ClusterSnapshot,
) -> Tuple[Dict[Tuple[str, str], int], Dict[Tuple[str, str], int]]:
    """Return (ready_counts, not_ready_counts) keyed by (namespace, service_name)."""
    ready_map: Dict[Tuple[str, str], int] = {}
    not_ready_map: Dict[Tuple[str, str], int] = {}

    for ep in snap.endpoints:
        meta = getattr(ep, "metadata", None)
        if not meta:
            continue
        key = (
            getattr(meta, "namespace", "default"),
            getattr(meta, "name", "unknown"),
        )
        r_count = 0
        nr_count = 0
        for sub in getattr(ep, "subsets", []) or []:
            r_count += len(getattr(sub, "addresses", []) or [])
            nr_count += len(getattr(sub, "not_ready_addresses", []) or [])
        ready_map[key] = r_count
        not_ready_map[key] = nr_count

    for es in snap.endpoint_slices:
        meta = getattr(es, "metadata", None)
        if not meta:
            continue
        labels = getattr(meta, "labels", {}) or {}
        svc_name = labels.get("kubernetes.io/service-name")
        if not svc_name:
            continue
        key = (getattr(meta, "namespace", "default"), svc_name)
        if key in ready_map:
            continue
        r_count = 0
        nr_count = 0
        for ep_item in getattr(es, "endpoints", []) or []:
            conds = getattr(ep_item, "conditions", None)
            is_ready = getattr(conds, "ready", True) if conds else True
            addrs = getattr(ep_item, "addresses", []) or []
            if is_ready:
                r_count += len(addrs)
            else:
                nr_count += len(addrs)
        ready_map[key] = ready_map.get(key, 0) + r_count
        not_ready_map[key] = not_ready_map.get(key, 0) + nr_count

    return ready_map, not_ready_map


def scan_networking(
    snap: ClusterSnapshot,
    config: KubernetesFastConfig,
) -> List[Finding]:
    """Scan Services, EndpointSlices, CoreDNS, Ingress, Gateway API, and NetworkPolicies (Sections 10–12, 17)."""
    findings: List[Finding] = []
    ready_eps, not_ready_eps = _count_ready_endpoints(snap)

    # Index pods by namespace
    pods_by_ns: Dict[str, List[Any]] = {}
    for pod in snap.pods:
        p_meta = getattr(pod, "metadata", None)
        if p_meta:
            pods_by_ns.setdefault(
                getattr(p_meta, "namespace", "default"), []
            ).append(pod)

    # Index services and their exposed ports by (namespace, name)
    svc_ports_map: Dict[Tuple[str, str], Set[Any]] = {}
    for svc in snap.services:
        meta = getattr(svc, "metadata", None)
        spec = getattr(svc, "spec", None)
        if not meta or not spec:
            continue
        key = (getattr(meta, "namespace", "default"), getattr(meta, "name", ""))
        ports_set: Set[Any] = set()
        for p in getattr(spec, "ports", []) or []:
            if getattr(p, "port", None) is not None:
                ports_set.add(getattr(p, "port"))
            if getattr(p, "name", None):
                ports_set.add(getattr(p, "name"))
        svc_ports_map[key] = ports_set

    # Index secrets by (namespace, name)
    secret_set: Set[Tuple[str, str]] = set()
    for sec in snap.secrets:
        s_meta = getattr(sec, "metadata", None)
        if s_meta:
            secret_set.add(
                (getattr(s_meta, "namespace", "default"), getattr(s_meta, "name", ""))
            )

    svc_idx = 0
    # 1. Services & EndpointSlices (Section 10)
    for svc in snap.services:
        meta = getattr(svc, "metadata", None)
        spec = getattr(svc, "spec", None)
        status = getattr(svc, "status", None)
        if not meta or not spec:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        svc_type = getattr(spec, "type", "ClusterIP") or "ClusterIP"
        selector = getattr(spec, "selector", None) or {}

        if svc_type == "ExternalName":
            continue

        # Check LoadBalancer unassigned ingress IP/hostname
        if svc_type == "LoadBalancer":
            lb = getattr(status, "load_balancer", None) if status else None
            lb_ing = getattr(lb, "ingress", None) if lb else None
            svc_age = age_minutes(getattr(meta, "creation_timestamp", None))
            if not lb_ing and (svc_age is None or svc_age >= config.pending_pod_minutes):
                svc_idx += 1
                findings.append(
                    Finding(
                        id=f"SVC-{svc_idx:03d}",
                        category="services_and_endpoints",
                        resource_type="Service",
                        resource_name=name,
                        namespace=ns,
                        severity=Severity.HIGH,
                        problem="LoadBalancer Service has no external IP/hostname assigned",
                        reason="LoadBalancerPending",
                        description=(
                            f"Service '{name}' (type=LoadBalancer) has no assigned ingress IP/hostname."
                        ),
                        evidence={
                            "type": svc_type,
                            "ageMinutes": round(svc_age, 1) if svc_age else None,
                        },
                        root_cause="Cloud controller manager or LoadBalancer controller has not provisioned an external IP.",
                        recommendation="Inspect Service events and LoadBalancer controller logs.",
                    )
                )

        if not selector:
            continue

        # Match selector against Pods in namespace
        ns_pods = pods_by_ns.get(ns, [])
        matched_pods = [
            p
            for p in ns_pods
            if labels_match_selector(
                getattr(getattr(p, "metadata", None), "labels", None), selector
            )
        ]

        if not matched_pods:
            svc_idx += 1
            findings.append(
                Finding(
                    id=f"SVC-{svc_idx:03d}",
                    category="services_and_endpoints",
                    resource_type="Service",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.HIGH,
                    problem="Service selector matches 0 Pods",
                    reason="SelectorMatchesNoPods",
                    description=(
                        f"Service '{name}' selector {selector} matches no Pods in namespace '{ns}'."
                    ),
                    evidence={"selector": selector},
                    root_cause="Service selector labels do not match any Pod labels, or backing workload is scaled to 0.",
                    recommendation="Verify Service spec.selector against Deployment/Pod template labels.",
                )
            )
            continue

        # Check ready endpoints count
        key = (ns, name)
        ready_cnt = ready_eps.get(key, 0)
        not_ready_cnt = not_ready_eps.get(key, 0)

        if ready_cnt == 0:
            svc_idx += 1
            related_pods = [
                RelatedResource(
                    type="Pod",
                    name=getattr(p.metadata, "name", "unknown"),
                    namespace=ns,
                )
                for p in matched_pods[:5]
                if getattr(p, "metadata", None)
            ]
            findings.append(
                Finding(
                    id=f"SVC-{svc_idx:03d}",
                    category="services_and_endpoints",
                    resource_type="Service",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.CRITICAL,
                    problem="Service has 0 ready endpoints",
                    reason="NoReadyEndpoints",
                    description=(
                        f"Service '{name}' matches {len(matched_pods)} Pod(s) but has 0 ready endpoints "
                        f"({not_ready_cnt} not-ready endpoints)."
                    ),
                    evidence={
                        "selector": selector,
                        "matchedPodCount": len(matched_pods),
                        "readyEndpoints": ready_cnt,
                        "notReadyEndpoints": not_ready_cnt,
                    },
                    root_cause="All backing Pods for this Service are either crashing, pending, or failing readiness probes.",
                    recommendation="Inspect the matched Pods to restore endpoint readiness.",
                    related_resources=related_pods,
                )
            )

        # Check targetPort vs Pod containerPort mismatch (when containerPorts are explicitly declared)
        declared_ports: Set[Any] = set()
        for mp in matched_pods:
            p_spec = getattr(mp, "spec", None)
            for c in getattr(p_spec, "containers", []) or [] if p_spec else []:
                for cp in getattr(c, "ports", []) or []:
                    if getattr(cp, "container_port", None) is not None:
                        declared_ports.add(getattr(cp, "container_port"))
                    if getattr(cp, "name", None):
                        declared_ports.add(getattr(cp, "name"))

        if declared_ports:
            for sp in getattr(spec, "ports", []) or []:
                tp = getattr(sp, "target_port", None) or getattr(sp, "port", None)
                # Convert numeric strings to int for comparison
                tp_norm: Any = int(tp) if isinstance(tp, str) and tp.isdigit() else tp
                if tp_norm is not None and tp_norm not in declared_ports:
                    svc_idx += 1
                    findings.append(
                        Finding(
                            id=f"SVC-{svc_idx:03d}",
                            category="services_and_endpoints",
                            resource_type="Service",
                            resource_name=name,
                            namespace=ns,
                            severity=Severity.MEDIUM,
                            problem=f"Service targetPort '{tp}' not found in Pod containerPorts",
                            reason="TargetPortMismatch",
                            description=(
                                f"Service '{name}' port {getattr(sp, 'port', '')} targets '{tp}', "
                                f"but matched Pods only declare ports {sorted(str(x) for x in declared_ports)}."
                            ),
                            evidence={
                                "servicePort": getattr(sp, "port", None),
                                "targetPort": tp,
                                "declaredPodPorts": sorted(str(x) for x in declared_ports),
                            },
                            root_cause="Service targetPort does not match the containerPort declared on the Pod spec.",
                            recommendation="Align Service spec.ports[].targetPort with the Pod containerPort.",
                        )
                    )

    # 2. DNS & CoreDNS Health (Section 11)
    dns_idx = 0
    dns_deps = [
        d
        for d in snap.kube_system_deployments
        if getattr(getattr(d, "metadata", None), "name", "") in ("coredns", "kube-dns")
    ]
    for d in dns_deps:
        d_meta = getattr(d, "metadata", None)
        d_spec = getattr(d, "spec", None)
        d_status = getattr(d, "status", None)
        d_name = getattr(d_meta, "name", "coredns") if d_meta else "coredns"
        desired = (getattr(d_spec, "replicas", 1) if d_spec else 1) or 1
        avail = (getattr(d_status, "available_replicas", 0) if d_status else 0) or 0
        if avail < desired:
            dns_idx += 1
            sev = Severity.CRITICAL if avail == 0 else Severity.HIGH
            findings.append(
                Finding(
                    id=f"DNS-{dns_idx:03d}",
                    category="dns",
                    resource_type="Deployment",
                    resource_name=d_name,
                    namespace="kube-system",
                    severity=sev,
                    problem=f"Cluster DNS ({d_name}) has {avail}/{desired} available replicas",
                    reason="CoreDNSDegraded" if avail > 0 else "CoreDNSOutage",
                    description=(
                        f"Cluster DNS Deployment '{d_name}' in kube-system has {avail}/{desired} available replicas."
                    ),
                    evidence={"desiredReplicas": desired, "availableReplicas": avail},
                    root_cause="CoreDNS Pods are unavailable, risking cluster-wide service name resolution failures.",
                    recommendation="Inspect CoreDNS Pods and kube-dns Service in kube-system immediately.",
                )
            )

    for ep in snap.kube_system_endpoints:
        ep_meta = getattr(ep, "metadata", None)
        ep_name = getattr(ep_meta, "name", "") if ep_meta else ""
        if ep_name in ("kube-dns", "coredns"):
            r_addrs = sum(
                len(getattr(s, "addresses", []) or [])
                for s in (getattr(ep, "subsets", []) or [])
            )
            if r_addrs == 0:
                dns_idx += 1
                findings.append(
                    Finding(
                        id=f"DNS-{dns_idx:03d}",
                        category="dns",
                        resource_type="Service",
                        resource_name=ep_name,
                        namespace="kube-system",
                        severity=Severity.CRITICAL,
                        problem=f"Cluster DNS Service '{ep_name}' has 0 ready endpoints",
                        reason="NoDNSEndpoints",
                        description=(
                            f"DNS Service '{ep_name}' in kube-system has no ready endpoints; "
                            f"internal DNS resolution is broken across the cluster."
                        ),
                        evidence={"service": ep_name, "readyEndpoints": 0},
                        root_cause="No CoreDNS/kube-dns Pods are ready to serve DNS queries.",
                        recommendation="Check CoreDNS Pods and CNI networking in kube-system.",
                    )
                )

    # 3. Ingress & Gateway API (Section 12)
    ing_idx = 0
    for ing in snap.ingresses:
        meta = getattr(ing, "metadata", None)
        spec = getattr(ing, "spec", None)
        if not meta or not spec:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")

        # Check TLS secrets
        for tls_item in getattr(spec, "tls", []) or []:
            sec_name = getattr(tls_item, "secret_name", None)
            if sec_name and (ns, sec_name) not in secret_set:
                ing_idx += 1
                findings.append(
                    Finding(
                        id=f"ING-{ing_idx:03d}",
                        category="ingress_and_gateway",
                        resource_type="Ingress",
                        resource_name=name,
                        namespace=ns,
                        severity=Severity.HIGH,
                        problem=f"Ingress references missing TLS Secret '{sec_name}'",
                        reason="MissingIngressTLSSecret",
                        description=(
                            f"Ingress '{name}' TLS configuration references Secret '{sec_name}', "
                            f"which does not exist in namespace '{ns}'."
                        ),
                        evidence={
                            "secretName": sec_name,
                            "hosts": getattr(tls_item, "hosts", []),
                        },
                        root_cause=f"TLS Secret '{sec_name}' is missing or cert-manager failed to issue it.",
                        recommendation="Create the TLS Secret or check Certificate/CertificateRequest resources.",
                    )
                )

        # Check backend service & port existence
        for rule in getattr(spec, "rules", []) or []:
            http_rule = getattr(rule, "http", None)
            if not http_rule:
                continue
            for path_item in getattr(http_rule, "paths", []) or []:
                backend = getattr(path_item, "backend", None)
                b_svc = getattr(backend, "service", None) if backend else None
                if not b_svc:
                    continue
                target_svc = getattr(b_svc, "name", None)
                port_obj = getattr(b_svc, "port", None)
                target_port = (
                    getattr(port_obj, "number", None) or getattr(port_obj, "name", None)
                    if port_obj
                    else None
                )
                if target_svc and (ns, target_svc) not in svc_ports_map:
                    ing_idx += 1
                    findings.append(
                        Finding(
                            id=f"ING-{ing_idx:03d}",
                            category="ingress_and_gateway",
                            resource_type="Ingress",
                            resource_name=name,
                            namespace=ns,
                            severity=Severity.HIGH,
                            problem=f"Ingress routes to non-existent Service '{target_svc}'",
                            reason="MissingBackendService",
                            description=(
                                f"Ingress '{name}' references backend Service '{target_svc}' "
                                f"which does not exist in namespace '{ns}'."
                            ),
                            evidence={
                                "backendService": target_svc,
                                "backendPort": target_port,
                                "path": getattr(path_item, "path", "/"),
                            },
                            root_cause=f"Backend Service '{target_svc}' was deleted or misnamed.",
                            recommendation="Update the Ingress backend service name or deploy the missing Service.",
                        )
                    )
                elif (
                    target_svc
                    and target_port is not None
                    and svc_ports_map.get((ns, target_svc))
                    and target_port not in svc_ports_map[(ns, target_svc)]
                ):
                    ing_idx += 1
                    findings.append(
                        Finding(
                            id=f"ING-{ing_idx:03d}",
                            category="ingress_and_gateway",
                            resource_type="Ingress",
                            resource_name=name,
                            namespace=ns,
                            severity=Severity.HIGH,
                            problem=f"Ingress backend port '{target_port}' not exposed on Service '{target_svc}'",
                            reason="BackendPortMismatch",
                            description=(
                                f"Ingress '{name}' targets port '{target_port}' on Service '{target_svc}', "
                                f"which only exposes {sorted(str(x) for x in svc_ports_map[(ns, target_svc)])}."
                            ),
                            evidence={
                                "backendService": target_svc,
                                "backendPort": target_port,
                                "servicePorts": sorted(
                                    str(x) for x in svc_ports_map[(ns, target_svc)]
                                ),
                            },
                            root_cause="Ingress backend port does not match any port on the target Service.",
                            recommendation="Align the Ingress backend port with the Service port definition.",
                        )
                    )

    # Check Gateway API custom resources if present
    for cr in snap.custom_resources:
        api_ver = cr.get("apiVersion", "")
        if "gateway.networking.k8s.io" not in api_ver:
            continue
        kind = cr.get("kind", "Gateway")
        meta = cr.get("metadata", {})
        c_name = meta.get("name", "unknown")
        c_ns = meta.get("namespace", "default")
        conds = cr.get("status", {}).get("conditions", []) or []
        for cond in conds:
            c_type = cond.get("type")
            c_status = cond.get("status")
            if c_type in ("Accepted", "Programmed", "ResolvedRefs") and c_status == "False":
                ing_idx += 1
                findings.append(
                    Finding(
                        id=f"GW-{ing_idx:03d}",
                        category="ingress_and_gateway",
                        resource_type=kind,
                        resource_name=c_name,
                        namespace=c_ns,
                        severity=Severity.HIGH,
                        problem=f"{kind} condition {c_type}=False",
                        reason=cond.get("reason") or f"{c_type}False",
                        description=f"{kind} '{c_name}' has {c_type}=False: {cond.get('message', '')}",
                        evidence=cond,
                        root_cause=cond.get("message") or f"{kind} configuration is not accepted/programmed.",
                        recommendation=f"Inspect {kind} spec and gateway controller logs.",
                    )
                )

    # 4. NetworkPolicies (Section 17)
    np_idx = 0
    for np in snap.network_policies:
        meta = getattr(np, "metadata", None)
        spec = getattr(np, "spec", None)
        if not meta or not spec:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        pod_sel = getattr(spec, "pod_selector", None)
        match_labels = getattr(pod_sel, "match_labels", None) if pod_sel else None
        match_exprs = getattr(pod_sel, "match_expressions", None) if pod_sel else None

        # Non-empty matchLabels that match 0 pods
        if match_labels and not match_exprs:
            ns_pods = pods_by_ns.get(ns, [])
            matched = [
                p
                for p in ns_pods
                if labels_match_selector(
                    getattr(getattr(p, "metadata", None), "labels", None),
                    match_labels,
                )
            ]
            if not matched:
                np_idx += 1
                findings.append(
                    Finding(
                        id=f"NP-{np_idx:03d}",
                        category="network_policies",
                        resource_type="NetworkPolicy",
                        resource_name=name,
                        namespace=ns,
                        severity=Severity.LOW,
                        problem="NetworkPolicy podSelector matches 0 Pods",
                        reason="NetworkPolicyMatchesNoPods",
                        description=(
                            f"NetworkPolicy '{name}' podSelector {match_labels} matches no Pods in '{ns}'."
                        ),
                        evidence={"podSelector": match_labels},
                        root_cause="Target Pods do not exist or have different labels than the NetworkPolicy podSelector.",
                        recommendation="Verify NetworkPolicy spec.podSelector against workload Pod labels.",
                    )
                )

        # Check Egress policy that blocks DNS (port 53) when egress rules are restricted
        policy_types = getattr(spec, "policy_types", []) or []
        egress_rules = getattr(spec, "egress", None)
        if "Egress" in policy_types and egress_rules:
            allows_dns_or_all = False
            for er in egress_rules:
                ports = getattr(er, "ports", None)
                if not ports:
                    # Rule with no ports field allows all ports
                    allows_dns_or_all = True
                    break
                for p_item in ports:
                    p_val = getattr(p_item, "port", None)
                    if p_val in (53, "53", "dns", "domain"):
                        allows_dns_or_all = True
                        break
            if not allows_dns_or_all:
                np_idx += 1
                findings.append(
                    Finding(
                        id=f"NP-{np_idx:03d}",
                        category="network_policies",
                        resource_type="NetworkPolicy",
                        resource_name=name,
                        namespace=ns,
                        severity=Severity.MEDIUM,
                        problem="NetworkPolicy restricts Egress without allowing DNS port 53",
                        reason="PotentialDNSBlock",
                        description=(
                            f"NetworkPolicy '{name}' enforces Egress port restrictions but does not permit port 53 (DNS)."
                        ),
                        evidence={"policyTypes": policy_types},
                        root_cause="Egress rules restrict outbound ports without an explicit rule for UDP/TCP 53.",
                        recommendation="Ensure another NetworkPolicy allows DNS egress or add UDP/TCP port 53 to egress rules.",
                    )
                )

    logger.info(
        f"[kubernetes/fast] Networking scanner finished: {len(findings)} networking/DNS/ingress findings"
    )
    return findings

