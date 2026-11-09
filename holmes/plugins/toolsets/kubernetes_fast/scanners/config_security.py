import base64
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography import x509

from holmes.plugins.toolsets.kubernetes_fast.collector import ClusterSnapshot
from holmes.plugins.toolsets.kubernetes_fast.models import (
    Finding,
    KubernetesFastConfig,
    RelatedResource,
    Severity,
)
from holmes.plugins.toolsets.kubernetes_fast.scanners.networking import (
    _count_ready_endpoints,
)
from holmes.plugins.toolsets.kubernetes_fast.utils import owner_references_to_related

logger = logging.getLogger(__name__)


def _parse_cert_expiry_days(b64_cert: str) -> Optional[Tuple[float, str, str]]:
    """Decode base64 PEM certificate and return (days_remaining, not_after_iso, subject)."""
    try:
        pem_bytes = base64.b64decode(b64_cert)
        cert = x509.load_pem_x509_certificate(pem_bytes)
        not_after = getattr(cert, "not_valid_after_utc", None)
        if not_after is None:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days = (not_after - now).total_seconds() / 86400.0
        subj = cert.subject.rfc4514_string()
        return days, not_after.strftime("%Y-%m-%dT%H:%M:%SZ"), subj
    except Exception:
        return None


def scan_config_security_certs_webhooks(
    snap: ClusterSnapshot,
    config: KubernetesFastConfig,
) -> List[Finding]:
    """Scan ConfigMap/Secret refs, RBAC, TLS certificates, and Admission Webhooks (Sections 16, 23, 24)."""
    findings: List[Finding] = []

    # 1. Index ConfigMaps, Secrets, ServiceAccounts, Roles, ClusterRoles
    cm_keys: Dict[Tuple[str, str], Set[str]] = {}
    for cm in snap.config_maps:
        meta = getattr(cm, "metadata", None)
        if not meta:
            continue
        k_set: Set[str] = set((getattr(cm, "data", None) or {}).keys()) | set(
            (getattr(cm, "binary_data", None) or {}).keys()
        )
        cm_keys[(getattr(meta, "namespace", "default"), getattr(meta, "name", ""))] = k_set

    sec_keys: Dict[Tuple[str, str], Set[str]] = {}
    for sec in snap.secrets:
        meta = getattr(sec, "metadata", None)
        if not meta:
            continue
        s_set: Set[str] = set((getattr(sec, "data", None) or {}).keys()) | set(
            (getattr(sec, "string_data", None) or {}).keys()
        )
        sec_keys[(getattr(meta, "namespace", "default"), getattr(meta, "name", ""))] = s_set

    sa_set: Set[Tuple[str, str]] = set()
    for sa in snap.service_accounts:
        meta = getattr(sa, "metadata", None)
        if meta:
            sa_set.add(
                (getattr(meta, "namespace", "default"), getattr(meta, "name", ""))
            )

    role_set: Set[Tuple[str, str]] = set()
    for r in snap.roles:
        meta = getattr(r, "metadata", None)
        if meta:
            role_set.add(
                (getattr(meta, "namespace", "default"), getattr(meta, "name", ""))
            )

    cluster_role_set: Set[str] = set()
    for cr in snap.cluster_roles:
        meta = getattr(cr, "metadata", None)
        if meta:
            cluster_role_set.add(getattr(meta, "name", ""))

    cfg_idx = 0

    # 2. Check Pod references to ConfigMaps, Secrets, and ServiceAccounts (Section 16)
    have_cms = bool(snap.config_maps) or "ConfigMaps" not in " ".join(snap.skipped_apis)
    have_secs = bool(snap.secrets) or "Secrets" not in " ".join(snap.skipped_apis)

    for pod in snap.pods:
        meta = getattr(pod, "metadata", None)
        spec = getattr(pod, "spec", None)
        status = getattr(pod, "status", None)
        if not meta or not spec:
            continue
        if status and getattr(status, "phase", None) == "Succeeded":
            continue

        pod_name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        related = owner_references_to_related(meta, ns)

        missing_refs: List[str] = []

        # ServiceAccount check
        sa_name = getattr(spec, "service_account_name", None) or getattr(
            spec, "service_account", None
        )
        if sa_name and sa_set and (ns, sa_name) not in sa_set:
            missing_refs.append(f"ServiceAccount/{sa_name}")

        # imagePullSecrets check
        if have_secs and sec_keys:
            for ips in getattr(spec, "image_pull_secrets", []) or []:
                ips_name = getattr(ips, "name", None)
                if ips_name and (ns, ips_name) not in sec_keys:
                    missing_refs.append(f"imagePullSecret/{ips_name}")

        # Volumes check
        for vol in getattr(spec, "volumes", []) or []:
            v_cm = getattr(vol, "config_map", None)
            if v_cm and have_cms:
                cm_name = getattr(v_cm, "name", None)
                optional = bool(getattr(v_cm, "optional", False))
                if cm_name and not optional and (ns, cm_name) not in cm_keys:
                    missing_refs.append(f"ConfigMap/{cm_name} (volume)")

            v_sec = getattr(vol, "secret", None)
            if v_sec and have_secs and sec_keys:
                s_name = getattr(v_sec, "secret_name", None)
                optional = bool(getattr(v_sec, "optional", False))
                if s_name and not optional and (ns, s_name) not in sec_keys:
                    missing_refs.append(f"Secret/{s_name} (volume)")

        # Container env & envFrom checks
        all_containers = list(getattr(spec, "containers", []) or []) + list(
            getattr(spec, "init_containers", []) or []
        )
        for c in all_containers:
            for ef in getattr(c, "env_from", []) or []:
                cm_ref = getattr(ef, "config_map_ref", None)
                if cm_ref and have_cms:
                    cm_name = getattr(cm_ref, "name", None)
                    if (
                        cm_name
                        and not getattr(cm_ref, "optional", False)
                        and (ns, cm_name) not in cm_keys
                    ):
                        missing_refs.append(f"ConfigMap/{cm_name} (envFrom)")

                s_ref = getattr(ef, "secret_ref", None)
                if s_ref and have_secs and sec_keys:
                    s_name = getattr(s_ref, "name", None)
                    if (
                        s_name
                        and not getattr(s_ref, "optional", False)
                        and (ns, s_name) not in sec_keys
                    ):
                        missing_refs.append(f"Secret/{s_name} (envFrom)")

            for env_var in getattr(c, "env", []) or []:
                val_from = getattr(env_var, "value_from", None)
                if not val_from:
                    continue
                cm_key_ref = getattr(val_from, "config_map_key_ref", None)
                if cm_key_ref and have_cms:
                    cm_name = getattr(cm_key_ref, "name", None)
                    key_name = getattr(cm_key_ref, "key", None)
                    optional = bool(getattr(cm_key_ref, "optional", False))
                    if cm_name and not optional:
                        if (ns, cm_name) not in cm_keys:
                            missing_refs.append(f"ConfigMap/{cm_name}")
                        elif key_name and key_name not in cm_keys[(ns, cm_name)]:
                            missing_refs.append(
                                f"ConfigMap/{cm_name}[missing key '{key_name}']"
                            )

                s_key_ref = getattr(val_from, "secret_key_ref", None)
                if s_key_ref and have_secs and sec_keys:
                    s_name = getattr(s_key_ref, "name", None)
                    key_name = getattr(s_key_ref, "key", None)
                    optional = bool(getattr(s_key_ref, "optional", False))
                    if s_name and not optional:
                        if (ns, s_name) not in sec_keys:
                            missing_refs.append(f"Secret/{s_name}")
                        elif key_name and key_name not in sec_keys[(ns, s_name)]:
                            missing_refs.append(
                                f"Secret/{s_name}[missing key '{key_name}']"
                            )

        if missing_refs:
            dedup_refs = list(dict.fromkeys(missing_refs))
            cfg_idx += 1
            findings.append(
                Finding(
                    id=f"CFG-{cfg_idx:03d}",
                    category="config_and_security",
                    resource_type="Pod",
                    resource_name=pod_name,
                    namespace=ns,
                    severity=Severity.HIGH,
                    problem=f"Pod references missing configuration/secret ({dedup_refs[0]})",
                    reason="MissingReferencedResource",
                    description=(
                        f"Pod '{pod_name}' references missing resource(s) or key(s): "
                        f"{', '.join(dedup_refs)}."
                    ),
                    evidence={"missingReferences": dedup_refs},
                    root_cause=f"Referenced resource(s) {', '.join(dedup_refs)} do not exist in namespace '{ns}'.",
                    recommendation="Create the missing ConfigMap, Secret, or ServiceAccount in the namespace.",
                    related_resources=related,
                )
            )

    # 3. Check RoleBindings & ClusterRoleBindings for broken references (Section 16)
    for rb in snap.role_bindings:
        meta = getattr(rb, "metadata", None)
        role_ref = getattr(rb, "role_ref", None)
        if not meta or not role_ref:
            continue
        rb_name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        r_kind = getattr(role_ref, "kind", "")
        r_name = getattr(role_ref, "name", "")

        if r_kind == "Role" and role_set and (ns, r_name) not in role_set:
            cfg_idx += 1
            findings.append(
                Finding(
                    id=f"RBAC-{cfg_idx:03d}",
                    category="config_and_security",
                    resource_type="RoleBinding",
                    resource_name=rb_name,
                    namespace=ns,
                    severity=Severity.MEDIUM,
                    problem=f"RoleBinding references non-existent Role '{r_name}'",
                    reason="MissingRoleRef",
                    description=f"RoleBinding '{rb_name}' binds to Role '{r_name}', which does not exist in '{ns}'.",
                    evidence={"roleKind": r_kind, "roleName": r_name},
                    root_cause=f"Role '{r_name}' was deleted or never created.",
                    recommendation="Create the missing Role or remove the orphaned RoleBinding.",
                )
            )
        elif (
            r_kind == "ClusterRole"
            and cluster_role_set
            and r_name not in cluster_role_set
        ):
            cfg_idx += 1
            findings.append(
                Finding(
                    id=f"RBAC-{cfg_idx:03d}",
                    category="config_and_security",
                    resource_type="RoleBinding",
                    resource_name=rb_name,
                    namespace=ns,
                    severity=Severity.MEDIUM,
                    problem=f"RoleBinding references non-existent ClusterRole '{r_name}'",
                    reason="MissingClusterRoleRef",
                    description=f"RoleBinding '{rb_name}' binds to ClusterRole '{r_name}', which does not exist.",
                    evidence={"roleKind": r_kind, "roleName": r_name},
                    root_cause=f"ClusterRole '{r_name}' was deleted or never created.",
                    recommendation="Create the missing ClusterRole or update the RoleBinding.",
                )
            )

    # 4. Certificate & TLS Health Checks (Section 23)
    cert_idx = 0
    for sec in snap.secrets:
        meta = getattr(sec, "metadata", None)
        if not meta:
            continue
        sec_type = getattr(sec, "type", "")
        data = getattr(sec, "data", None) or {}
        if sec_type != "kubernetes.io/tls" and "tls.crt" not in data:
            continue
        tls_crt = data.get("tls.crt")
        if not tls_crt:
            continue

        parsed = _parse_cert_expiry_days(tls_crt)
        if not parsed:
            continue
        days_left, not_after_str, subj = parsed
        if days_left <= config.cert_warning_days:
            cert_idx += 1
            sec_name = getattr(meta, "name", "unknown")
            ns = getattr(meta, "namespace", "default")
            if days_left <= 0:
                sev = Severity.CRITICAL
                prob = f"TLS Certificate in Secret '{sec_name}' has EXPIRED"
                reason = "CertificateExpired"
            elif days_left <= config.cert_critical_days:
                sev = Severity.HIGH
                prob = f"TLS Certificate in Secret '{sec_name}' expires in {days_left:.1f} days"
                reason = "CertificateExpiringSoon"
            else:
                sev = Severity.MEDIUM
                prob = f"TLS Certificate in Secret '{sec_name}' expires in {days_left:.0f} days"
                reason = "CertificateExpiryWarning"

            findings.append(
                Finding(
                    id=f"CERT-{cert_idx:03d}",
                    category="certificates",
                    resource_type="Secret",
                    resource_name=sec_name,
                    namespace=ns,
                    severity=sev,
                    problem=prob,
                    reason=reason,
                    description=(
                        f"TLS certificate in Secret '{sec_name}' (subject: {subj}) "
                        f"valid until {not_after_str} ({days_left:.1f} days remaining)."
                    ),
                    evidence={
                        "daysRemaining": round(days_left, 1),
                        "notAfter": not_after_str,
                        "subject": subj,
                    },
                    root_cause="TLS certificate has expired or is approaching its expiration date.",
                    recommendation="Renew the TLS certificate or inspect cert-manager Certificate/Issuer status.",
                )
            )

    # Cert-manager custom resources (Certificate, CertificateRequest, Issuer, ClusterIssuer)
    for cr in snap.custom_resources:
        api_ver = cr.get("apiVersion", "")
        if "cert-manager.io" not in api_ver:
            continue
        kind = cr.get("kind", "Certificate")
        meta = cr.get("metadata", {})
        c_name = meta.get("name", "unknown")
        c_ns = meta.get("namespace")
        conds = cr.get("status", {}).get("conditions", []) or []
        for cond in conds:
            if cond.get("type") == "Ready" and cond.get("status") == "False":
                cert_idx += 1
                findings.append(
                    Finding(
                        id=f"CERT-{cert_idx:03d}",
                        category="certificates",
                        resource_type=kind,
                        resource_name=c_name,
                        namespace=c_ns,
                        severity=Severity.HIGH,
                        problem=f"cert-manager {kind} is Ready=False",
                        reason=cond.get("reason") or "CertificateNotReady",
                        description=f"{kind} '{c_name}' Ready=False: {cond.get('message', '')}",
                        evidence=cond,
                        root_cause=cond.get("message") or f"cert-manager failed to reconcile {kind}.",
                        recommendation="Check cert-manager controller logs, ACME challenges, and Issuer configuration.",
                    )
                )

    # 5. Admission Controller & Webhook Health Checks (Section 24)
    wh_idx = 0
    ready_eps, _ = _count_ready_endpoints(snap)
    all_services: Set[Tuple[str, str]] = set()
    for s in list(snap.services) + list(snap.kube_system_services):
        m = getattr(s, "metadata", None)
        if m:
            all_services.add(
                (getattr(m, "namespace", "default"), getattr(m, "name", ""))
            )

    webhook_configs = [
        ("ValidatingWebhookConfiguration", w) for w in snap.validating_webhooks
    ] + [("MutatingWebhookConfiguration", w) for w in snap.mutating_webhooks]

    for wh_kind, wh_cfg in webhook_configs:
        meta = getattr(wh_cfg, "metadata", None)
        if not meta:
            continue
        cfg_name = getattr(meta, "name", "unknown")
        for wh in getattr(wh_cfg, "webhooks", []) or []:
            wh_name = getattr(wh, "name", cfg_name)
            failure_policy = getattr(wh, "failure_policy", "Fail") or "Fail"
            client_cfg = getattr(wh, "client_config", None)
            svc_ref = getattr(client_cfg, "service", None) if client_cfg else None
            if not svc_ref:
                continue
            svc_ns = getattr(svc_ref, "namespace", None)
            svc_name = getattr(svc_ref, "name", None)
            if not svc_ns or not svc_name:
                continue

            # Only check endpoint availability when we scanned all namespaces or that specific namespace
            if snap.namespace and snap.namespace not in (svc_ns, "kube-system"):
                continue

            svc_exists = (svc_ns, svc_name) in all_services
            ep_ready = ready_eps.get((svc_ns, svc_name), 0)

            if not svc_exists or ep_ready == 0:
                wh_idx += 1
                sev = (
                    Severity.CRITICAL
                    if failure_policy == "Fail"
                    else Severity.MEDIUM
                )
                findings.append(
                    Finding(
                        id=f"WH-{wh_idx:03d}",
                        category="webhooks",
                        resource_type=wh_kind,
                        resource_name=cfg_name,
                        namespace=svc_ns,
                        severity=sev,
                        problem=(
                            f"Admission webhook '{wh_name}' backend Service '{svc_ns}/{svc_name}' is unavailable"
                        ),
                        reason="WebhookBackendUnavailable",
                        description=(
                            f"{wh_kind} '{cfg_name}' (webhook '{wh_name}', failurePolicy={failure_policy}) "
                            f"targets Service '{svc_ns}/{svc_name}' which "
                            + (
                                "does not exist."
                                if not svc_exists
                                else "has 0 ready endpoints."
                            )
                        ),
                        evidence={
                            "webhook": wh_name,
                            "failurePolicy": failure_policy,
                            "targetService": f"{svc_ns}/{svc_name}",
                            "serviceExists": svc_exists,
                            "readyEndpoints": ep_ready,
                        },
                        root_cause=(
                            f"Webhook backend Service '{svc_ns}/{svc_name}' has no ready Pods, "
                            f"and failurePolicy={failure_policy} will reject matching API requests."
                        ),
                        recommendation="Restore the webhook controller Pods or set failurePolicy=Ignore temporarily if blocking critical operations.",
                        related_resources=[
                            RelatedResource(
                                type="Service", name=svc_name, namespace=svc_ns
                            )
                        ],
                    )
                )

    logger.info(
        f"[kubernetes/fast] Config/Security/Certs/Webhooks scanner finished: {len(findings)} findings"
    )
    return findings

