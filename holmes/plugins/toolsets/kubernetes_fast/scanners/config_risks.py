import logging
from typing import List

from holmes.plugins.toolsets.kubernetes_fast.collector import ClusterSnapshot
from holmes.plugins.toolsets.kubernetes_fast.models import (
    Finding,
    KubernetesFastConfig,
    Severity,
)

logger = logging.getLogger(__name__)


def scan_config_risks(
    snap: ClusterSnapshot,
    config: KubernetesFastConfig,
) -> List[Finding]:
    """Scan workload specifications for configuration & deployment risks (Section 25)."""
    findings: List[Finding] = []
    idx = 0

    for dep in snap.deployments:
        meta = getattr(dep, "metadata", None)
        spec = getattr(dep, "spec", None)
        if not meta or not spec:
            continue

        ns = getattr(meta, "namespace", "default")
        if ns == "kube-system":
            continue
        name = getattr(meta, "name", "unknown")
        replicas = getattr(spec, "replicas", 1) or 1
        tmpl = getattr(spec, "template", None)
        pod_spec = getattr(tmpl, "spec", None) if tmpl else None
        if not pod_spec:
            continue

        risks: List[str] = []
        if replicas == 1:
            risks.append("singleReplicaNoHA")

        if getattr(pod_spec, "host_network", False):
            risks.append("hostNetworkEnabled")
        if getattr(pod_spec, "host_pid", False):
            risks.append("hostPIDEnabled")

        for vol in getattr(pod_spec, "volumes", []) or []:
            if getattr(vol, "host_path", None) is not None:
                risks.append("usesHostPathVolume")
                break

        for c in getattr(pod_spec, "containers", []) or []:
            c_name = getattr(c, "name", "container")
            img = getattr(c, "image", "") or ""
            if img.endswith(":latest") or ":" not in img:
                risks.append(f"{c_name}:latestOrUntaggedImage")

            res = getattr(c, "resources", None)
            reqs = getattr(res, "requests", None) or {} if res else {}
            lims = getattr(res, "limits", None) or {} if res else {}
            if not reqs.get("cpu") or not reqs.get("memory"):
                risks.append(f"{c_name}:missingResourceRequests")
            if not lims.get("memory"):
                risks.append(f"{c_name}:missingMemoryLimit")

            if not getattr(c, "readiness_probe", None) and not getattr(
                c, "liveness_probe", None
            ):
                risks.append(f"{c_name}:missingHealthProbes")

            sc = getattr(c, "security_context", None)
            if sc and getattr(sc, "privileged", False):
                risks.append(f"{c_name}:privilegedContainer")

        if risks:
            idx += 1
            has_sec_risk = any(
                "privileged" in r or "host" in r.lower() for r in risks
            )
            findings.append(
                Finding(
                    id=f"RISK-{idx:03d}",
                    category="configuration_risks",
                    resource_type="Deployment",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.LOW if has_sec_risk else Severity.INFORMATIONAL,
                    problem=f"Deployment has {len(risks)} configuration risk indicator(s)",
                    reason="ConfigurationRisk",
                    description=f"Deployment '{name}' has configuration risks: {', '.join(risks[:6])}.",
                    evidence={"risks": risks},
                    root_cause="Workload specification omits production reliability or security best practices.",
                    recommendation="Define CPU/memory requests & limits, readiness/liveness probes, and pinned image tags.",
                )
            )

    logger.info(
        f"[kubernetes/fast] Configuration risks scanner finished: {len(findings)} risk items"
    )
    return findings

