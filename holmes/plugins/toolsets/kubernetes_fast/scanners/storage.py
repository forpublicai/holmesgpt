import logging
from typing import Dict, List, Set, Tuple

from holmes.plugins.toolsets.kubernetes_fast.collector import ClusterSnapshot
from holmes.plugins.toolsets.kubernetes_fast.models import (
    Finding,
    KubernetesFastConfig,
    RelatedResource,
    Severity,
)

logger = logging.getLogger(__name__)


def scan_storage(
    snap: ClusterSnapshot,
    config: KubernetesFastConfig,
) -> List[Finding]:
    """Scan PVCs, PVs, StorageClasses, and VolumeAttachments (Section 13)."""
    findings: List[Finding] = []
    idx = 0

    # Index StorageClasses and identify default StorageClasses
    sc_modes: Dict[str, str] = {}
    default_scs: List[str] = []
    for sc in snap.storage_classes:
        meta = getattr(sc, "metadata", None)
        if not meta:
            continue
        sc_name = getattr(meta, "name", "")
        binding_mode = getattr(sc, "volume_binding_mode", "Immediate") or "Immediate"
        sc_modes[sc_name] = binding_mode
        ann = getattr(meta, "annotations", {}) or {}
        if (
            ann.get("storageclass.kubernetes.io/is-default-class") == "true"
            or ann.get("storageclass.beta.kubernetes.io/is-default-class") == "true"
        ):
            default_scs.append(sc_name)

    if len(default_scs) > 1:
        idx += 1
        findings.append(
            Finding(
                id=f"STOR-{idx:03d}",
                category="storage",
                resource_type="StorageClass",
                resource_name=", ".join(default_scs),
                severity=Severity.MEDIUM,
                problem="Multiple default StorageClasses configured",
                reason="MultipleDefaultStorageClasses",
                description=(
                    f"Cluster has {len(default_scs)} default StorageClasses ({default_scs}), "
                    f"which can cause ambiguous PVC provisioning."
                ),
                evidence={"defaultStorageClasses": default_scs},
                root_cause="More than one StorageClass has storageclass.kubernetes.io/is-default-class=true.",
                recommendation="Mark only one StorageClass as the default.",
            )
        )

    # Map PVCs mounted by Pods: (namespace, pvc_name) -> list of Pod names
    pvc_consumers: Dict[Tuple[str, str], List[str]] = {}
    for pod in snap.pods:
        p_meta = getattr(pod, "metadata", None)
        p_spec = getattr(pod, "spec", None)
        if not p_meta or not p_spec:
            continue
        p_ns = getattr(p_meta, "namespace", "default")
        p_name = getattr(p_meta, "name", "unknown")
        for vol in getattr(p_spec, "volumes", []) or []:
            pvc_src = getattr(vol, "persistent_volume_claim", None)
            claim_name = getattr(pvc_src, "claim_name", None) if pvc_src else None
            if claim_name:
                pvc_consumers.setdefault((p_ns, claim_name), []).append(p_name)

    # 1. PersistentVolumeClaims
    for pvc in snap.pvcs:
        meta = getattr(pvc, "metadata", None)
        spec = getattr(pvc, "spec", None)
        status = getattr(pvc, "status", None)
        if not meta or not spec or not status:
            continue

        name = getattr(meta, "name", "unknown")
        ns = getattr(meta, "namespace", "default")
        phase = getattr(status, "phase", "Unknown") or "Unknown"
        sc_name = getattr(spec, "storage_class_name", None)
        consumers = pvc_consumers.get((ns, name), [])
        related = [
            RelatedResource(type="Pod", name=c_pod, namespace=ns)
            for c_pod in consumers[:5]
        ]

        if phase == "Lost":
            idx += 1
            findings.append(
                Finding(
                    id=f"STOR-{idx:03d}",
                    category="storage",
                    resource_type="PersistentVolumeClaim",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.CRITICAL,
                    problem="PersistentVolumeClaim is in Lost state",
                    reason="PVCLost",
                    description=f"PVC '{name}' in namespace '{ns}' has lost its underlying PersistentVolume.",
                    evidence={
                        "phase": phase,
                        "volumeName": getattr(spec, "volume_name", None),
                        "storageClassName": sc_name,
                        "mountedByPods": consumers,
                    },
                    root_cause="The backing PersistentVolume was deleted or became detached/unavailable.",
                    recommendation="Check the backing PersistentVolume and storage backend immediately.",
                    related_resources=related,
                )
            )
            continue

        if sc_name and sc_modes and sc_name not in sc_modes:
            idx += 1
            findings.append(
                Finding(
                    id=f"STOR-{idx:03d}",
                    category="storage",
                    resource_type="PersistentVolumeClaim",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.HIGH,
                    problem=f"PVC references non-existent StorageClass '{sc_name}'",
                    reason="MissingStorageClass",
                    description=(
                        f"PVC '{name}' (phase={phase}) requests StorageClass '{sc_name}', "
                        f"which does not exist in the cluster."
                    ),
                    evidence={
                        "phase": phase,
                        "storageClassName": sc_name,
                        "availableStorageClasses": list(sc_modes.keys()),
                        "mountedByPods": consumers,
                    },
                    root_cause=f"StorageClass '{sc_name}' is not installed or is misspelled.",
                    recommendation="Create the StorageClass or update the PVC to use an existing StorageClass.",
                    related_resources=related,
                )
            )
            continue

        if phase == "Pending":
            binding_mode = sc_modes.get(sc_name or "", "Immediate")
            # WaitForFirstConsumer PVCs with 0 consuming pods are expected to stay Pending until a pod is scheduled
            if binding_mode == "WaitForFirstConsumer" and not consumers:
                continue

            idx += 1
            no_default_sc = not sc_name and not default_scs and bool(sc_modes)
            findings.append(
                Finding(
                    id=f"STOR-{idx:03d}",
                    category="storage",
                    resource_type="PersistentVolumeClaim",
                    resource_name=name,
                    namespace=ns,
                    severity=Severity.HIGH if consumers else Severity.MEDIUM,
                    problem="PersistentVolumeClaim is stuck Pending",
                    reason="NoDefaultStorageClass" if no_default_sc else "PVCPending",
                    description=(
                        f"PVC '{name}' is Pending"
                        + (
                            f" and blocking {len(consumers)} Pod(s): {consumers[:3]}"
                            if consumers
                            else "."
                        )
                    ),
                    evidence={
                        "phase": phase,
                        "storageClassName": sc_name,
                        "volumeBindingMode": binding_mode,
                        "mountedByPods": consumers,
                    },
                    root_cause=(
                        "PVC omits storageClassName and no default StorageClass is configured."
                        if no_default_sc
                        else "CSI provisioner failed to provision volume or WaitForFirstConsumer Pod cannot be scheduled."
                    ),
                    recommendation="Inspect PVC events (`kubectl describe pvc`) and CSI provisioner Pods.",
                    related_resources=related,
                )
            )

    # 2. PersistentVolumes
    for pv in snap.pvs:
        meta = getattr(pv, "metadata", None)
        status = getattr(pv, "status", None)
        spec = getattr(pv, "spec", None)
        if not meta or not status:
            continue

        pv_name = getattr(meta, "name", "unknown")
        phase = getattr(status, "phase", "Unknown") or "Unknown"
        if phase in ("Failed", "Released"):
            idx += 1
            sev = Severity.HIGH if phase == "Failed" else Severity.LOW
            claim_ref = getattr(spec, "claim_ref", None) if spec else None
            findings.append(
                Finding(
                    id=f"STOR-{idx:03d}",
                    category="storage",
                    resource_type="PersistentVolume",
                    resource_name=pv_name,
                    severity=sev,
                    problem=f"PersistentVolume is in {phase} state",
                    reason=f"PV{phase}",
                    description=(
                        f"PersistentVolume '{pv_name}' is in '{phase}' state "
                        f"({getattr(status, 'message', '') or 'not available for new claims'})."
                    ),
                    evidence={
                        "phase": phase,
                        "reason": getattr(status, "reason", None),
                        "message": getattr(status, "message", None),
                        "reclaimPolicy": getattr(
                            spec, "persistent_volume_reclaim_policy", None
                        )
                        if spec
                        else None,
                        "claimRef": getattr(claim_ref, "name", None) if claim_ref else None,
                    },
                    root_cause=(
                        "Volume reclamation failed."
                        if phase == "Failed"
                        else "Claim was deleted and PV with Retain policy has not been cleaned up."
                    ),
                    recommendation="Inspect the PV and reclaim or delete it if no longer needed.",
                )
            )

    # 3. VolumeAttachments
    for va in snap.volume_attachments:
        meta = getattr(va, "metadata", None)
        status = getattr(va, "status", None)
        spec = getattr(va, "spec", None)
        if not meta or not status:
            continue

        att_err = getattr(status, "attach_error", None)
        det_err = getattr(status, "detach_error", None)
        if att_err or det_err:
            idx += 1
            va_name = getattr(meta, "name", "unknown")
            err_msg = (
                getattr(att_err, "message", None)
                if att_err
                else getattr(det_err, "message", None)
            )
            findings.append(
                Finding(
                    id=f"STOR-{idx:03d}",
                    category="storage",
                    resource_type="VolumeAttachment",
                    resource_name=va_name,
                    severity=Severity.HIGH,
                    problem="VolumeAttachment reporting attach/detach error",
                    reason="VolumeAttachError" if att_err else "VolumeDetachError",
                    description=f"VolumeAttachment '{va_name}' error: {err_msg}",
                    evidence={
                        "attached": getattr(status, "attached", False),
                        "nodeName": getattr(spec, "node_name", None) if spec else None,
                        "attacher": getattr(spec, "attacher", None) if spec else None,
                        "errorMessage": err_msg,
                    },
                    root_cause=err_msg or "CSI driver or cloud storage failed to attach/detach volume.",
                    recommendation="Check CSI controller/node plugin logs and cloud volume attachment limits.",
                )
            )

    logger.info(
        f"[kubernetes/fast] Storage scanner finished: {len(findings)} storage findings"
    )
    return findings

