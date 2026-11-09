from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional

from holmes.plugins.toolsets.kubernetes_fast.models import RelatedResource

EXIT_CODE_EXPLANATIONS: Dict[int, str] = {
    1: "General application error (exit code 1)",
    2: "Shell misuse or invalid command syntax (exit code 2)",
    126: "Command invoked cannot execute — permission problem or not executable (exit code 126)",
    127: "Command not found — missing binary or invalid PATH (exit code 127)",
    128: "Invalid exit argument (exit code 128)",
    130: "Terminated by SIGINT / Ctrl-C (exit code 130)",
    137: "Terminated by SIGKILL — commonly OOMKilled or forceful kill (exit code 137)",
    139: "Segmentation fault / SIGSEGV (exit code 139)",
    143: "Graceful termination via SIGTERM (exit code 143)",
}

_BINARY_UNITS: Dict[str, int] = {
    "Ki": 1024,
    "Mi": 1024**2,
    "Gi": 1024**3,
    "Ti": 1024**4,
    "Pi": 1024**5,
    "Ei": 1024**6,
}

_DECIMAL_UNITS: Dict[str, float] = {
    "n": 1e-9,
    "u": 1e-6,
    "m": 1e-3,
    "k": 1e3,
    "K": 1e3,
    "M": 1e6,
    "G": 1e9,
    "T": 1e12,
    "P": 1e15,
    "E": 1e18,
}

_QUANTITY_RE = re.compile(r"^([+-]?[0-9.]+(?:[eE][+-]?[0-9]+)?)([A-Za-z]*)$")


def explain_exit_code(exit_code: Optional[int]) -> Optional[str]:
    if exit_code is None:
        return None
    if exit_code in EXIT_CODE_EXPLANATIONS:
        return EXIT_CODE_EXPLANATIONS[exit_code]
    if 128 < exit_code <= 192:
        sig = exit_code - 128
        return f"Terminated by signal {sig} (exit code {exit_code})"
    return f"Exited with non-zero code {exit_code}"


def parse_cpu_millicores(value: Optional[str]) -> float:
    """Convert Kubernetes CPU quantity string (e.g. '250m', '2', '500000u') to millicores."""
    if not value:
        return 0.0
    s = str(value).strip()
    m = _QUANTITY_RE.match(s)
    if not m:
        return 0.0
    num = float(m.group(1))
    unit = m.group(2)
    if unit == "":
        return num * 1000.0
    if unit == "m":
        return num
    if unit == "u":
        return num / 1000.0
    if unit == "n":
        return num / 1_000_000.0
    if unit in _DECIMAL_UNITS:
        return num * _DECIMAL_UNITS[unit] * 1000.0
    return 0.0


def parse_memory_bytes(value: Optional[str]) -> int:
    """Convert Kubernetes memory/storage quantity string (e.g. '512Mi', '2Gi') to bytes."""
    if not value:
        return 0
    s = str(value).strip()
    m = _QUANTITY_RE.match(s)
    if not m:
        return 0
    num = float(m.group(1))
    unit = m.group(2)
    if unit == "":
        return int(num)
    if unit in _BINARY_UNITS:
        return int(num * _BINARY_UNITS[unit])
    if unit in _DECIMAL_UNITS:
        return int(num * _DECIMAL_UNITS[unit])
    return 0


def parse_quantity_float(value: Optional[str]) -> float:
    """Parse any Kubernetes quantity into a normalized float for ratio comparisons."""
    if not value:
        return 0.0
    s = str(value).strip()
    m = _QUANTITY_RE.match(s)
    if not m:
        return 0.0
    num = float(m.group(1))
    unit = m.group(2)
    if unit == "":
        return num
    if unit in _BINARY_UNITS:
        return num * float(_BINARY_UNITS[unit])
    if unit in _DECIMAL_UNITS:
        return num * _DECIMAL_UNITS[unit]
    return num


def labels_match_selector(
    labels: Optional[Dict[str, str]],
    selector: Optional[Dict[str, str]],
) -> bool:
    """Return True if all key/value pairs in selector exist in labels."""
    if not selector:
        return False
    if not labels:
        return False
    for k, v in selector.items():
        if labels.get(k) != v:
            return False
    return True


def to_utc_datetime(dt: Any) -> Optional[datetime]:
    if dt is None:
        return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    if isinstance(dt, str):
        try:
            cleaned = dt.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(cleaned)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None
    return None


def age_minutes(dt: Any, now: Optional[datetime] = None) -> Optional[float]:
    parsed = to_utc_datetime(dt)
    if not parsed:
        return None
    ref = now or datetime.now(timezone.utc)
    delta = (ref - parsed).total_seconds() / 60.0
    return max(0.0, delta)


def format_iso(dt: Any) -> Optional[str]:
    parsed = to_utc_datetime(dt)
    if not parsed:
        return str(dt) if dt else None
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def owner_references_to_related(
    metadata: Any, default_namespace: Optional[str] = None
) -> List[RelatedResource]:
    if not metadata or not getattr(metadata, "owner_references", None):
        return []
    ns = getattr(metadata, "namespace", None) or default_namespace
    related: List[RelatedResource] = []
    for ref in metadata.owner_references:
        kind = getattr(ref, "kind", None)
        name = getattr(ref, "name", None)
        if kind and name:
            related.append(RelatedResource(type=kind, name=name, namespace=ns))
    return related

