import json
import re
from typing import Any, Dict, List, Optional

from holmes.plugins.toolsets.kubernetes_logs_fast.models import ParsedLogEntry
from holmes.plugins.toolsets.utils import to_unix_ms

TIMESTAMP_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s?"
)
PREFIX_RE = re.compile(r"^\[(?P<pod>[^/]+)/(?P<container>[^\]]+)\]\s")

STACK_CONTINUATION_RE = re.compile(
    r"^(?:"
    r"\s+at\s+"
    r"|Caused by:"
    r"|\s+\.\.\.\s+\d+\s+more"
    r"|\s+File\s+\"[^\"]+\",\s+line\s+\d+"
    r"|\t+[^\s]"
    r"|goroutine\s+\d+\s+\["
    r"|created by\s+"
    r"|\s*---\s+End of inner exception"
    r")"
)

# Regexes for normalizing variable tokens during deduplication fingerprinting
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
_ISO_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
)
_NUM_RE = re.compile(r"\b\d+\b")


def fingerprint_log_message(text: str) -> str:
    """Normalize variable numbers, IPs, UUIDs, and timestamps to group repeated log lines."""
    first_line = text.split("\n", 1)[0][:250]
    norm = _ISO_TS_RE.sub("<TS>", first_line)
    norm = _UUID_RE.sub("<UUID>", norm)
    norm = _HEX_RE.sub("<HEX>", norm)
    norm = _IP_RE.sub("<IP>", norm)
    norm = _NUM_RE.sub("<N>", norm)
    return norm.strip().lower()


def _try_parse_json_log(line: str) -> Optional[Dict[str, Any]]:
    stripped = line.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    try:
        obj = json.loads(stripped)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _extract_json_fields(
    obj: Dict[str, Any],
) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], bool]:
    """Return (level, message, error_str, error_code, stack_str, is_benign_json)."""
    raw_level = (
        obj.get("level")
        or obj.get("severity")
        or obj.get("lvl")
        or obj.get("log.level")
        or obj.get("levelname")
    )
    level = str(raw_level).strip().lower() if raw_level is not None else None

    raw_msg = obj.get("message") or obj.get("msg") or obj.get("log")
    msg = str(raw_msg) if raw_msg is not None else None

    raw_err = obj.get("error") or obj.get("err") or obj.get("exception")
    if isinstance(raw_err, dict):
        err_str = raw_err.get("message") or raw_err.get("type") or json.dumps(raw_err)
    elif raw_err is not None and raw_err != "" and raw_err is not False:
        err_str = str(raw_err)
    else:
        err_str = None

    raw_code = obj.get("error_code") or obj.get("errorCode") or obj.get("code")
    err_code = str(raw_code) if raw_code is not None else None

    raw_stack = (
        obj.get("stack")
        or obj.get("trace")
        or obj.get("stack_trace")
        or obj.get("stacktrace")
    )
    stack_str = str(raw_stack) if raw_stack else None

    is_benign = bool(
        level in ("info", "debug", "trace")
        and not err_str
        and not stack_str
        and not err_code
    )
    return level, msg, err_str, err_code, stack_str, is_benign


def parse_raw_logs(
    raw_text: str,
    default_container: str,
    source: str = "current",
    max_lines: Optional[int] = None,
) -> List[ParsedLogEntry]:
    """Parse raw container logs into structured entries, coalescing multiline stack traces."""
    if not raw_text:
        return []

    entries: List[ParsedLogEntry] = []
    in_python_traceback = False

    lines = raw_text.splitlines()
    if max_lines and len(lines) > max_lines:
        lines = lines[-max_lines:]

    for raw_line in lines:
        if not raw_line.strip():
            continue

        line = raw_line
        container = default_container

        # 1. Strip optional [pod/container] prefix
        pref_m = PREFIX_RE.match(line)
        if pref_m:
            container = pref_m.group("container")
            line = line[pref_m.end() :]

        # 2. Extract optional leading ISO-8601 timestamp
        ts_str: Optional[str] = None
        ts_ms: Optional[int] = None
        ts_m = TIMESTAMP_RE.match(line)
        if ts_m:
            ts_str = ts_m.group("ts")
            line = line[ts_m.end() :]
            try:
                ts_ms = to_unix_ms(ts_str)
            except Exception:
                ts_ms = None

        # 3. Check if this line is a stack-trace / multiline continuation of the previous entry
        is_continuation = False
        if entries and entries[-1].container == container:
            if STACK_CONTINUATION_RE.match(line):
                is_continuation = True
            elif in_python_traceback and (
                line.startswith("  ")
                or re.match(r"^[A-Za-z0-9_.]*(?:Error|Exception):", line)
            ):
                is_continuation = True
                if not line.startswith("  "):
                    in_python_traceback = False
            elif ts_str is None and not line.lstrip().startswith("{"):
                is_continuation = True

        if "Traceback (most recent call last):" in line:
            in_python_traceback = True

        if is_continuation and entries:
            prev = entries[-1]
            if len(prev.content) < 1200:
                prev.content = f"{prev.content}\n{line}"[:1200]
            continue

        # 4. Check for structured JSON log object
        json_obj = _try_parse_json_log(line)
        if json_obj is not None:
            lvl, msg, err_s, err_code, stack_s, is_benign = _extract_json_fields(
                json_obj
            )
            json_ts = (
                json_obj.get("timestamp")
                or json_obj.get("time")
                or json_obj.get("ts")
                or json_obj.get("@timestamp")
            )
            if not ts_str and isinstance(json_ts, str):
                ts_str = json_ts

            parts: List[str] = []
            if lvl:
                parts.append(f"[{lvl.upper()}]")
            if msg:
                parts.append(msg)
            if err_s and err_s not in (msg or ""):
                parts.append(f"error={err_s}")
            if err_code:
                parts.append(f"error_code={err_code}")
            if stack_s:
                parts.append(stack_s[:500])

            synthesized = " ".join(parts) if parts else line
            entries.append(
                ParsedLogEntry(
                    content=synthesized[:1200],
                    container=container,
                    source=source,
                    timestamp_str=ts_str,
                    timestamp_ms=ts_ms,
                    is_json=True,
                    json_level=lvl,
                    json_message=msg,
                    json_error=err_s,
                    json_error_code=err_code,
                    is_benign_json=is_benign,
                )
            )
        else:
            entries.append(
                ParsedLogEntry(
                    content=line[:1200],
                    container=container,
                    source=source,
                    timestamp_str=ts_str,
                    timestamp_ms=ts_ms,
                )
            )

    return entries

