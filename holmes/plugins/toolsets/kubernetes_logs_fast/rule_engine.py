from dataclasses import dataclass
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from holmes.plugins.toolsets.kubernetes_fast.models import Severity
from holmes.plugins.toolsets.kubernetes_logs_fast.models import (
    LogRule,
    LogsFastConfig,
    ParsedLogEntry,
)

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).parent / "rules"

# Global false-positive benign patterns (e.g. health probes returning 200 OK or zero-error counters)
GLOBAL_BENIGN_REGEX = re.compile(
    r"(?:"
    r"\"(?:GET|HEAD)\s+/(?:healthz?|readyz?|livez?|metrics|status|ping)\b[^\"]*\"\s+20[04]\b"
    r"|\b(?:0\s+errors|0\s+warnings|errors=0|warnings=0|error_count:\s*0|exit\s+code\s+0|exit\s+status\s+0|exited\s+with\s+code\s+0)\b"
    r")",
    re.IGNORECASE,
)


@dataclass
class CompiledRule:
    rule: LogRule
    compiled_patterns: List[Tuple[str, Optional[re.Pattern]]]
    compiled_excludes: List[str]


def _parse_severity(val: str) -> Severity:
    v = str(val).strip().lower()
    for s in Severity:
        if s.value == v:
            return s
    return Severity.HIGH


def _dict_to_rule(item: Dict[str, Any]) -> Optional[LogRule]:
    rule_id = item.get("id")
    name = item.get("name")
    patterns = item.get("patterns")
    if not rule_id or not name or not patterns or not isinstance(patterns, list):
        return None
    return LogRule(
        id=str(rule_id),
        name=str(name),
        category=str(item.get("category", "general_error")),
        severity=_parse_severity(item.get("severity", "high")),
        patterns=[str(p) for p in patterns if p],
        match_mode=str(item.get("match_mode", "any")).lower(),
        case_insensitive=bool(item.get("case_insensitive", True)),
        enabled=bool(item.get("enabled", True)),
        language=item.get("language"),
        exclude_patterns=[str(x) for x in (item.get("exclude_patterns") or []) if x],
        min_occurrences=int(item.get("min_occurrences", 1) or 1),
        description=str(item.get("description", "")),
        recommendation=str(item.get("recommendation", "")),
    )


def _load_yaml_rules(path: Path) -> List[LogRule]:
    if not path.is_file():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            return []
        rules: List[LogRule] = []
        for entry in raw:
            if isinstance(entry, dict):
                r = _dict_to_rule(entry)
                if r:
                    rules.append(r)
        return rules
    except Exception as e:
        logger.warning(f"[kubernetes/logs_fast] Failed loading rules from {path}: {e}")
        return []


def load_compiled_rules(
    config: LogsFastConfig,
    include_warnings: Optional[bool] = None,
    extra_keywords: Optional[str] = None,
) -> List[CompiledRule]:
    """Load built-in YAML rules, language rules, and user custom rules, then compile patterns."""
    all_rules: List[LogRule] = []
    all_rules.extend(_load_yaml_rules(_RULES_DIR / "default_rules.yaml"))
    all_rules.extend(_load_yaml_rules(_RULES_DIR / "language_rules.yaml"))

    if config.custom_rules_file:
        custom_path = Path(config.custom_rules_file)
        all_rules.extend(_load_yaml_rules(custom_path))

    for cr_dict in config.custom_rules:
        if isinstance(cr_dict, dict):
            parsed = _dict_to_rule(cr_dict)
            if parsed:
                all_rules.append(parsed)

    if extra_keywords and extra_keywords.strip():
        kw_list = [k.strip() for k in extra_keywords.split(",") if k.strip()]
        if kw_list:
            all_rules.insert(
                0,
                LogRule(
                    id="LOG-CUSTOM-KW",
                    name="User-specified search keyword match",
                    category="custom_keyword",
                    severity=Severity.HIGH,
                    patterns=kw_list,
                    match_mode="any",
                    case_insensitive=True,
                    enabled=True,
                    description="Matched keyword(s) requested in the scan query.",
                    recommendation="Inspect the matched log entry.",
                ),
            )

    disabled_ids: Set[str] = {r.strip() for r in config.disabled_rule_ids}
    disabled_cats: Set[str] = {c.strip().lower() for c in config.disabled_categories}
    enabled_langs: Set[str] = {lang.strip().lower() for lang in config.enabled_languages}
    allow_warnings = (
        include_warnings if include_warnings is not None else config.include_warnings
    )

    compiled_list: List[CompiledRule] = []
    for rule in all_rules:
        if not rule.enabled:
            continue
        if rule.id in disabled_ids:
            continue
        if rule.category.lower() in disabled_cats:
            continue
        if rule.language and rule.language.lower() not in enabled_langs:
            continue
        if not allow_warnings and (
            rule.severity in (Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL)
            or rule.category == "warning"
        ):
            continue

        flags = re.IGNORECASE if rule.case_insensitive else 0
        comp_patterns: List[Tuple[str, Optional[re.Pattern]]] = []
        for pat in rule.patterns:
            if rule.match_mode == "regex":
                try:
                    comp_patterns.append((pat, re.compile(pat, flags)))
                except re.error:
                    comp_patterns.append(
                        (pat.lower() if rule.case_insensitive else pat, None)
                    )
            else:
                comp_patterns.append(
                    (pat.lower() if rule.case_insensitive else pat, None)
                )

        comp_excludes = [
            ex.lower() if rule.case_insensitive else ex for ex in rule.exclude_patterns
        ]
        compiled_list.append(
            CompiledRule(
                rule=rule,
                compiled_patterns=comp_patterns,
                compiled_excludes=comp_excludes,
            )
        )

    logger.debug(
        f"[kubernetes/logs_fast] Loaded {len(compiled_list)} active log detection rules"
    )
    return compiled_list


def match_entry_against_rules(
    entry: ParsedLogEntry,
    compiled_rules: List[CompiledRule],
    custom_excludes_lower: List[str],
) -> Optional[Tuple[LogRule, str]]:
    """Evaluate a ParsedLogEntry against compiled rules and return the highest-priority (LogRule, matched_pattern)."""
    text = entry.content
    if not text:
        return None

    # 1. Global benign filter
    if GLOBAL_BENIGN_REGEX.search(text):
        return None

    text_lower = text.lower()
    for cex in custom_excludes_lower:
        if cex in text_lower:
            return None

    # 2. If structured JSON explicitly says level=info/debug/trace and has no error field,
    # skip noisy generic keyword rules while still allowing specific critical rules (e.g. OOMKilled).
    skip_generic = entry.is_benign_json

    for comp in compiled_rules:
        rule = comp.rule
        if skip_generic and rule.category in ("general_error", "warning"):
            continue

        haystack = text_lower if rule.case_insensitive else text

        # Rule-specific exclusions
        if any(ex in haystack for ex in comp.compiled_excludes):
            continue

        if rule.match_mode == "all":
            # AND condition: every pattern must match
            if all(p_str in haystack for p_str, _ in comp.compiled_patterns):
                joined = " + ".join(rule.patterns[:3])
                return rule, joined
        elif rule.match_mode == "regex":
            for raw_pat, regex_obj in comp.compiled_patterns:
                if regex_obj is not None:
                    m = regex_obj.search(text)
                    if m:
                        return rule, m.group(0)
                elif raw_pat in haystack:
                    return rule, raw_pat
        else:
            # Default "any" (OR substring match)
            for p_str, _ in comp.compiled_patterns:
                if p_str in haystack:
                    return rule, p_str

    # 3. Fallback for structured JSON logs with explicit level="error" / "fatal" / "critical"
    # that didn't match a more specific domain rule
    if entry.is_json and entry.json_level in ("error", "fatal", "critical", "panic", "severe"):
        sev = (
            Severity.CRITICAL
            if entry.json_level in ("fatal", "critical", "panic")
            else Severity.HIGH
        )
        synthetic_rule = LogRule(
            id="LOG-JSON-ERR",
            name=f"Structured JSON log (level={entry.json_level})",
            category="structured_json_error",
            severity=sev,
            patterns=[f"level={entry.json_level}"],
            description="Application emitted a structured JSON log entry with an error/fatal severity level.",
            recommendation="Inspect the structured message, error_code, and stack trace.",
        )
        return synthetic_rule, f"level={entry.json_level}"

    return None

