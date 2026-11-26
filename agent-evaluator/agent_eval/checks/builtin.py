from __future__ import annotations

import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from ..cases import Case

STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_NOT_APPLICABLE = "not_applicable"
STATUS_ERROR = "error"


@dataclass(frozen=True)
class CheckResult:
    status: str
    reason: str
    evidence: Any = None


@dataclass
class CheckContext:
    all_cases: tuple[Case, ...]
    allow_network: bool = False
    network_timeout: float = 5.0
    _dataset_cache: dict[str, Any] = field(default_factory=dict)


CheckFn = Callable[[Case, dict, CheckContext], CheckResult]

_REGISTRY: dict[str, CheckFn] = {}


def register_check(name: str, fn: CheckFn) -> None:
    if name in _REGISTRY:
        raise ValueError(f"a check named '{name}' is already registered")
    _REGISTRY[name] = fn


def known_checks() -> set[str]:
    return set(_REGISTRY)


def run_check(name: str, case: Case, params: dict, context: CheckContext) -> CheckResult:
    fn = _REGISTRY.get(name)
    if fn is None:
        return CheckResult(STATUS_ERROR, f"unknown check type '{name}'")
    try:
        return fn(case, params, context)
    except KeyError as exc:
        return CheckResult(STATUS_ERROR, f"missing data: {exc}")
    except Exception as exc:  # a buggy check must be recorded as an error, never crash the run
        return CheckResult(STATUS_ERROR, f"check raised {type(exc).__name__}: {exc}")


def _get_field(case: Case, params: dict, default_path: str = "output") -> Any:
    return case.get(params.get("field", default_path))


def _required_fields(case: Case, params: dict, context: CheckContext) -> CheckResult:
    fields = params.get("fields")
    if not fields:
        return CheckResult(STATUS_ERROR, "'required_fields' check needs a non-empty 'fields' param")
    missing = []
    for f in fields:
        try:
            value = case.get(f)
        except KeyError:
            missing.append(f)
            continue
        if value is None or value == "" or value == []:
            missing.append(f)
    if missing:
        return CheckResult(STATUS_FAIL, f"missing or empty field(s): {missing}", evidence=missing)
    return CheckResult(STATUS_PASS, "all required fields present")


def _json_schema(case: Case, params: dict, context: CheckContext) -> CheckResult:
    schema = params.get("schema")
    if schema is None:
        return CheckResult(STATUS_ERROR, "'json_schema' check needs a 'schema' param")
    import jsonschema

    value = _get_field(case, params)
    try:
        jsonschema.validate(value, schema)
    except jsonschema.ValidationError as exc:
        return CheckResult(STATUS_FAIL, str(exc), evidence=value)
    return CheckResult(STATUS_PASS, "matches schema")


def _regex(case: Case, params: dict, context: CheckContext, negate: bool) -> CheckResult:
    pattern = params.get("pattern")
    if not pattern:
        return CheckResult(STATUS_ERROR, "'regex' check needs a 'pattern' param")
    value = _get_field(case, params)
    if not isinstance(value, str):
        return CheckResult(STATUS_ERROR, f"field is not a string: {type(value).__name__}")
    matched = re.search(pattern, value) is not None
    ok = (not matched) if negate else matched
    if ok:
        return CheckResult(STATUS_PASS, f"{'did not match' if negate else 'matched'} /{pattern}/", evidence=value)
    return CheckResult(
        STATUS_FAIL, f"expected to {'not ' if negate else ''}match /{pattern}/", evidence=value
    )


def _enum(case: Case, params: dict, context: CheckContext) -> CheckResult:
    allowed = params.get("values")
    if not allowed:
        return CheckResult(STATUS_ERROR, "'enum' check needs a 'values' param")
    value = _get_field(case, params)
    if value in allowed:
        return CheckResult(STATUS_PASS, f"'{value}' is in {allowed}")
    return CheckResult(STATUS_FAIL, f"'{value}' is not in {allowed}", evidence=value)


def _range(case: Case, params: dict, context: CheckContext) -> CheckResult:
    value = _get_field(case, params)
    if not isinstance(value, (int, float)):
        return CheckResult(STATUS_ERROR, f"field is not numeric: {type(value).__name__}")
    lo = params.get("min")
    hi = params.get("max")
    if lo is not None and value < lo:
        return CheckResult(STATUS_FAIL, f"{value} is below minimum {lo}", evidence=value)
    if hi is not None and value > hi:
        return CheckResult(STATUS_FAIL, f"{value} is above maximum {hi}", evidence=value)
    return CheckResult(STATUS_PASS, f"{value} is within [{lo}, {hi}]")


def _normalize_text(value: Any) -> str:
    text = ("" if value is None else str(value)).lower().strip()
    text = re.sub(r"[^\w\s]", "", text)
    return re.sub(r"\s+", " ", text)


def _reference_match(case: Case, params: dict, context: CheckContext) -> CheckResult:
    if case.reference is None:
        return CheckResult(STATUS_NOT_APPLICABLE, "case has no 'reference'")
    value = _get_field(case, params)
    normalize = params.get("normalize", True)
    ok = _normalize_text(value) == _normalize_text(case.reference) if normalize else value == case.reference
    if ok:
        return CheckResult(STATUS_PASS, "matches reference")
    return CheckResult(STATUS_FAIL, f"'{value}' does not match reference '{case.reference}'", evidence=value)


def _duplicate(case: Case, params: dict, context: CheckContext) -> CheckResult:
    fields = params.get("fields")
    if not fields:
        return CheckResult(STATUS_ERROR, "'duplicate' check needs a non-empty 'fields' param")
    cache_key = f"duplicate:{','.join(fields)}"
    counts = context._dataset_cache.get(cache_key)
    if counts is None:
        counts = {}
        for other in context.all_cases:
            try:
                key = tuple(other.get(f) for f in fields)
            except KeyError:
                continue
            counts.setdefault(key, []).append(other.id)
        context._dataset_cache[cache_key] = counts
    try:
        key = tuple(case.get(f) for f in fields)
    except KeyError as exc:
        return CheckResult(STATUS_ERROR, f"missing data: {exc}")
    siblings = [cid for cid in counts.get(key, []) if cid != case.id]
    if siblings:
        return CheckResult(STATUS_FAIL, f"shares key {key} with case(s) {siblings}", evidence=siblings)
    return CheckResult(STATUS_PASS, f"key {key} is unique")


def _url_reachable(case: Case, params: dict, context: CheckContext) -> CheckResult:
    if not context.allow_network:
        return CheckResult(STATUS_ERROR, "network checks are disabled for this run (pass --allow-network to enable)")
    url = _get_field(case, params)
    if not isinstance(url, str) or not url:
        return CheckResult(STATUS_ERROR, f"field is not a non-empty URL string: {url!r}")
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=context.network_timeout) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except (urllib.error.URLError, socket.timeout, ValueError) as exc:
        return CheckResult(STATUS_ERROR, f"network error reaching {url}: {exc}")
    if 200 <= status < 400:
        return CheckResult(STATUS_PASS, f"{url} responded {status}")
    return CheckResult(STATUS_FAIL, f"{url} responded {status}", evidence=status)


_SPIFFE_ID_RE = re.compile(r"^spiffe://(?P<trust_domain>[a-z0-9]([a-z0-9.-]*[a-z0-9])?)(?P<path>/[^\s#?]*)?$")


def _spiffe_id_valid(case: Case, params: dict, context: CheckContext) -> CheckResult:
    trust_domain = params.get("trust_domain")
    if not trust_domain:
        return CheckResult(STATUS_ERROR, "'spiffe_id_valid' check needs a 'trust_domain' param")
    value = _get_field(case, params, default_path="output.id")
    if not isinstance(value, str):
        return CheckResult(STATUS_ERROR, f"field is not a string: {type(value).__name__}")
    match = _SPIFFE_ID_RE.match(value)
    if not match:
        return CheckResult(STATUS_FAIL, f"'{value}' is not a syntactically valid SPIFFE ID", evidence=value)
    if match.group("trust_domain") != trust_domain:
        return CheckResult(
            STATUS_FAIL,
            f"trust domain '{match.group('trust_domain')}' does not match expected '{trust_domain}'",
            evidence=value,
        )
    path_policy = params.get("path_policy")
    if path_policy:
        path = match.group("path") or "/"
        policy_tag = next((tag for tag in case.tags if tag in path_policy), None)
        if policy_tag is not None:
            prefix = path_policy[policy_tag]
            if not path.startswith(prefix):
                return CheckResult(
                    STATUS_FAIL,
                    f"path '{path}' does not start with required prefix '{prefix}' for tag '{policy_tag}'",
                    evidence=value,
                )
    return CheckResult(STATUS_PASS, f"'{value}' is a valid SPIFFE ID in trust domain '{trust_domain}'")


register_check("required_fields", _required_fields)
register_check("json_schema", _json_schema)
register_check("regex", lambda case, params, ctx: _regex(case, params, ctx, negate=False))
register_check("not_regex", lambda case, params, ctx: _regex(case, params, ctx, negate=True))
register_check("enum", _enum)
register_check("range", _range)
register_check("reference_match", _reference_match)
register_check("duplicate", _duplicate)
register_check("url_reachable", _url_reachable)
register_check("spiffe_id_valid", _spiffe_id_valid)
