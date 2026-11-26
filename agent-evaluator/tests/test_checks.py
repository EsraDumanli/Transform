from agent_eval.cases import Case
from agent_eval.checks.builtin import (
    STATUS_ERROR,
    STATUS_FAIL,
    STATUS_NOT_APPLICABLE,
    STATUS_PASS,
    CheckContext,
    run_check,
)


def _case(output=None, reference=None, tags=()):
    return Case(id="c1", subject="s", input={}, output=output or {}, reference=reference, tags=tuple(tags))


def _ctx(cases=()):
    return CheckContext(all_cases=cases)


def test_required_fields_fails_on_empty_string():
    case = _case(output={"company": ""})
    result = run_check("required_fields", case, {"fields": ["output.company"]}, _ctx((case,)))
    assert result.status == STATUS_FAIL


def test_required_fields_passes_when_present():
    case = _case(output={"company": "Acme"})
    result = run_check("required_fields", case, {"fields": ["output.company"]}, _ctx((case,)))
    assert result.status == STATUS_PASS


def test_enum_checks_allowed_values():
    case = _case(output={"tier": "strong"})
    assert run_check("enum", case, {"field": "output.tier", "values": ["strong", "good"]}, _ctx()).status == STATUS_PASS
    case2 = _case(output={"tier": "bogus"})
    assert run_check("enum", case2, {"field": "output.tier", "values": ["strong", "good"]}, _ctx()).status == STATUS_FAIL


def test_range_checks_bounds():
    case = _case(output={"score": 50})
    assert run_check("range", case, {"field": "output.score", "min": 0, "max": 100}, _ctx()).status == STATUS_PASS
    case2 = _case(output={"score": -1})
    assert run_check("range", case2, {"field": "output.score", "min": 0, "max": 100}, _ctx()).status == STATUS_FAIL


def test_regex_and_not_regex():
    case = _case(output={"role": "Backend Engineer"})
    assert run_check("regex", case, {"field": "output.role", "pattern": "^[A-Za-z ]+$"}, _ctx()).status == STATUS_PASS
    assert run_check("not_regex", case, {"field": "output.role", "pattern": "[0-9]"}, _ctx()).status == STATUS_PASS


def test_reference_match_is_not_applicable_without_reference():
    case = _case(output={"answer": "yes"}, reference=None)
    result = run_check("reference_match", case, {"field": "output.answer"}, _ctx())
    assert result.status == STATUS_NOT_APPLICABLE


def test_reference_match_normalizes_by_default():
    case = _case(output={"answer": "Yes!"}, reference="yes")
    result = run_check("reference_match", case, {"field": "output.answer"}, _ctx())
    assert result.status == STATUS_PASS


def test_duplicate_flags_shared_keys():
    cases = (
        _case(output={"company": "Acme", "role": "Eng"}),
        Case(id="c2", subject="s", input={}, output={"company": "Acme", "role": "Eng"}),
    )
    result = run_check("duplicate", cases[0], {"fields": ["output.company", "output.role"]}, _ctx(cases))
    assert result.status == STATUS_FAIL


def test_duplicate_passes_when_unique():
    cases = (
        _case(output={"company": "Acme", "role": "Eng"}),
        Case(id="c2", subject="s", input={}, output={"company": "Globex", "role": "Eng"}),
    )
    result = run_check("duplicate", cases[0], {"fields": ["output.company", "output.role"]}, _ctx(cases))
    assert result.status == STATUS_PASS


def test_url_reachable_errors_when_network_disabled():
    case = _case(output={"link": "https://example.com"})
    result = run_check("url_reachable", case, {"field": "output.link"}, CheckContext(all_cases=(), allow_network=False))
    assert result.status == STATUS_ERROR


def test_spiffe_id_valid_checks_syntax_and_trust_domain():
    case = _case(output={"id": "spiffe://example.org/mcp/foo"})
    params = {"field": "output.id", "trust_domain": "example.org"}
    assert run_check("spiffe_id_valid", case, params, _ctx()).status == STATUS_PASS

    case_wrong_domain = _case(output={"id": "spiffe://other.org/mcp/foo"})
    assert run_check("spiffe_id_valid", case_wrong_domain, params, _ctx()).status == STATUS_FAIL

    case_bad_syntax = _case(output={"id": "not-a-spiffe-id"})
    assert run_check("spiffe_id_valid", case_bad_syntax, params, _ctx()).status == STATUS_FAIL


def test_spiffe_id_valid_enforces_path_policy_by_tag():
    params = {
        "field": "output.id",
        "trust_domain": "example.org",
        "path_policy": {"mcp_server": "/mcp/"},
    }
    good = _case(output={"id": "spiffe://example.org/mcp/foo"}, tags=["mcp_server"])
    assert run_check("spiffe_id_valid", good, params, _ctx()).status == STATUS_PASS

    bad = _case(output={"id": "spiffe://example.org/k8s/foo"}, tags=["mcp_server"])
    assert run_check("spiffe_id_valid", bad, params, _ctx()).status == STATUS_FAIL


def test_unknown_check_type_is_an_error():
    case = _case()
    result = run_check("does_not_exist", case, {}, _ctx())
    assert result.status == STATUS_ERROR


def test_check_that_raises_is_recorded_as_error_not_a_crash():
    case = _case(output={})
    result = run_check("range", case, {"field": "output.missing"}, _ctx())
    assert result.status == STATUS_ERROR
