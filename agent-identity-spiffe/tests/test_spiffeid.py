import pytest

from spiffe_identity import spiffeid
from spiffe_identity.spiffeid import SpiffeIDError


@pytest.mark.parametrize("s", ["spiffe://example.org", "spiffe://example.org/a/b-c/d_e.f", "spiffe://a_b-c.d/X"])
def test_parse_valid(s):
    assert str(spiffeid.parse(s)) == s


@pytest.mark.parametrize("s", [
    "http://example.org/a", "spiffe://", "spiffe://Example.org/a", "spiffe://example.org/",
    "spiffe://example.org//a", "spiffe://example.org/a/../b", "spiffe://example.org/a/./b",
    "spiffe://example.org/a b", "spiffe://ex ample.org/a", "spiffe://example.org/" + "a" * 2100,
])
def test_parse_invalid(s):
    with pytest.raises(SpiffeIDError):
        spiffeid.parse(s)


def test_sanitize_segment():
    assert spiffeid.sanitize_segment("Ticket Triage Agent!") == "Ticket-Triage-Agent"
    assert spiffeid.sanitize_segment("  ") == ""
    assert spiffeid.sanitize_segment("..") == ""
    assert spiffeid.sanitize_segment("payments/api") == "payments-api"


def test_from_parts_and_membership():
    sid = spiffeid.from_parts("example.org", "ai-agent", "triage")
    assert sid.member_of("example.org") and sid.is_workload
    assert not spiffeid.from_parts("example.org").is_workload
