"""5 scenarios confirming compute_risk_score's formula behaves correctly.

Why pytest and not `adk eval`
------------------------------
There's also a risk_score_eval.evalset.json in this app, built for ADK's
own eval harness (`adk eval`). That harness checks whether an *LLM agent*
calls the right tool with the right arguments and phrases a matching
response — which requires an actual paid model call (Gemini or Anthropic)
every time you run it.

These tests check something narrower but more fundamental: is the scoring
*formula itself* correct? compute_risk_score() is plain deterministic
Python, so it doesn't need a model at all — these run for free, in
milliseconds, and will catch a broken formula before it ever reaches an
agent. Run with: `pytest tests/test_risk_score.py -v`

The formula being tested (see tools/risk_score_tools.py):
    exposure   = sum(severity_weight for every finding with status="fail")
    hygiene    = passes / (passes + fails)      — unknowns don't count
    credit     = exposure * hygiene * 0.4        — good practices discount
                                                    exposure, capped at 40%
    score      = clamp(exposure - credit, 0, 100)
"""

from dumanli_security_posture.tools.risk_score_tools import compute_risk_score


def test_pristine_environment_scores_zero():
    """Scenario 1 — every check passed, nothing failed.

    Logic: with zero fails, exposure is 0 regardless of how many passes
    exist (credit is a percentage of exposure, so it has nothing to
    discount). A perfectly clean environment must score exactly 0, not
    just "low" — there should be no floor above zero.
    """
    findings = [
        {"title": "FileVault on", "area": "device", "severity": "high", "status": "pass"},
        {"title": "SIP enabled", "area": "device", "severity": "medium", "status": "pass"},
        {"title": "Firewall enabled", "area": "device", "severity": "medium", "status": "pass"},
        {"title": "No telnet on router", "area": "router", "severity": "high", "status": "pass"},
        {"title": "All LAN devices identified", "area": "lan", "severity": "medium", "status": "pass"},
    ]
    result = compute_risk_score(findings)
    assert result["risk_score"] == 0
    assert result["risk_label"] == "Low"
    assert result["total_exposure_before_credit"] == 0


def test_multiple_uncontrolled_criticals_hit_critical_band():
    """Scenario 2 — three critical fails, zero passing controls anywhere.

    Logic: with no passes at all, hygiene_ratio is 0/3 = 0, so credit is
    0 no matter how severe the exposure is — nothing offsets it. Exposure
    = 3 x 30 (critical weight) = 90, uncapped by any credit, landing in
    the Critical band (>80). This confirms severe, uncontrolled findings
    can't be diluted away by the credit mechanism.
    """
    findings = [
        {"title": "Remote code execution CVE unpatched", "area": "device", "severity": "critical", "status": "fail"},
        {"title": "Router default admin credentials confirmed", "area": "router", "severity": "critical", "status": "fail"},
        {"title": "Telnet exposed to LAN with no auth", "area": "router", "severity": "critical", "status": "fail"},
    ]
    result = compute_risk_score(findings)
    assert result["risk_score"] == 90
    assert result["risk_label"] == "Critical"
    assert result["hygiene_credit_applied"] == 0.0
    assert result["exposure_by_area"]["device"] == 30
    assert result["exposure_by_area"]["router"] == 60


def test_real_scan_mixed_findings_regression():
    """Scenario 3 — the actual 12 findings from this Mac's real scan.

    Logic: a regression pin. This is the exact finding set gathered
    earlier this session (pending macOS update, FileVault/SIP/firewall
    on, stealth off, clean router except two unknowns, 9/11 LAN devices
    unidentified). It locks in today's real-world result — 21/Moderate —
    so a future change to the formula can't silently change what this
    environment scores without a test failing to flag it.
    """
    findings = [
        {"title": "Pending macOS update (Tahoe 26.6.2, Recommended)", "area": "device", "severity": "high", "status": "fail"},
        {"title": "FileVault full-disk encryption on", "area": "device", "severity": "high", "status": "pass"},
        {"title": "System Integrity Protection enabled", "area": "device", "severity": "medium", "status": "pass"},
        {"title": "Application Firewall enabled", "area": "device", "severity": "medium", "status": "pass"},
        {"title": "Firewall stealth mode off", "area": "device", "severity": "low", "status": "fail"},
        {"title": "No risky listening services", "area": "device", "severity": "low", "status": "pass"},
        {"title": "No telnet/FTP/exposed UPnP or TR-069 on router", "area": "router", "severity": "high", "status": "pass"},
        {"title": "Router exposes only DNS/HTTP/HTTPS (53, 80, 443)", "area": "router", "severity": "medium", "status": "pass"},
        {"title": "Router remote-management/UPnP state (WAN side)", "area": "router", "severity": "medium", "status": "unknown"},
        {"title": "Router admin password changed from default", "area": "router", "severity": "medium", "status": "unknown"},
        {"title": "9 of 11 LAN devices unidentified", "area": "lan", "severity": "medium", "status": "fail"},
        {"title": "No IoT/guest network segmentation", "area": "lan", "severity": "low", "status": "fail"},
    ]
    result = compute_risk_score(findings)
    assert result["risk_score"] == 21
    assert result["risk_label"] == "Moderate"
    assert result["total_exposure_before_credit"] == 28
    assert result["hygiene_credit_applied"] == 6.7
    assert result["exposure_by_area"] == {"device": 18, "router": 0, "lan": 10, "other": 0}


def test_strong_hygiene_dilutes_but_does_not_erase_exposure():
    """Scenario 4 — 6 passing controls against only 2 minor fails.

    Logic: this is the credit mechanism's core guarantee: it discounts,
    it never zeroes out. exposure=10, hygiene_ratio=6/8=0.75, so credit
    = 10 * 0.75 * 0.4 = 3.0 exactly — never more than 40% of exposure,
    no matter how many passes exist. Score is 7, not 0: two real,
    specific gaps (no IoT segmentation, unidentified devices) still show
    up even in an otherwise well-hardened environment.
    """
    findings = [
        {"title": "FileVault on", "area": "device", "severity": "high", "status": "pass"},
        {"title": "SIP enabled", "area": "device", "severity": "medium", "status": "pass"},
        {"title": "Firewall enabled", "area": "device", "severity": "medium", "status": "pass"},
        {"title": "No telnet on router", "area": "router", "severity": "high", "status": "pass"},
        {"title": "Only 80/443/53 open on router", "area": "router", "severity": "medium", "status": "pass"},
        {"title": "No risky listening services", "area": "device", "severity": "low", "status": "pass"},
        {"title": "No IoT segmentation", "area": "lan", "severity": "low", "status": "fail"},
        {"title": "2 unidentified LAN devices", "area": "lan", "severity": "medium", "status": "fail"},
    ]
    result = compute_risk_score(findings)
    assert result["risk_score"] == 7
    assert result["risk_label"] == "Low"
    assert result["total_exposure_before_credit"] == 10
    assert result["hygiene_credit_applied"] == 3.0


def test_no_findings_yet_scores_zero_without_crashing():
    """Scenario 5 — no scan has run yet; the tool receives an empty list.

    Logic: an edge case, not a "good" environment — the difference
    matters at the agent layer (risk_score_agent's instructions tell it
    to say "no data yet" rather than report this 0 as a real score). At
    the tool layer, the concern is purely robustness: passes=fails=0
    means the hygiene_ratio division (passes / (passes + fails)) would
    divide by zero without a guard. This confirms that guard holds and
    the tool degrades to a safe, inert 0 instead of raising.
    """
    result = compute_risk_score([])
    assert result["risk_score"] == 0
    assert result["risk_label"] == "Low"
    assert result["hygiene_credit_applied"] == 0.0
    assert result["exposure_by_area"] == {"device": 0, "router": 0, "lan": 0, "other": 0}
