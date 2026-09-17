"""Turns findings the other agents already gathered into one risk score.

Deliberately not an LLM guess: a fixed, inspectable formula so the number
means the same thing every time it's computed and each point is traceable
back to a specific finding.

Model
-----
1. Every finding that FAILED adds "exposure" points, weighted by severity.
2. Findings marked UNKNOWN (checked but not confirmed either way — e.g. we
   can't see whether the router's remote management is on from the LAN
   side) add nothing. Absence of evidence isn't evidence of absence.
3. Findings that PASSED (confirmed protective controls — FileVault on, no
   telnet on the router, etc.) don't cancel exposure 1:1. Instead they earn
   a "hygiene credit" that discounts the total exposure by up to 40% —
   good practices elsewhere lower risk somewhat, but they don't erase a
   real, specific gap.
4. Final score is exposure minus credit, clamped to 0-100.
"""

SEVERITY_WEIGHTS = {"critical": 30, "high": 15, "medium": 7, "low": 3, "info": 0}
MAX_CREDIT_FRACTION = 0.4
VALID_AREAS = {"device", "router", "lan", "other"}


def compute_risk_score(findings: list[dict]) -> dict:
    """Compute a 0-100 risk score for the environment from a list of findings.

    Pass every finding gathered so far — by device_scanner_agent,
    network_recon_agent, and/or vulnerability_analyst_agent — not just the
    bad ones; confirmed protective controls (status "pass") earn hygiene
    credit that discounts the score, so leaving them out only inflates the
    number.

    Each finding is a dict:
      - "title": short human label, e.g. "Pending macOS update"
      - "area": one of "device", "router", "lan", "other"
      - "severity": one of "critical", "high", "medium", "low", "info"
      - "status": "fail" (the gap exists), "pass" (control confirmed
        present/good), or "unknown" (checked but not confirmed either way)

    Returns the score, a qualitative label, a per-area exposure breakdown,
    the hygiene credit applied, and each finding annotated with the exact
    points it contributed — so the number is always explainable.
    """
    exposure_by_area = {a: 0 for a in VALID_AREAS}
    scored = []
    fail_count = 0
    pass_count = 0

    for f in findings:
        area = f.get("area", "other").lower()
        if area not in VALID_AREAS:
            area = "other"
        severity = f.get("severity", "info").lower()
        status = f.get("status", "unknown").lower()
        weight = SEVERITY_WEIGHTS.get(severity, 0)

        if status == "fail":
            exposure_by_area[area] += weight
            fail_count += 1
            contribution = weight
        elif status == "pass":
            pass_count += 1
            contribution = 0
        else:
            contribution = 0

        scored.append({**f, "area": area, "points": contribution})

    total_exposure = sum(exposure_by_area.values())
    total_signals = fail_count + pass_count
    hygiene_ratio = (pass_count / total_signals) if total_signals else 0.0
    credit = round(total_exposure * hygiene_ratio * MAX_CREDIT_FRACTION, 1)

    score = max(0, min(100, round(total_exposure - credit)))

    if score <= 20:
        label = "Low"
    elif score <= 40:
        label = "Moderate"
    elif score <= 60:
        label = "Elevated"
    elif score <= 80:
        label = "High"
    else:
        label = "Critical"

    return {
        "risk_score": score,
        "risk_label": label,
        "total_exposure_before_credit": total_exposure,
        "hygiene_credit_applied": credit,
        "exposure_by_area": exposure_by_area,
        "findings_scored": scored,
    }
