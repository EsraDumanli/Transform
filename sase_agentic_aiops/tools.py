"""
The tool layer the agent operates on. Split deliberately into two kinds:

  - READ_TOOLS: safe to let an LLM call on its own during triage. They only
    look things up.
  - ACTIONS: mutating. Nothing in this file calls these directly from the
    triage path -- main.py only calls one after the human-approval gate
    (or an explicit --approve demo flag) says to. That split is the whole
    point of the reference architecture: the orchestrator proposes, the
    gate decides, the executor is the only thing that acts.

Everything here is simulated. There is no real SASE platform behind it.
"""

from __future__ import annotations

import random

from telemetry import PLANTED_EXFIL_USER, PLANTED_PEER_OUTLIER_USER, PLANTED_DRIFT_USER

_rng = random.Random(3)

_IDENTITY_DB = {
    PLANTED_EXFIL_USER: {"risk_level": "high", "mfa_enrolled": True, "recent_password_reset": True},
    PLANTED_PEER_OUTLIER_USER: {"risk_level": "medium", "mfa_enrolled": False, "recent_password_reset": False},
    PLANTED_DRIFT_USER: {"risk_level": "low", "mfa_enrolled": True, "recent_password_reset": False},
}

_NETWORK_DB = {
    PLANTED_EXFIL_USER: {"reputation": "suspicious", "asn_country": "NG", "known_vpn_exit": False},
    PLANTED_PEER_OUTLIER_USER: {"reputation": "neutral", "asn_country": "US", "known_vpn_exit": True},
    PLANTED_DRIFT_USER: {"reputation": "clean", "asn_country": "US", "known_vpn_exit": False},
}

_POLICY_DB = {
    "default-access-policy": {"policy_id": "default-access-policy", "mfa_required": True, "last_changed_days_ago": 41},
}


def identity_lookup(user: str) -> dict:
    """Read-only. Returns identity/auth risk signals for a user."""
    return _IDENTITY_DB.get(user, {"risk_level": "low", "mfa_enrolled": True, "recent_password_reset": False})


def network_lookup(user: str) -> dict:
    """Read-only. Returns network/IP reputation signals associated with a user's recent sessions."""
    return _NETWORK_DB.get(user, {"reputation": "clean", "asn_country": "US", "known_vpn_exit": False})


def policy_lookup(policy_id: str = "default-access-policy") -> dict:
    """Read-only. Returns the current state of an access policy."""
    return _POLICY_DB.get(policy_id, {"policy_id": policy_id, "mfa_required": True, "last_changed_days_ago": 0})


READ_TOOLS = {
    "identity_lookup": identity_lookup,
    "network_lookup": network_lookup,
    "policy_lookup": policy_lookup,
}

# JSON schemas for the walk-rung Claude tool-use loop (see agent.py).
READ_TOOL_SCHEMAS = [
    {
        "name": "identity_lookup",
        "description": "Look up identity and authentication risk signals for a user.",
        "input_schema": {
            "type": "object",
            "properties": {"user": {"type": "string", "description": "The user id, e.g. user_007"}},
            "required": ["user"],
        },
    },
    {
        "name": "network_lookup",
        "description": "Look up network/IP reputation signals associated with a user's recent sessions.",
        "input_schema": {
            "type": "object",
            "properties": {"user": {"type": "string", "description": "The user id, e.g. user_007"}},
            "required": ["user"],
        },
    },
    {
        "name": "policy_lookup",
        "description": "Look up the current state of an access policy.",
        "input_schema": {
            "type": "object",
            "properties": {"policy_id": {"type": "string", "description": "Policy id. Defaults to the org's default access policy."}},
            "required": [],
        },
    },
]


# ---- Mutating actions. Gated -- never call these from the triage path. ----

def quarantine_session(user: str) -> dict:
    return {"action": "quarantine_session", "user": user, "result": "session revoked, device flagged for review"}


def adjust_policy(policy_id: str, change: str) -> dict:
    return {"action": "adjust_policy", "policy_id": policy_id, "change": change, "result": "policy updated"}


def open_ticket(summary: str) -> dict:
    ticket_id = f"OPS-{_rng.randint(1000, 9999)}"
    return {"action": "open_ticket", "ticket_id": ticket_id, "summary": summary, "result": "ticket created"}


ACTIONS = {
    "quarantine_session": quarantine_session,
    "adjust_policy": adjust_policy,
    "open_ticket": open_ticket,
}

# Whether taking this action for real would need a human to sign off first.
ACTION_NEEDS_APPROVAL = {
    "quarantine_session": True,
    "adjust_policy": True,
    "open_ticket": False,  # opening a ticket isn't destructive
}
