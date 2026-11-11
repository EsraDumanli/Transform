"""agent-discovery: find workloads, propose SPIFFE IDs, gate them on human approval, register them.

  python -m spiffe_identity.cli discover --config config.json
  python -m spiffe_identity.cli plan     --config config.json [--json]
  python -m spiffe_identity.cli apply    --config config.json --approver "you" [--issue-dir out/] [--approve-all]
  python -m spiffe_identity.cli entries  --config config.json
  python -m spiffe_identity.cli jwt      --config config.json --spiffe-id spiffe://td/x --audience my-service
  python -m spiffe_identity.cli verify-x509 --cert svid.pem --bundle bundle.pem
  python -m spiffe_identity.cli verify-jwt  --token-file t.jwt --jwks jwks.json --audience my-service
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import approval, ca, config as config_mod, discovery
from .classifier import ClaudeProposer, LLMError
from .client import Client, ServerError
from .policy import Policy, PolicyError, Proposal


def _discover(cfg: dict) -> list[discovery.Result]:
    dcfg = config_mod.section(cfg, "discovery")
    if not dcfg:
        raise config_mod.ConfigError("discovery: enable at least one source")
    return discovery.run(discovery.build(dcfg, lambda p: config_mod.resolve_path(cfg, p)))


def _print_results(results: list[discovery.Result]) -> None:
    for r in results:
        status = f"ERROR: {r.error}" if r.error else f"{len(r.workloads)} workload(s)"
        print(f"[{r.source}] {status}")
        for w in r.warnings:
            print(f"  warning: {w}")


def _plan(cfg: dict, use_llm: bool | None) -> tuple[list[discovery.Result], list[Proposal]]:
    results = _discover(cfg)
    policy = Policy.from_config(cfg["trust_domain"], config_mod.section(cfg, "policy"))
    seen, proposals = set(), []
    for r in results:
        for w in r.workloads:
            if w.key() in seen:
                continue
            seen.add(w.key())
            proposals.append(policy.assign(w))
    llm_cfg = cfg.get("llm") or {}
    enabled = llm_cfg.get("enabled", False) if use_llm is None else use_llm
    unassigned = [p for p in proposals if not p.assignable]
    if enabled and unassigned:
        try:
            ClaudeProposer(cfg["trust_domain"], llm_cfg).propose(unassigned)
        except LLMError as e:
            print(f"LLM step skipped: {e}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 - API/network errors leave workloads unassigned
            print(f"LLM step failed ({type(e).__name__}: {e}); those workloads stay unassigned", file=sys.stderr)
    return results, proposals


def _print_plan(proposals: list[Proposal]) -> None:
    assigned = [p for p in proposals if p.assignable]
    unassigned = [p for p in proposals if not p.assignable]
    print(f"\n{len(assigned)} proposed identity(ies):")
    for p in assigned:
        print(f"  {p.spiffe_id:<60} <- {p.workload.name} ({p.workload.kind}) [{p.assigned_by}]")
    print(f"\n{len(unassigned)} workload(s) left unassigned (not enough data to assign an identity):")
    for p in unassigned:
        print(f"  {p.workload.name} ({p.workload.kind}, {p.workload.source}): {'; '.join(p.problems)}")


def cmd_discover(args, cfg) -> int:
    results = _discover(cfg)
    if args.json:
        print(json.dumps([{**r.__dict__, "workloads": [w.to_dict() for w in r.workloads]} for r in results], indent=2))
    else:
        _print_results(results)
        for r in results:
            for w in r.workloads:
                print(f"  {w.kind:<16} {w.name:<40} {', '.join(w.selectors)}")
    return 0


def cmd_plan(args, cfg) -> int:
    results, proposals = _plan(cfg, args.llm)
    if args.json:
        print(json.dumps([p.to_dict() for p in proposals], indent=2))
    else:
        _print_results(results)
        _print_plan(proposals)
    return 0


def cmd_apply(args, cfg) -> int:
    client = Client.from_config(cfg, lambda p: config_mod.resolve_path(cfg, p))
    results, proposals = _plan(cfg, args.llm)
    _print_results(results)
    _print_plan(proposals)
    approved = approval.gate(proposals, approve_all=args.approve_all)
    if not approved:
        print("\nNo proposals approved; nothing registered.")
        return 0
    issue_dir = Path(args.issue_dir) if args.issue_dir else None
    failures = 0
    for p in approved:
        try:
            entry = client.create_entry({
                "spiffe_id": p.spiffe_id, "selectors": p.workload.selectors, "source": p.workload.source,
                "assigned_by": p.assigned_by, "approved_by": args.approver, "rationale": p.rationale,
            })
            print(f"{'registered' if entry.get('created') else 'already registered'}: {p.spiffe_id} (entry {entry['id']})")
            if issue_dir:
                cert, key, bundle = client.x509_svid(p.spiffe_id)
                d = issue_dir / p.spiffe_id.removeprefix("spiffe://").replace("/", "_")
                d.mkdir(parents=True, exist_ok=True)
                (d / "svid.pem").write_bytes(cert)
                fd = os.open(d / "svid-key.pem", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(key)
                (d / "bundle.pem").write_bytes(bundle)
                print(f"  X.509-SVID written to {d}/")
        except ServerError as e:
            failures += 1
            print(f"FAILED {p.spiffe_id}: {e}", file=sys.stderr)
    return 1 if failures else 0


def cmd_entries(args, cfg) -> int:
    client = Client.from_config(cfg, lambda p: config_mod.resolve_path(cfg, p))
    print(json.dumps(client.list_entries(), indent=2))
    return 0


def cmd_jwt(args, cfg) -> int:
    client = Client.from_config(cfg, lambda p: config_mod.resolve_path(cfg, p))
    print(client.jwt_svid(args.spiffe_id, args.audience))
    return 0


def cmd_verify_x509(args) -> int:
    sid = ca.verify_x509_svid(Path(args.cert).read_bytes(), Path(args.bundle).read_bytes())
    print(f"valid X.509-SVID for {sid}")
    return 0


def cmd_verify_jwt(args) -> int:
    token = Path(args.token_file).read_text().strip()
    sid = ca.verify_jwt_svid(token, json.loads(Path(args.jwks).read_text()), args.audience)
    print(f"valid JWT-SVID for {sid} (audience {args.audience})")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="agent-discovery", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def with_config(p):
        p.add_argument("--config", required=True)
        return p

    p = with_config(sub.add_parser("discover", help="run discovery sources and list what they found"))
    p.add_argument("--json", action="store_true")
    for name, helptext in (("plan", "discover + propose identities (no changes made)"), ("apply", "plan + approval gate + register on the server")):
        p = with_config(sub.add_parser(name, help=helptext))
        g = p.add_mutually_exclusive_group()
        g.add_argument("--llm", dest="llm", action="store_true", default=None, help="force the Claude step on")
        g.add_argument("--no-llm", dest="llm", action="store_false", help="force the Claude step off")
        if name == "plan":
            p.add_argument("--json", action="store_true")
        else:
            p.add_argument("--approver", required=True, help="your name, recorded on every entry you approve")
            p.add_argument("--issue-dir", help="also mint an X.509-SVID per approved identity into this directory")
            p.add_argument("--approve-all", action="store_true", help="DEMO ONLY: approve every proposal without prompting")
    with_config(sub.add_parser("entries", help="list registration entries on the server"))
    p = with_config(sub.add_parser("jwt", help="mint a JWT-SVID for a registered SPIFFE ID"))
    p.add_argument("--spiffe-id", required=True)
    p.add_argument("--audience", required=True, action="append", help="repeat for several audiences")
    p = sub.add_parser("verify-x509", help="verify an X.509-SVID against a trust bundle")
    p.add_argument("--cert", required=True)
    p.add_argument("--bundle", required=True)
    p = sub.add_parser("verify-jwt", help="verify a JWT-SVID against a JWKS bundle")
    p.add_argument("--token-file", required=True)
    p.add_argument("--jwks", required=True)
    p.add_argument("--audience", required=True)

    args = ap.parse_args(argv)
    try:
        if args.cmd == "verify-x509":
            return cmd_verify_x509(args)
        if args.cmd == "verify-jwt":
            return cmd_verify_jwt(args)
        cfg = config_mod.load(args.config)
        return {"discover": cmd_discover, "plan": cmd_plan, "apply": cmd_apply, "entries": cmd_entries, "jwt": cmd_jwt}[args.cmd](args, cfg)
    except (config_mod.ConfigError, discovery.ConfigError, PolicyError, ServerError, ca.CAError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
