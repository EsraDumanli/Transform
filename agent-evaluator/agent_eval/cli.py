from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .report import render_report
from .rubric import load_rubric
from .runner import EvalError, RunConfig, RunnerError, Verdict
from .runner import run as run_eval


def _cmd_run(args: argparse.Namespace) -> int:
    config = RunConfig(
        dataset_path=Path(args.dataset),
        rubric_path=Path(args.rubric),
        out_dir=Path(args.out),
        allow_network=args.allow_network,
    )
    try:
        result = run_eval(config)
    except RunnerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    run_dir = result["run_dir"]
    print(f"wrote {run_dir}/results.jsonl, errors.jsonl, run.json, report.md")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    manifest_path = run_dir / "run.json"
    if not manifest_path.exists():
        print(f"error: no run.json in {run_dir}", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rubric = load_rubric(manifest["rubric"]["source"])

    verdicts = []
    with (run_dir / "results.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                verdicts.append(Verdict(**json.loads(line)))

    errors = []
    with (run_dir / "errors.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                errors.append(EvalError(**json.loads(line)))

    report_md = render_report(rubric, verdicts, errors, manifest)
    (run_dir / "report.md").write_text(report_md, encoding="utf-8")
    print(f"wrote {run_dir}/report.md")
    return 0


def _not_yet(name: str, milestone: str) -> int:
    print(f"error: '{name}' is not implemented yet (planned for {milestone})", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-eval")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="grade a dataset against a rubric")
    p_run.add_argument("--dataset", required=True, help="path to a JSONL case dataset")
    p_run.add_argument("--rubric", required=True, help="path to a rubric JSON file")
    p_run.add_argument("--out", default="runs", help="directory under which the run folder is created")
    p_run.add_argument("--allow-network", action="store_true", help="enable checks that make network requests")
    p_run.set_defaults(fn=_cmd_run)

    p_report = sub.add_parser("report", help="re-render report.md from an existing run folder")
    p_report.add_argument("run_dir", help="path to a runs/<timestamp>-<rubric>/ folder")
    p_report.set_defaults(fn=_cmd_report)

    p_cases = sub.add_parser("cases", help="run an adapter and write a dataset (adapters land in M2)")
    p_cases.set_defaults(fn=lambda args: _not_yet("cases", "M2"))

    p_calibrate = sub.add_parser("calibrate", help="measure judge agreement against hand labels (lands in M4)")
    p_calibrate.set_defaults(fn=lambda args: _not_yet("calibrate", "M4"))

    p_compare = sub.add_parser("compare", help="diff two runs on the same dataset and rubric (lands in M5)")
    p_compare.set_defaults(fn=lambda args: _not_yet("compare", "M5"))

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
