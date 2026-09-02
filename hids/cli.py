"""CLI entry point.

Subcommands:
    scan <source>       Batch-analyze a live channel, an exported .evtx, or
                        a JSON fixture; print risk-ranked findings.
    benchmark [<path>]  Grade the rule engine against the labeled fixture
                        corpus and print precision/recall/F1.
    audit-credentials   Run the companion credential-auditor tool
                        (browser extensions, plaintext secrets, risky
                        settings) and print risk-ranked findings.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from hids.collector import SYSMON_CHANNEL, CollectorError, load_events
from hids.credaudit_bridge import CredauditNotFound, run_credaudit
from hids.scorer import benchmark, load_labeled_fixture, score_events

_DEFAULT_FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "labeled_events.json"


def cmd_scan(args: argparse.Namespace) -> int:
    source = args.source or SYSMON_CHANNEL
    try:
        events = load_events(source)
    except CollectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    risks = score_events(list(events))

    if not risks:
        print("No findings.")
        return 0

    for risk in risks:
        print(f"\n[score {risk.score}] {risk.image}  (process_guid={risk.process_guid})")
        for finding in risk.findings:
            print(f"    - {finding.rule_id} (severity {finding.severity}, {finding.technique}): {finding.description}")
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    path = Path(args.fixture) if args.fixture else _DEFAULT_FIXTURE
    labeled_events = load_labeled_fixture(path)

    result = benchmark(labeled_events)
    print(
        f"Cases: {len(labeled_events)}  TP={result.true_positives}  "
        f"FP={result.false_positives}  FN={result.false_negatives}"
    )
    print(f"Precision: {result.precision:.2f}  Recall: {result.recall:.2f}  F1: {result.f1:.2f}")
    if result.wrong_rule:
        print(f"warning: {result.wrong_rule} malicious case(s) fired a different rule than the fixture expected")
    return 0


def cmd_audit_credentials(args: argparse.Namespace) -> int:
    try:
        findings = run_credaudit()
    except CredauditNotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not findings:
        print("No findings.")
        return 0

    findings = sorted(findings, key=lambda f: -f.score)
    for finding in findings:
        print(f"\n[score {finding.score}] {finding.category}: {finding.title}")
        print(f"    location: {finding.location}")
        print(f"    detail:   {finding.detail}")
        print(f"    fix:      {finding.recommendation}")

    return 1 if any(f.score >= 8 for f in findings) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hids", description="Lightweight host intrusion detector for Sysmon events.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Scan a live channel, .evtx file, or JSON fixture.")
    scan_parser.add_argument("source", nargs="?", help=f"Defaults to live channel: {SYSMON_CHANNEL}")
    scan_parser.set_defaults(func=cmd_scan)

    bench_parser = sub.add_parser("benchmark", help="Grade the rule engine against the labeled fixture corpus.")
    bench_parser.add_argument("fixture", nargs="?", help="Path to a labeled JSON fixture (default: tests/fixtures/labeled_events.json)")
    bench_parser.set_defaults(func=cmd_benchmark)

    audit_parser = sub.add_parser(
        "audit-credentials",
        help="Run the companion credential-auditor tool and report findings in HIDS's risk format.",
    )
    audit_parser.set_defaults(func=cmd_audit_credentials)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
