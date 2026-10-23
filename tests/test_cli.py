from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from hids.cli import main
from hids.collector import CollectorError
from hids.credaudit_bridge import CredentialFinding, CredauditNotFound
from hids.events import Event

FIXTURE = Path(__file__).parent / "fixtures" / "labeled_events.json"


def test_no_subcommand_exits_nonzero():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code != 0


def test_benchmark_runs_and_reports(capsys):
    assert main(["benchmark", str(FIXTURE)]) == 0
    out = capsys.readouterr().out
    assert "Precision: 1.00" in out
    assert "Recall: 1.00" in out


def test_scan_fixture_prints_ranked_findings(capsys):
    assert main(["scan", str(FIXTURE)]) == 0
    out = capsys.readouterr().out
    assert "OFFICE_SPAWNED_SHELL" in out
    # Highest score (Office->shell, severity 10) must be printed before a lower one.
    assert out.index("score 10") < out.index("score 8")


def _ps_event(guid, command_line):
    return Event(
        event_id=1,
        timestamp=datetime(2026, 10, 23, 10, 0, 0),
        computer="TESTHOST",
        process_guid=guid,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line=command_line,
    )


def test_scan_groups_identical_processes_and_truncates_long_commands(capsys):
    blob = "A" * 5000
    events = [_ps_event(f"g{i}", f"powershell.exe -EncodedCommand {blob}") for i in range(3)]
    events.append(_ps_event("other", "powershell.exe -NoProfile -NonInteractive -File x.ps1"))
    with patch("hids.cli.load_events", return_value=events):
        assert main(["scan"]) == 0
    out = capsys.readouterr().out
    assert out.count("[score") == 2
    assert "x3 processes, e.g. process_guid=g0" in out
    assert "process_guid=other" in out
    assert blob not in out
    assert "more chars]" in out


def test_scan_with_allowlist_reports_what_it_suppressed(tmp_path, capsys):
    allow = tmp_path / "allow.json"
    allow.write_text(
        '{"entries": [{"name": "noisy tool", "rule": "ENCODED_POWERSHELL", "command_line": ".* -NonInteractive .*"}]}',
        encoding="utf-8",
    )
    events = [_ps_event("g1", "powershell.exe -NonInteractive -File ok.ps1"), _ps_event("g2", "powershell.exe -enc AAAA")]
    with patch("hids.cli.load_events", return_value=events):
        assert main(["scan", "--allowlist", str(allow)]) == 0
    out = capsys.readouterr().out
    assert "process_guid=g2" in out
    assert "process_guid=g1" not in out
    assert "Suppressed by allowlist (1 findings):" in out
    assert "noisy tool" in out


def test_scan_bad_allowlist_exits_2(tmp_path, capsys):
    allow = tmp_path / "allow.json"
    allow.write_text("{not json", encoding="utf-8")
    assert main(["scan", str(FIXTURE), "--allowlist", str(allow)]) == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_scan_reports_collector_error_as_exit_2(capsys):
    with patch("hids.cli.load_events", side_effect=CollectorError("no wevtutil")):
        assert main(["scan"]) == 2
    assert "no wevtutil" in capsys.readouterr().err


def test_audit_credentials_missing_tool_exits_2(capsys):
    with patch("hids.cli.run_credaudit", side_effect=CredauditNotFound("not installed")):
        assert main(["audit-credentials"]) == 2
    assert "not installed" in capsys.readouterr().err


def test_audit_credentials_exit_1_on_high_severity():
    high = CredentialFinding("extension_permission", "HIGH", "t", "d", "loc", "fix")
    with patch("hids.cli.run_credaudit", return_value=[high]):
        assert main(["audit-credentials"]) == 1


def test_audit_credentials_exit_0_when_only_low(capsys):
    low = CredentialFinding("risky_setting", "LOW", "t", "d", "loc", "fix")
    with patch("hids.cli.run_credaudit", return_value=[low]):
        assert main(["audit-credentials"]) == 0
