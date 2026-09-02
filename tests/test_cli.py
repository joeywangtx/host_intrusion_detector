from pathlib import Path
from unittest.mock import patch

import pytest

from hids.cli import main
from hids.collector import CollectorError
from hids.credaudit_bridge import CredentialFinding, CredauditNotFound

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
