import json
import subprocess
from unittest.mock import patch

import pytest

from hids.credaudit_bridge import CredauditNotFound, run_credaudit


def _fake_completed_process(findings):
    payload = json.dumps({"summary": {}, "findings": findings})

    class _Result:
        stdout = payload
        stderr = ""

    return _Result()


def test_raises_when_credaudit_not_on_path():
    with patch("hids.credaudit_bridge.shutil.which", return_value=None):
        with pytest.raises(CredauditNotFound):
            run_credaudit()


def test_parses_findings_into_dataclasses():
    raw_findings = [
        {
            "category": "extension_permission",
            "severity": "HIGH",
            "title": "Extension X requests risky permissions",
            "detail": "cookies, webRequest",
            "location": "chrome:Default:abc",
            "recommendation": "Remove it.",
        }
    ]
    with patch("hids.credaudit_bridge.shutil.which", return_value="/usr/bin/credaudit"), \
         patch("hids.credaudit_bridge.subprocess.run", return_value=_fake_completed_process(raw_findings)):
        findings = run_credaudit()

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].score == 8


def test_raises_when_credaudit_hangs():
    with patch("hids.credaudit_bridge.shutil.which", return_value="/usr/bin/credaudit"), \
         patch("hids.credaudit_bridge.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="credaudit", timeout=1)):
        with pytest.raises(RuntimeError, match="did not finish"):
            run_credaudit(timeout=1)


def test_raises_on_unparseable_output():
    class _BadResult:
        stdout = "not json"
        stderr = "boom"

    with patch("hids.credaudit_bridge.shutil.which", return_value="/usr/bin/credaudit"), \
         patch("hids.credaudit_bridge.subprocess.run", return_value=_BadResult()):
        with pytest.raises(RuntimeError):
            run_credaudit()
