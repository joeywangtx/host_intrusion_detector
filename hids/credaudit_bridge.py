"""Bridge to the companion credential-auditor project.

HIDS watches process/persistence telemetry; credential-auditor watches a
different, complementary attack surface (over-permissioned browser
extensions, plaintext secrets in local configs, risky browser settings).
Rather than duplicating that logic here, `hids audit-credentials` shells
out to the `credaudit` CLI (installed separately, see
../credential_auditor) and folds its JSON findings into HIDS's own
severity-ranked report format, so a single tool invocation can cover both
surfaces during a periodic host check.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

_SEVERITY_TO_SCORE = {"LOW": 3, "MEDIUM": 6, "HIGH": 8, "CRITICAL": 10}


@dataclass
class CredentialFinding:
    category: str
    severity: str
    title: str
    detail: str
    location: str
    recommendation: str

    @property
    def score(self) -> int:
        return _SEVERITY_TO_SCORE.get(self.severity, 0)


class CredauditNotFound(RuntimeError):
    pass


DEFAULT_TIMEOUT = 120.0


def run_credaudit(
    extra_args: list[str] | None = None, timeout: float = DEFAULT_TIMEOUT
) -> list[CredentialFinding]:
    """Run `credaudit --json` as a subprocess and parse its findings.

    Raises CredauditNotFound if the `credaudit` command isn't on PATH
    (it's a separate installable package, not a dependency of this one).
    Raises RuntimeError if credaudit hangs past `timeout` or emits
    unparseable output.
    """
    if shutil.which("credaudit") is None:
        raise CredauditNotFound(
            "credaudit is not installed or not on PATH. "
            "Install it from ../credential_auditor with `pip install -e .`."
        )

    cmd = ["credaudit", "--json", *(extra_args or [])]
    # credaudit exits 1 when HIGH/CRITICAL findings exist -- that's a
    # signal, not a failure, so don't check=True here.
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"credaudit did not finish within {timeout:.0f}s") from exc

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"credaudit produced unparseable output: {result.stderr}") from exc

    return [
        CredentialFinding(
            category=f["category"],
            severity=f["severity"],
            title=f["title"],
            detail=f["detail"],
            location=f["location"],
            recommendation=f["recommendation"],
        )
        for f in payload.get("findings", [])
    ]
