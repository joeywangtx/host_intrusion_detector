"""Detection rules.

Each rule is a function `(Event) -> Finding | None`. Rules only see one
event at a time (no cross-event state) except where the event itself
carries the parent/child relationship already (Sysmon EventID 1 includes
the parent's image/command line inline, so "Word spawned PowerShell" is a
single-event check, not a stateful correlation).

CWE/MITRE ATT&CK mapping is included per finding for the same reason the
vuln scanner tags CWE IDs: it lets a finding be checked against a named,
external standard instead of an ad hoc label.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from hids.events import Event

# Severity scale: 1 (informational) - 10 (critical). Kept coarse and
# consistent across rules so scores can be summed meaningfully.
SEVERITY_LOW = 3
SEVERITY_MEDIUM = 6
SEVERITY_HIGH = 8
SEVERITY_CRITICAL = 10


@dataclass
class Finding:
    rule_id: str
    severity: int
    technique: str  # MITRE ATT&CK technique ID, e.g. "T1059.001"
    description: str
    event: Event


# --- Rule: encoded/obfuscated PowerShell -----------------------------------

_ENCODED_PS_PATTERN = re.compile(
    r"-enc(odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{20,}|-noni|-nop\b|-w(indowstyle)?\s+hidden|-bypass",
    re.IGNORECASE,
)


def rule_encoded_powershell(event: Event) -> Finding | None:
    if event.event_id != 1:
        return None
    if "powershell" not in event.image_name and "pwsh" not in event.image_name:
        return None
    if not _ENCODED_PS_PATTERN.search(event.command_line):
        return None
    return Finding(
        rule_id="ENCODED_POWERSHELL",
        severity=SEVERITY_HIGH,
        technique="T1059.001",
        description=(
            f"PowerShell launched with obfuscation/execution-bypass flags: "
            f"{event.command_line!r}"
        ),
        event=event,
    )


# --- Rule: suspicious parent/child process chains ---------------------------

# Office and other document-handling apps that should not normally spawn a
# shell or scripting engine as a direct child.
_OFFICE_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe",
    "acrord32.exe", "acrobat.exe",
}
_SUSPICIOUS_CHILDREN = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
}


def rule_office_spawned_shell(event: Event) -> Finding | None:
    if event.event_id != 1:
        return None
    if event.parent_image_name in _OFFICE_PARENTS and event.image_name in _SUSPICIOUS_CHILDREN:
        return Finding(
            rule_id="OFFICE_SPAWNED_SHELL",
            severity=SEVERITY_CRITICAL,
            technique="T1566.001",
            description=(
                f"{event.parent_image_name} spawned {event.image_name} "
                f"(classic macro/exploit dropper chain): {event.command_line!r}"
            ),
            event=event,
        )
    return None


# Browsers spawning a shell is the same pattern, one step removed (drive-by
# download or malicious extension executing a payload).
_BROWSER_PARENTS = {"chrome.exe", "msedge.exe", "firefox.exe"}


def rule_browser_spawned_shell(event: Event) -> Finding | None:
    if event.event_id != 1:
        return None
    if event.parent_image_name in _BROWSER_PARENTS and event.image_name in _SUSPICIOUS_CHILDREN:
        return Finding(
            rule_id="BROWSER_SPAWNED_SHELL",
            severity=SEVERITY_HIGH,
            technique="T1189",
            description=(
                f"{event.parent_image_name} spawned {event.image_name}: "
                f"{event.command_line!r}"
            ),
            event=event,
        )
    return None


# --- Rule: new scheduled task (persistence) ---------------------------------

def rule_scheduled_task_created(event: Event) -> Finding | None:
    # Security log 4698 ("A scheduled task was created") is the direct
    # signal; schtasks.exe /create via Sysmon EventID 1 is the command-line
    # equivalent when the Security channel isn't being collected.
    if event.event_id == 4698:
        task_name = event.extra.get("TaskName", "<unknown>")
        return Finding(
            rule_id="SCHEDULED_TASK_CREATED",
            severity=SEVERITY_MEDIUM,
            technique="T1053.005",
            description=f"New scheduled task created: {task_name}",
            event=event,
        )
    if event.event_id == 1 and event.image_name == "schtasks.exe" and "/create" in event.command_line.lower():
        return Finding(
            rule_id="SCHEDULED_TASK_CREATED",
            severity=SEVERITY_MEDIUM,
            technique="T1053.005",
            description=f"schtasks.exe /create invoked: {event.command_line!r}",
            event=event,
        )
    return None


# --- Rule: LOLBin used to download/execute (living-off-the-land binaries) ---

_DOWNLOAD_INDICATORS = re.compile(r"http://|https://|-urlcache|bitstransfer|downloadstring|downloadfile", re.IGNORECASE)
_LOLBINS = {"certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "bitsadmin.exe"}


def rule_lolbin_download(event: Event) -> Finding | None:
    if event.event_id != 1:
        return None
    if event.image_name not in _LOLBINS:
        return None
    if not _DOWNLOAD_INDICATORS.search(event.command_line):
        return None
    return Finding(
        rule_id="LOLBIN_DOWNLOAD",
        severity=SEVERITY_HIGH,
        technique="T1105",
        description=f"{event.image_name} used to fetch remote content: {event.command_line!r}",
        event=event,
    )


# --- Rule: process running from a temp/download directory -------------------

_SUSPICIOUS_PATHS = re.compile(
    r"\\appdata\\local\\temp\\|\\windows\\temp\\|\\downloads\\", re.IGNORECASE
)


def rule_exec_from_temp(event: Event) -> Finding | None:
    if event.event_id != 1:
        return None
    if not _SUSPICIOUS_PATHS.search(event.image):
        return None
    return Finding(
        rule_id="EXEC_FROM_TEMP",
        severity=SEVERITY_LOW,
        technique="T1204",
        description=f"Executable launched from a temp/download path: {event.image!r}",
        event=event,
    )


ALL_RULES = [
    rule_encoded_powershell,
    rule_office_spawned_shell,
    rule_browser_spawned_shell,
    rule_scheduled_task_created,
    rule_lolbin_download,
    rule_exec_from_temp,
]


def evaluate(event: Event) -> list[Finding]:
    findings = []
    for rule in ALL_RULES:
        finding = rule(event)
        if finding is not None:
            findings.append(finding)
    return findings
