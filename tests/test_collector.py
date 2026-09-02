import subprocess
from datetime import timezone
from unittest.mock import patch

import pytest

from hids.collector import (
    CollectorError,
    _parse_event_xml,
    _parse_systemtime,
    read_evtx_via_wevtutil,
)

# A realistic Sysmon EventID 1 (process create) record as emitted by
# `wevtutil qe ... /f:xml` -- nanosecond SystemTime, namespaced, no wrapper root.
SYSMON_PROC_CREATE = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>"
    "<TimeCreated SystemTime='2026-08-20T10:00:00.123456789Z'/>"
    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>TESTHOST</Computer>"
    "</System><EventData>"
    "<Data Name='ProcessGuid'>{aabbccdd}</Data><Data Name='ProcessId'>1001</Data>"
    "<Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
    "<Data Name='CommandLine'>cmd.exe /c whoami</Data>"
    "<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data>"
    "<Data Name='ParentProcessId'>500</Data>"
    "</EventData></Event>"
)

SYSMON_4698 = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System><EventID>4698</EventID>"
    "<TimeCreated SystemTime='2026-08-20T10:06:00.000000000Z'/>"
    "<Computer>TESTHOST</Computer></System>"
    "<EventData><Data Name='TaskName'>\\Evil\\Persist</Data></EventData></Event>"
)


def test_parse_systemtime_truncates_nanoseconds():
    ts = _parse_systemtime("2026-08-20T10:00:00.123456789Z")
    assert ts.year == 2026 and ts.microsecond == 123456
    assert ts.tzinfo == timezone.utc


def test_parse_event_xml_process_create():
    event = _parse_event_xml(SYSMON_PROC_CREATE)
    assert event.event_id == 1
    assert event.image_name == "cmd.exe"
    assert event.command_line == "cmd.exe /c whoami"
    assert event.parent_image_name == "explorer.exe"
    assert event.process_id == 1001


def test_parse_event_xml_non_process_event_uses_extra_bag():
    event = _parse_event_xml(SYSMON_4698)
    assert event.event_id == 4698
    assert event.extra["TaskName"] == "\\Evil\\Persist"
    assert event.image == ""


def _fake_run(stdout):
    return subprocess.CompletedProcess(args=["wevtutil"], returncode=0, stdout=stdout, stderr="")


def test_read_evtx_skips_malformed_chunks_but_keeps_good_ones():
    # One valid record, one truncated/garbage record, concatenated as wevtutil does.
    blob = SYSMON_PROC_CREATE + "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>oops</EventID></System></Event>"
    with patch("hids.collector.subprocess.run", return_value=_fake_run(blob)):
        events = list(read_evtx_via_wevtutil("Microsoft-Windows-Sysmon/Operational"))
    assert len(events) == 1
    assert events[0].image_name == "cmd.exe"


def test_read_evtx_raises_collector_error_when_wevtutil_missing():
    with patch("hids.collector.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(CollectorError):
            list(read_evtx_via_wevtutil("Microsoft-Windows-Sysmon/Operational"))


def test_read_evtx_raises_collector_error_on_wevtutil_failure():
    err = subprocess.CalledProcessError(returncode=15007, cmd=["wevtutil"], stderr="The channel was not found.")
    with patch("hids.collector.subprocess.run", side_effect=err):
        with pytest.raises(CollectorError, match="channel"):
            list(read_evtx_via_wevtutil("Nope/Operational"))
