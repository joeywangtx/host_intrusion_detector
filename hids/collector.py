"""Event sources: live Sysmon log, exported .evtx, and JSON fixtures.

Live/`.evtx` reading goes through `wevtutil` (built into Windows, no extra
install) rather than pywin32, so the only external setup this project needs
is Sysmon itself.
"""

from __future__ import annotations

import json
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from hids.events import Event

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Raised by the collector for expected operational failures (channel missing,
# access denied, wevtutil unavailable) so the CLI can print a hint instead of
# a traceback.
class CollectorError(RuntimeError):
    pass


# Errors _parse_event_xml can raise on a malformed / partial event chunk,
# beyond ET.ParseError: a missing node makes `.find(...).text` an AttributeError,
# a missing attribute a KeyError, and a bad int/timestamp a ValueError.
_MALFORMED_EVENT_ERRORS = (ET.ParseError, AttributeError, KeyError, ValueError)


# Sysmon writes SystemTime with 9-digit (nanosecond) fractional seconds and a
# trailing "Z", e.g. "2026-08-20T10:00:00.123456789Z". datetime.fromisoformat
# on Python 3.10 only accepts 3- or 6-digit fractions, so normalize first.
_FRACTION_RE = re.compile(r"\.(\d+)")


def _parse_systemtime(value: str) -> datetime:
    value = value.replace("Z", "+00:00")
    value = _FRACTION_RE.sub(lambda m: "." + m.group(1)[:6], value, count=1)
    return datetime.fromisoformat(value)


def _parse_event_xml(xml_text: str) -> Event:
    root = ET.fromstring(xml_text)
    system = root.find("e:System", _NS)
    event_id = int(system.find("e:EventID", _NS).text)
    computer_el = system.find("e:Computer", _NS)
    computer = (computer_el.text if computer_el is not None else "") or ""
    time_text = system.find("e:TimeCreated", _NS).attrib["SystemTime"]
    timestamp = _parse_systemtime(time_text)

    data = {}
    event_data = root.find("e:EventData", _NS)
    if event_data is not None:
        for d in event_data.findall("e:Data", _NS):
            name = d.attrib.get("Name", "")
            data[name] = d.text or ""

    if event_id == 1:
        return Event(
            event_id=event_id,
            timestamp=timestamp,
            computer=computer,
            process_guid=data.get("ProcessGuid", ""),
            process_id=int(data.get("ProcessId", 0) or 0),
            image=data.get("Image", ""),
            command_line=data.get("CommandLine", ""),
            parent_process_guid=data.get("ParentProcessGuid", ""),
            parent_process_id=int(data.get("ParentProcessId", 0) or 0),
            parent_image=data.get("ParentImage", ""),
            parent_command_line=data.get("ParentCommandLine", ""),
            user=data.get("User", ""),
            extra=data,
        )

    return Event(event_id=event_id, timestamp=timestamp, computer=computer, extra=data)


def read_evtx_via_wevtutil(channel: str, max_events: int = 500) -> Iterator[Event]:
    """Read recent events from a live/exported channel using `wevtutil qe`.

    `channel` can be a live channel name (e.g. SYSMON_CHANNEL) or a path to
    an exported .evtx file (wevtutil auto-detects and adds /lf for files).
    """
    is_file = channel.lower().endswith(".evtx")
    cmd = ["wevtutil", "qe", channel, f"/c:{max_events}", "/rd:true", "/f:xml"]
    if is_file:
        cmd.append("/lf:true")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError as exc:
        raise CollectorError(
            "`wevtutil` was not found. Live/.evtx event reading requires Windows; "
            "on other platforms pass a JSON fixture path instead."
        ) from exc
    except subprocess.CalledProcessError as exc:
        detail = " ".join((exc.stderr or exc.stdout or "").split()).rstrip(".")
        raise CollectorError(
            f"`wevtutil` could not read {channel!r}: {detail or f'exit code {exc.returncode}'}. "
            "The channel may not exist (is Sysmon installed?) or reading it may require an "
            "elevated (Administrator) terminal."
        ) from exc

    # wevtutil concatenates raw <Event>...</Event> blocks with no wrapping
    # root element and no separators, so split on the closing tag.
    raw = result.stdout.strip()
    for chunk in raw.split("</Event>"):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            yield _parse_event_xml(chunk + "</Event>")
        except _MALFORMED_EVENT_ERRORS:
            continue


def load_json_fixture(path: str | Path) -> Iterator[Event]:
    """Load synthetic events from a JSON fixture (used by tests/benchmark).

    Fixture shape: a list of objects, each either matching Event's fields
    directly, or a raw Sysmon-style dict under "raw" with the same keys
    `_parse_event_xml` extracts (ProcessGuid, CommandLine, etc.) plus
    "EventID" and "TimeCreated".
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    for item in payload:
        if "raw" in item:
            raw = item["raw"]
            yield Event(
                event_id=raw["EventID"],
                timestamp=datetime.fromisoformat(raw["TimeCreated"]),
                computer=raw.get("Computer", "TESTHOST"),
                process_guid=raw.get("ProcessGuid", ""),
                process_id=int(raw.get("ProcessId", 0) or 0),
                image=raw.get("Image", ""),
                command_line=raw.get("CommandLine", ""),
                parent_process_guid=raw.get("ParentProcessGuid", ""),
                parent_process_id=int(raw.get("ParentProcessId", 0) or 0),
                parent_image=raw.get("ParentImage", ""),
                parent_command_line=raw.get("ParentCommandLine", ""),
                user=raw.get("User", ""),
                extra=raw,
            )
        else:
            item = dict(item)
            item["timestamp"] = datetime.fromisoformat(item["timestamp"])
            yield Event(**item)


def load_events(source: str) -> Iterable[Event]:
    """Dispatch on source type: live channel name, .evtx path, or .json fixture."""
    if source.lower().endswith(".json"):
        return list(load_json_fixture(source))
    return list(read_evtx_via_wevtutil(source))
