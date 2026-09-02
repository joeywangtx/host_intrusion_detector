"""Normalized event model.

Sysmon writes to the Windows Event Log as EventID-tagged XML with fields that
vary by ID (process creation vs. network connect vs. file create). Rules
should not care whether an Event arrived via live `wevtutil` XML, an
exported .evtx, or a synthetic JSON fixture used in tests -- they should all
collapse to this one shape first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


# Sysmon event IDs this project understands. Full list:
# https://learn.microsoft.com/sysinternals/downloads/sysmon
EVENT_PROCESS_CREATE = 1
EVENT_NETWORK_CONNECT = 3
EVENT_PROCESS_TERMINATE = 5
EVENT_DRIVER_LOADED = 6
EVENT_IMAGE_LOADED = 7
EVENT_FILE_CREATE = 11
EVENT_REGISTRY_SET = 13

# Not a Sysmon event -- Security log, "A scheduled task was created".
EVENT_SCHEDULED_TASK_CREATED = 4698


@dataclass
class Event:
    event_id: int
    timestamp: datetime
    computer: str
    # Common process-creation fields (EventID 1). Empty string when the
    # event type doesn't carry them, rather than None, so rules can do
    # plain substring/regex checks without a None-guard on every field.
    process_guid: str = ""
    process_id: int = 0
    image: str = ""
    command_line: str = ""
    parent_process_guid: str = ""
    parent_process_id: int = 0
    parent_image: str = ""
    parent_command_line: str = ""
    user: str = ""
    # Raw field bag for anything rule-specific (e.g. TaskName for 4698,
    # DestinationIp for EventID 3) that doesn't deserve its own column.
    extra: dict = field(default_factory=dict)

    @property
    def image_name(self) -> str:
        return self.image.rsplit("\\", 1)[-1].lower() if self.image else ""

    @property
    def parent_image_name(self) -> str:
        return self.parent_image.rsplit("\\", 1)[-1].lower() if self.parent_image else ""
