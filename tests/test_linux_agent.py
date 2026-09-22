import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from agents.linux import collect as agent
from collector.contract import validate_report

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux agent platform checks")


def test_live_linux_agent_emits_valid_json_with_all_controls(tmp_path):
    output = tmp_path / "report.json"
    result = subprocess.run(
        [
            "bash",
            "agents/linux/check.sh",
            "--device-id",
            "TEST-LINUX",
            "--headless",
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=100,
    )
    report = json.loads(result.stdout)
    validate_report(report)
    assert len(report["checks"]) == 8
    assert json.loads(output.read_text()) == report
    assert output.stat().st_mode & 0o777 == 0o600


def test_unavailable_command_is_error_not_pass(monkeypatch):
    def unavailable(*args):
        raise FileNotFoundError("Command not installed")

    monkeypatch.setattr(agent, "disk_encryption", unavailable)
    report = agent.collect("TEST-LINUX", headless=True)
    assert report["checks"][0]["status"] == "error"
    assert report["checks"][0]["value"] is None
    assert report["checks"][5]["status"] == "not_applicable"


@pytest.mark.parametrize("kind,expected", [("crypt", True), ("part", False)])
def test_encryption_follows_root_device_ancestry(monkeypatch, kind, expected):
    def command(*args):
        if args[0] == "findmnt":
            return "/dev/mapper/root"
        return json.dumps(
            {
                "blockdevices": [
                    {"type": "lvm", "children": [{"type": kind, "children": [{"type": "disk"}]}]}
                ]
            }
        )

    monkeypatch.setattr(agent, "run", command)
    assert agent.disk_encryption() == {"enabled": expected}


def test_partial_encryption_does_not_pass_multidevice_root(monkeypatch):
    monkeypatch.setattr(
        agent,
        "run",
        lambda *args: (
            "/dev/mapper/root"
            if args[0] == "findmnt"
            else json.dumps(
                {
                    "blockdevices": [
                        {"type": "lvm", "children": [{"type": "crypt"}, {"type": "part"}]}
                    ]
                }
            )
        ),
    )
    assert agent.disk_encryption() == {"enabled": False}


def test_container_root_is_unknown_not_false_encryption_failure(monkeypatch):
    monkeypatch.setattr(agent, "run", lambda *args: "overlay")
    with pytest.raises(RuntimeError, match="not a visible block device"):
        agent.disk_encryption()


def test_no_desktop_session_is_error_unless_explicit_headless(monkeypatch):
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    with pytest.raises(RuntimeError, match="No desktop"):
        agent.screen_lock()
    with pytest.raises(agent.NotApplicable):
        agent.screen_lock(headless=True)


def test_gnome_timeout_includes_lock_delay(monkeypatch):
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "synthetic-session")
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "GNOME")
    values = {"lock-enabled": "true", "idle-delay": "uint32 300", "lock-delay": "uint32 60"}
    monkeypatch.setattr(agent, "run", lambda *args: values[args[-1]])
    assert agent.screen_lock() == {"enabled": True, "timeout_minutes": 6}
    values["idle-delay"] = "uint32 0"
    assert agent.screen_lock()["enabled"] is False


def test_permission_denied_firewall_is_not_reported_as_disabled(monkeypatch):
    monkeypatch.setattr(agent, "has", lambda name: name == "ufw")

    def denied(*args):
        raise RuntimeError("Permission denied")

    monkeypatch.setattr(agent, "run", denied)
    with pytest.raises(RuntimeError, match="Cannot verify"):
        agent.firewall()


def test_admin_inventory_includes_primary_group_members(monkeypatch):
    import grp
    import pwd

    monkeypatch.setattr(
        pwd,
        "getpwall",
        lambda: [
            SimpleNamespace(pw_name="root", pw_uid=0, pw_gid=0),
            SimpleNamespace(pw_name="primary-admin", pw_uid=1001, pw_gid=27),
        ],
    )

    def group(name):
        if name == "sudo":
            return SimpleNamespace(gr_mem=["itadmin"], gr_gid=27)
        raise KeyError(name)

    monkeypatch.setattr(grp, "getgrnam", group)
    assert agent.local_admins()["members"] == ["itadmin", "primary-admin", "root"]


def test_software_inventory_excludes_removed_package_records(monkeypatch):
    monkeypatch.setattr(agent, "has", lambda name: name == "dpkg-query")
    monkeypatch.setattr(agent, "run", lambda *args: "active\tinstalled\nold\tconfig-files")
    assert agent.unauthorised_software() == {"installed": ["active"]}


@pytest.mark.parametrize(
    "url",
    [
        "http://collector.example",
        "file:///tmp/report",
        "https://user:pass@example.com",
        "https://example.com?secret=x",
    ],
)
def test_submission_rejects_unsafe_transports(url):
    with pytest.raises(ValueError, match="requires HTTPS"):
        agent.send({}, url, "test-key")
