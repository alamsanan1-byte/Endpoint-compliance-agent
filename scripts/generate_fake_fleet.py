"""Generate clearly labelled synthetic endpoints; optionally submit to your local collector."""

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agents.linux.collect import send


def make_report(index=0, os_name=None, scenario=None, collected_at=None):
    os_name = os_name or ("windows" if index % 2 == 0 else "linux")
    scenario = scenario or ["good", "bad", "unknown", "warning", "headless"][index % 5]
    values = {
        "disk_encryption": {"enabled": True},
        "patch_level": {"days_since_update": 5},
        "firewall": {"enabled": True},
        "antivirus": {"enabled": True, "definition_age_days": 1},
        "local_admins": {
            "members": ["Administrator" if os_name == "windows" else "root", "itadmin"]
        },
        "screen_lock": {"enabled": True, "timeout_minutes": 5},
        "pending_reboot": {"required": False},
        "unauthorised_software": {"installed": ["Example Editor", "Example Browser"]},
    }
    if scenario == "bad":
        values["disk_encryption"]["enabled"] = False
        values["patch_level"]["days_since_update"] = 65
        values["firewall"]["enabled"] = False
        values["local_admins"]["members"].append("unapproved-lab-admin")
        values["unauthorised_software"]["installed"].append("demo-blocked-app")
    if scenario == "warning":
        values["pending_reboot"]["required"] = True
    checks = [
        {"id": name, "status": "pass", "value": value, "detail": None}
        for name, value in values.items()
    ]
    if scenario == "unknown":
        checks[0].update(status="error", value=None, detail="Synthetic permission-denied example")
    if scenario == "headless" and os_name == "linux":
        checks[5].update(
            status="not_applicable", value=None, detail="Synthetic headless Linux server"
        )
    return {
        "device_id": f"DEMO-{os_name.upper()}-{index + 1:03d}",
        "hostname": f"synthetic-{os_name}-{index + 1:03d}",
        "os": os_name,
        "os_version": "11 (synthetic)" if os_name == "windows" else "Ubuntu 24.04 (synthetic)",
        "collected_at": (collected_at or datetime.now(timezone.utc)).isoformat(),
        "agent_version": "1.0.0",
        "checks": checks,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--output", type=Path, default=Path("output/fake-fleet"))
    parser.add_argument("--send", action="store_true")
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    if not 1 <= args.count <= 10000:
        parser.error("count must be between 1 and 10000")
    args.output.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    for index in range(args.count):
        report = make_report(index, collected_at=now - timedelta(minutes=index % 60))
        (args.output / f"{report['device_id']}.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        if args.send:
            send(report, args.server, os.environ["API_KEY"])
    print(f"Generated {args.count} SYNTHETIC devices in {args.output}")


if __name__ == "__main__":
    main()
