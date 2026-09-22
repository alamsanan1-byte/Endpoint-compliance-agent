#!/usr/bin/env python3
"""Read-only Linux facts. Python 3.10+ standard library; no third-party agent packages."""

import argparse
import glob
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NotApplicable(Exception):
    pass


def run(*args):
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "LC_ALL": "C"},
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"{args[0]} exited {result.returncode}; check permissions/service availability"
        )
    return result.stdout.strip()


def has(name):
    return shutil.which(name) is not None


def disk_encryption():
    source = run("findmnt", "-n", "-o", "SOURCE", "--target", "/").split("[")[0]
    if not source.startswith("/dev/"):
        raise RuntimeError("Root filesystem is not a visible block device (container/network root)")
    tree = json.loads(run("lsblk", "--inverse", "--json", "-o", "NAME,TYPE", source))

    def protected(node, encrypted=False):
        encrypted = encrypted or node["type"] == "crypt"
        return (
            all(protected(child, encrypted) for child in node["children"])
            if node.get("children")
            else encrypted
        )

    devices = tree.get("blockdevices", [])
    if not devices:
        raise RuntimeError("No root block device found")
    return {"enabled": all(protected(device) for device in devices)}


def patch_level():
    # Timestamp proxy for completed package updates, not a vulnerability or missing-patch scan.
    timestamps = []
    if has("dpkg-query"):
        for name in glob.glob("/var/log/apt/history.log*"):
            opener = gzip.open if name.endswith(".gz") else open
            with opener(name, "rt", encoding="utf-8", errors="replace") as handle:
                for block in handle.read().split("\n\n"):
                    if not re.search(r"^(Upgrade|Install):", block, re.M):
                        continue
                    match = re.search(r"^End-Date:\s*(.+)$", block, re.M)
                    if match:
                        timestamps.append(datetime.fromisoformat(match[1].strip()).timestamp())
    elif has("rpm"):
        # RPM install time is available without initiating a repository refresh.
        for line in run("rpm", "-qa", "--qf", "%{INSTALLTIME}\n").splitlines():
            if line.isdigit():
                timestamps.append(float(line))
    else:
        raise RuntimeError("Unsupported package manager: apt/dpkg or rpm required")
    if not timestamps:
        raise RuntimeError("No readable completed package-update history")
    age = (time.time() - max(timestamps)) / 86400
    if age < -0.01:
        raise RuntimeError("Package-update time is in the future; verify the system clock")
    return {"days_since_update": round(max(0, age), 2)}


def firewall():
    states = []
    errors = []
    if has("ufw"):
        try:
            states.append(run("ufw", "status").startswith("Status: active"))
        except RuntimeError as exc:
            errors.append(str(exc))
    if has("firewall-cmd"):
        result = subprocess.run(
            ["firewall-cmd", "--state"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip() == "running":
            states.append(True)
        elif result.stdout.strip() == "not running" or result.stderr.strip() == "not running":
            states.append(False)
        else:
            errors.append("firewalld status unavailable")
    if any(states):
        return {"enabled": True}
    if errors or not states:
        raise RuntimeError(
            "Cannot verify ufw/firewalld; direct nftables/iptables rules are unsupported"
        )
    return {"enabled": False}


def antivirus():
    if not has("clamscan"):
        raise RuntimeError("ClamAV not installed; other antivirus providers are unsupported")
    version = run("clamscan", "--version").split("/", 2)
    if len(version) != 3:
        raise RuntimeError("ClamAV signature timestamp unavailable")
    stamp = datetime.strptime(version[2].strip(), "%a %b %d %H:%M:%S %Y").timestamp()
    age = (time.time() - stamp) / 86400
    if age < -0.01:
        raise RuntimeError("ClamAV signature timestamp is in the future")
    # A command-line scanner alone does not count as running protection.
    active = []
    for service in ["clamav-daemon", "clamd@scan"]:
        result = subprocess.run(
            ["systemctl", "is-active", service], capture_output=True, text=True, timeout=10
        )
        active.append(result.stdout.strip() == "active")
    return {"enabled": any(active), "definition_age_days": round(max(0, age), 2)}


def local_admins():
    import grp
    import pwd

    # Only conventional groups + UID 0. Custom sudoers/polkit rules require manual review.
    users = pwd.getpwall()
    members = {user.pw_name for user in users if user.pw_uid == 0}
    for group_name in ["sudo", "wheel"]:
        try:
            group = grp.getgrnam(group_name)
        except KeyError:
            continue
        members.update(group.gr_mem)
        members.update(user.pw_name for user in users if user.pw_gid == group.gr_gid)
    return {"members": sorted(members)}


def screen_lock(headless=False):
    if headless:
        raise NotApplicable("Explicitly enrolled as a headless Linux endpoint")
    if not os.getenv("DBUS_SESSION_BUS_ADDRESS"):
        raise RuntimeError("No desktop session available; use --headless only for a genuine server")
    if "GNOME" not in os.getenv("XDG_CURRENT_DESKTOP", "").upper():
        raise RuntimeError("Only GNOME desktop screen-lock collection is supported")
    enabled = run("gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled") == "true"
    idle = run("gsettings", "get", "org.gnome.desktop.session", "idle-delay")
    delay = run("gsettings", "get", "org.gnome.desktop.screensaver", "lock-delay")
    seconds = int(idle.split()[-1])
    return {
        "enabled": enabled and seconds > 0,
        "timeout_minutes": (seconds + int(delay.split()[-1])) / 60,
    }


def pending_reboot():
    if has("dpkg-query"):
        return {"required": Path("/var/run/reboot-required").exists()}
    if has("needs-restarting"):
        result = subprocess.run(
            ["needs-restarting", "-r"], capture_output=True, text=True, timeout=10
        )
        if result.returncode in (0, 1):
            return {"required": result.returncode == 1}
    raise RuntimeError("Reboot signal unavailable; RPM systems require needs-restarting")


def unauthorised_software():
    if has("dpkg-query"):
        lines = run("dpkg-query", "-W", "-f", "${binary:Package}\t${db:Status-Status}\n")
        names = [line.split("\t")[0] for line in lines.splitlines() if line.endswith("\tinstalled")]
    elif has("rpm"):
        names = run("rpm", "-qa", "--qf", "%{NAME}\n").splitlines()
    else:
        raise RuntimeError("No supported package manager")
    return {"installed": sorted(set(names))}


def collect(device_id=None, headless=False):
    hostname = socket.gethostname()
    if device_id is None:
        machine_id = Path("/etc/machine-id").read_text().strip()
        if not machine_id:
            raise RuntimeError("Empty machine-id; provide --device-id")
        device_id = "linux-" + hashlib.sha256(machine_id.encode()).hexdigest()[:24]
    checks = []
    for name, function in [
        ("disk_encryption", disk_encryption),
        ("patch_level", patch_level),
        ("firewall", firewall),
        ("antivirus", antivirus),
        ("local_admins", local_admins),
        ("screen_lock", lambda: screen_lock(headless)),
        ("pending_reboot", pending_reboot),
        ("unauthorised_software", unauthorised_software),
    ]:
        try:
            value, status, detail = function(), "pass", None
        except NotApplicable as exc:
            value, status, detail = None, "not_applicable", str(exc)
        except Exception as exc:
            value, status, detail = None, "error", f"{type(exc).__name__}: {exc}"[:1000]
        checks.append({"id": name, "status": status, "value": value, "detail": detail})
    return {
        "device_id": device_id,
        "hostname": hostname,
        "os": "linux",
        "os_version": platform.release(),
        "agent_version": "1.0.0",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send(report, server, key):
    parts = urlsplit(server)
    loopback = parts.hostname in {"localhost", "127.0.0.1", "::1"}
    if (parts.scheme != "https" and not (parts.scheme == "http" and loopback)) or (
        not parts.hostname or parts.username or parts.password or parts.query or parts.fragment
    ):
        raise ValueError("Collector requires HTTPS (HTTP allowed only for loopback)")
    if not key:
        raise ValueError("Set API_KEY before submitting")
    request = Request(
        server.rstrip("/") + "/reports",
        data=json.dumps(report).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    with build_opener(NoRedirect).open(request, timeout=20) as response:
        return json.loads(response.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-id", default=os.getenv("DEVICE_ID"))
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--output", type=Path, help="Save a private local copy before submission")
    parser.add_argument("--send", action="store_true")
    parser.add_argument("--server", default=os.getenv("COLLECTOR_URL", "http://127.0.0.1:8000"))
    args = parser.parse_args()
    if args.device_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", args.device_id):
        parser.error("Invalid device ID; use 1-128 letters, digits, dots, underscores or hyphens")
    report = collect(args.device_id, args.headless)
    text = json.dumps(report, indent=2)
    if args.output:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(text + "\n")
    print(text)
    if args.send:
        try:
            result = send(report, args.server, os.getenv("API_KEY", ""))
            print(f"Submitted report {result['report_id']}", file=sys.stderr)
        except Exception:
            print(
                "Submission failed. Check connectivity, TLS and credentials; local report retained.",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
