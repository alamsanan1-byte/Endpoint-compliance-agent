"""Deterministic, centrally configured policy evaluation. No endpoint verdict is trusted."""

import hashlib
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from collector.contract import ROOT

WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def load_policy(path):
    policy = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "schema/policy.schema.json").read_text())
    Draft202012Validator(schema).validate(policy)
    return policy


def policy_hash(policy):
    return hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()


def decide(check_id, value, rule, os_name):
    """Return a verdict and explanation from raw facts, never agent status text."""
    if check_id in {"disk_encryption", "firewall"}:
        ok = not rule["required"] or value["enabled"]
        return ("pass" if ok else "fail", f"Enabled: {value['enabled']}")
    if check_id == "patch_level":
        age = value["days_since_update"]
        limit = rule["max_days_since_update"]
        return ("pass" if age <= limit else "fail", f"Last update {age:g} days ago; limit {limit}")
    if check_id == "antivirus":
        ok = not rule["required"] or (
            value["enabled"] and value["definition_age_days"] <= rule["max_definition_age_days"]
        )
        return ("pass" if ok else "fail", "Antivirus service and signature freshness evaluated")
    if check_id == "local_admins":
        members = {name.casefold() for name in value["members"]}
        allowed = rule.get("allowlist_by_os", {}).get(os_name, rule["allowlist"])
        unexpected = sorted(members - {name.casefold() for name in allowed})
        ok = len(members) <= rule["max_count"] and not unexpected
        return (
            "pass" if ok else "fail",
            f"{len(members)} administrators; unexpected: {unexpected}",
        )
    if check_id == "screen_lock":
        ok = value["enabled"] and 0 < value["timeout_minutes"] <= rule["max_timeout_minutes"]
        return ("pass" if ok else "fail", f"Lock timeout: {value['timeout_minutes']:g} minutes")
    if check_id == "pending_reboot":
        return (
            ("warn", "A reboot is pending") if value["required"] else ("pass", "No pending reboot")
        )
    blocked = {name.casefold() for name in rule["blocklist"]}
    matches = sorted(name for name in value["installed"] if name.casefold() in blocked)
    return ("fail" if matches else "pass", f"Blocked software: {matches}")


def evaluate(report, policy):
    incoming = {check["id"]: check for check in report["checks"]}
    checks = []
    earned = total = 0.0
    for check_id, rule in policy["baseline"].items():
        check = incoming.get(check_id)
        if check is None or check["status"] == "error":
            status, detail = (
                "error",
                "Evidence unavailable: "
                + ((check["detail"] or "collector error") if check else "missing check"),
            )
        elif check["status"] == "not_applicable":
            if report["os"] in rule.get("not_applicable_on", []):
                status, detail = "not_applicable", check["detail"]
            else:
                status, detail = "error", "Policy does not permit this platform exemption"
        else:
            status, detail = decide(check_id, check["value"], rule, report["os"])
        weight = WEIGHTS[rule["severity"]]
        if status != "not_applicable":
            total += weight
            earned += weight if status == "pass" else weight / 2 if status == "warn" else 0
        checks.append(
            {
                "id": check_id,
                "status": status,
                "severity": rule["severity"],
                "detail": detail,
                "value": check["value"] if check else None,
            }
        )
    score = round(100 * earned / total, 2) if total else 0
    has_error = any(c["status"] == "error" for c in checks)
    has_fail = any(c["status"] == "fail" for c in checks)
    critical_fail = any(c["status"] == "fail" and c["severity"] == "critical" for c in checks)
    if critical_fail or (has_fail and score < policy["compliance_threshold"]):
        state = "non_compliant"
    elif has_error or not total:
        state = "unknown"
    elif score < policy["compliance_threshold"]:
        state = "non_compliant"
    elif any(c["status"] in {"fail", "warn"} for c in checks):
        state = "warning"
    else:
        state = "compliant"
    return {
        "score": score,
        "state": state,
        "checks": checks,
        "policy_version": policy["version"],
        "policy_hash": policy_hash(policy),
    }
