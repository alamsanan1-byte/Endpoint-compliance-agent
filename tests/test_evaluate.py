import copy
import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

from collector.contract import validate_report
from collector.evaluate import evaluate, load_policy


@pytest.mark.parametrize(
    "path", sorted(Path("tests/fixtures").glob("*.json")), ids=lambda p: p.stem
)
def test_fixtures_satisfy_shared_contract(path):
    validate_report(json.loads(path.read_text()))


def test_good_and_bad_have_explainable_scores(good, baseline):
    assert evaluate(good, baseline)["score"] == 100
    bad = json.loads(Path("tests/fixtures/windows-bad.json").read_text())
    result = evaluate(bad, baseline)
    assert result["score"] == 33.33
    assert result["state"] == "non_compliant"
    assert {c["id"] for c in result["checks"] if c["status"] == "fail"} == {
        "disk_encryption",
        "patch_level",
        "firewall",
        "local_admins",
        "unauthorised_software",
    }


def test_endpoint_pass_verdict_cannot_override_facts(good, baseline):
    good["checks"][0]["value"]["enabled"] = False
    baseline["compliance_threshold"] = 0
    result = evaluate(good, baseline)
    assert result["checks"][0]["status"] == "fail"
    assert result["state"] == "non_compliant"  # Critical failure overrides aggregate threshold.


def test_error_is_unknown_and_does_not_earn_pass_points(good, baseline):
    good["checks"][0].update(status="error", value=None, detail="Permission denied")
    result = evaluate(good, baseline)
    assert result["state"] == "unknown"
    assert result["score"] == 83.33
    assert result["checks"][0]["status"] == "error"


def test_missing_check_cannot_create_false_compliance(good, baseline):
    good["checks"] = good["checks"][1:]
    assert evaluate(good, baseline)["state"] == "unknown"


def test_exemption_needs_central_policy_approval(good, baseline):
    good["checks"][5].update(status="not_applicable", value=None, detail="Headless server")
    assert evaluate(good, baseline)["state"] == "unknown"
    good["os"] = "linux"
    good["checks"][4]["value"]["members"] = ["root", "itadmin"]
    assert evaluate(good, baseline)["score"] == 100


def test_policy_change_alters_result_without_changing_agent(good, baseline):
    original = copy.deepcopy(good)
    assert evaluate(good, baseline)["state"] == "compliant"
    baseline["baseline"]["patch_level"]["max_days_since_update"] = 2
    assert evaluate(good, baseline)["state"] == "non_compliant"
    assert original == good


def test_warning_has_half_credit(good, baseline):
    good["checks"][6]["value"]["required"] = True
    result = evaluate(good, baseline)
    assert (result["score"], result["state"]) == (95.83, "warning")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r["checks"][0].update(value={"enabled": "true"}),
        lambda r: r["checks"][1].update(value={"days_since_update": -1}),
        lambda r: r.update(collected_at="yesterday"),
        lambda r: r.update(collected_at="2026-09-22T10:00:00"),
        lambda r: r["checks"][0].update(id="invented_control"),
        lambda r: r["checks"][0].update(status="not_applicable", value=None, detail=None),
    ],
)
def test_invalid_report_facts_rejected(good, mutation):
    mutation(good)
    with pytest.raises(ValidationError):
        validate_report(good)


def test_duplicate_control_ids_rejected(good):
    good["checks"][1] = good["checks"][0]
    with pytest.raises(ValueError, match="only once"):
        validate_report(good)


def test_unknown_policy_controls_fail_validation(tmp_path, baseline):
    import yaml

    baseline["baseline"]["typo_control"] = {"severity": "high"}
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(baseline))
    with pytest.raises(ValidationError):
        load_policy(path)
