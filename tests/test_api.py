import copy
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from fastapi.testclient import TestClient

from collector.api import create_app
from tests.conftest import KEY, ROOT


def test_ingest_persists_history_and_duplicate_is_idempotent(client, good):
    first = client.post("/reports", json=good)
    assert first.status_code == 201
    duplicate = client.post("/reports", json=good)
    assert duplicate.status_code == 200
    assert duplicate.json()["report_id"] == first.json()["report_id"]
    assert duplicate.json()["duplicate"] is True
    fleet = client.get("/fleet").json()
    assert fleet["total"] == 1
    assert fleet["summary"]["compliant"] == 1
    history = client.get(f"/devices/{good['device_id']}/history").json()["reports"]
    assert len(history) == 1
    assert history[0]["evaluation"]["policy_hash"]


def test_sensitive_routes_require_authentication(client, good):
    for url in ["/fleet", "/policy", f"/devices/{good['device_id']}/history"]:
        assert client.get(url, headers={"Authorization": ""}).status_code == 401
    assert (
        client.post("/reports", json=good, headers={"Authorization": "Bearer wrong"}).status_code
        == 401
    )
    assert client.get("/health", headers={"Authorization": ""}).status_code == 200


def test_short_key_refuses_to_start(tmp_path):
    with pytest.raises(RuntimeError, match="API_KEY"):
        with TestClient(create_app(tmp_path / "test.db", api_key="unsafe")):
            pass


@pytest.mark.parametrize("hours", [25, -1])
def test_stale_and_future_reports_are_rejected(client, good, hours):
    good["collected_at"] = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    assert client.post("/reports", json=good).status_code == 422
    assert client.get("/fleet").json()["total"] == 0


def test_out_of_order_reports_preserve_latest_and_keep_history(client, good):
    assert client.post("/reports", json=good).status_code == 201
    earlier = copy.deepcopy(good)
    earlier["collected_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    earlier["checks"][0]["value"]["enabled"] = False
    response = client.post("/reports", json=earlier)
    assert response.json()["is_latest"] is False
    assert client.get("/fleet").json()["devices"][0]["score"] == 100
    assert len(client.get(f"/devices/{good['device_id']}/history").json()["reports"]) == 2


def test_timezone_normalization_orders_by_actual_time(client, good):
    good["collected_at"] = datetime.now(timezone.utc).isoformat()
    assert client.post("/reports", json=good).status_code == 201
    other = copy.deepcopy(good)
    zone = timezone(timedelta(hours=10))
    other["collected_at"] = (datetime.now(zone) - timedelta(hours=1)).isoformat()
    other["checks"][0]["value"]["enabled"] = False
    assert client.post("/reports", json=other).json()["is_latest"] is False


def test_policy_changes_refresh_fleet_but_preserve_original_history(client, good):
    client.post("/reports", json=good)
    policy = yaml.safe_load(client.policy_file.read_text())
    policy["baseline"]["patch_level"]["max_days_since_update"] = 1
    client.policy_file.write_text(yaml.safe_dump(policy))
    device = client.get("/fleet").json()["devices"][0]
    assert device["state"] == "non_compliant"
    assert device["policy_changed"] is True
    assert device["previous_score"] == 100
    stored = client.get(f"/devices/{good['device_id']}/history").json()["reports"][0]
    assert stored["evaluation"]["score"] == 100


def test_device_becomes_stale_in_fleet(client, good):
    policy = yaml.safe_load(client.policy_file.read_text())
    policy["reporting"]["stale_after_hours"] = 0.1
    client.policy_file.write_text(yaml.safe_dump(policy))
    good["collected_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    assert client.post("/reports", json=good).status_code == 201
    fleet = client.get("/fleet").json()
    assert fleet["summary"]["stale"] == 1
    assert fleet["summary"]["compliant"] == 0


def test_invalid_json_and_oversized_reports(client):
    assert client.post("/reports", content="{broken").status_code == 400
    assert client.post("/reports", content='{"value": NaN}').status_code == 400
    assert client.post("/reports", content="x" * (512 * 1024 + 1)).status_code == 413


def test_invalid_schema_is_not_persisted(client, good):
    good["checks"][0]["value"] = {"enabled": "yes"}
    assert client.post("/reports", json=good).status_code == 422
    assert client.get("/fleet").json()["total"] == 0


def test_invalid_policy_does_not_make_devices_look_compliant(client):
    client.policy_file.write_text("version: [broken")
    assert client.get("/fleet").status_code == 503


def test_persistence_across_collector_restart(tmp_path, good):
    path = tmp_path / "persist.db"
    for index in range(2):
        with TestClient(
            create_app(path, ROOT / "policy/baseline.yaml", KEY, ""),
            headers={"Authorization": f"Bearer {KEY}"},
        ) as client:
            if not index:
                client.post("/reports", json=good)
            assert client.get("/fleet").json()["total"] == 1


def test_dashboard_assets_and_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert client.get("/assets/dashboard.js").status_code == 200
    assert client.get("/assets/secrets.env").status_code == 404
    assert client.get("/devices/missing/history").status_code == 404
    assert client.get("/devices/missing/history?limit=201").status_code == 422
