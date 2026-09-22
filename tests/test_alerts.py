import copy
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from collector.api import create_app
from tests.conftest import KEY, ROOT


def test_alert_debounce_recovery_and_retry_survive_restart(tmp_path, good):
    sent = []
    db = tmp_path / "alerts.db"
    now = datetime.now(timezone.utc)
    bad = copy.deepcopy(good)
    bad["checks"][0]["value"]["enabled"] = False

    def sender(url, payload):
        sent.append(payload)

    for index in range(2):
        with TestClient(
            create_app(
                db, ROOT / "policy/baseline.yaml", KEY, "https://example.invalid/test", sender
            ),
            headers={"Authorization": f"Bearer {KEY}"},
        ) as client:
            bad["collected_at"] = (now + timedelta(seconds=index)).isoformat()
            response = client.post("/reports", json=bad)
            assert response.json()["alert"] == ("sent" if index == 0 else "debounced")
            assert len(sent) == 1
            if index:
                good["collected_at"] = (now + timedelta(seconds=3)).isoformat()
                assert client.post("/reports", json=good).json()["alert"] == "healthy"
                bad["collected_at"] = (now + timedelta(seconds=4)).isoformat()
                assert client.post("/reports", json=bad).json()["alert"] == "sent"
                assert len(sent) == 2
                assert client.post("/reports", json=bad).json()["alert"] == "duplicate"


def test_failed_webhook_does_not_lose_report_or_suppress_retry(tmp_path, good):
    attempts = []

    def sender(url, payload):
        attempts.append(payload)
        if len(attempts) == 1:
            raise OSError("simulated failure")

    good["checks"][0]["value"]["enabled"] = False
    with TestClient(
        create_app(
            tmp_path / "test.db",
            ROOT / "policy/baseline.yaml",
            KEY,
            "https://example.invalid/test",
            sender,
        ),
        headers={"Authorization": f"Bearer {KEY}"},
    ) as client:
        assert client.post("/reports", json=good).json()["alert"] == "failed"
        good["collected_at"] = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
        assert client.post("/reports", json=good).json()["alert"] == "sent"
        assert len(client.get(f"/devices/{good['device_id']}/history").json()["reports"]) == 2
