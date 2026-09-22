import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from collector.api import create_app
from collector.evaluate import load_policy

ROOT = Path(__file__).resolve().parents[1]
KEY = "test-only-key-never-used-in-deployment"


@pytest.fixture
def good():
    report = json.loads((ROOT / "tests/fixtures/windows-good.json").read_text())
    report["collected_at"] = datetime.now(timezone.utc).isoformat()
    return report


@pytest.fixture
def baseline():
    return load_policy(ROOT / "policy/baseline.yaml")


@pytest.fixture
def client(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text((ROOT / "policy/baseline.yaml").read_text())
    app = create_app(tmp_path / "test.db", policy, api_key=KEY, webhook_url="")
    with TestClient(app, headers={"Authorization": f"Bearer {KEY}"}) as client:
        client.policy_file = policy
        yield client
