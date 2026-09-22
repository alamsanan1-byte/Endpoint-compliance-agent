"""Exercise the public HTTP contract with 50 synthetic devices and a disposable database."""

import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from collector.api import create_app
from scripts.generate_fake_fleet import make_report


def main():
    with tempfile.TemporaryDirectory() as directory:
        key = "synthetic-smoke-test-key-local-only"
        app = create_app(database_path=Path(directory) / "fleet.db", api_key=key, webhook_url="")
        with TestClient(app, headers={"Authorization": f"Bearer {key}"}) as client:
            for index in range(50):
                response = client.post("/reports", json=make_report(index))
                assert response.status_code == 201, response.text
            result = client.get("/fleet").json()
            assert result["total"] == 50
            assert result["summary"] == {
                "compliant": 20,
                "non_compliant": 10,
                "warning": 10,
                "unknown": 10,
                "stale": 0,
            }
            print(f"50 synthetic devices ingested and evaluated: {result['summary']}")


if __name__ == "__main__":
    main()
