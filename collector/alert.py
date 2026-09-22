"""Best-effort alerts, persisted debounce, no network request until explicitly configured."""

import hashlib
import json
import logging
import time
from urllib.parse import urlsplit

import httpx

LOG = logging.getLogger(__name__)


def validate_webhook(url):
    if not url:
        return
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise ValueError("WEBHOOK_URL must use HTTPS without embedded credentials")


def send_webhook(url, payload):
    # Redirects are deliberately disabled: a configured destination cannot silently move.
    with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
        client.post(url, json=payload).raise_for_status()


class Alerter:
    def __init__(self, database, url="", sender=send_webhook):
        validate_webhook(url)
        self.db, self.url, self.sender = database, url, sender

    def notify(self, report, evaluation, cooldown_minutes):
        if not self.url:
            return "disabled"
        if evaluation["state"] == "compliant":
            with self.db.connect() as db:
                db.execute("DELETE FROM alerts WHERE device_id=?", (report["device_id"],))
            return "healthy"
        # Use failing control IDs/states, not timestamps or changing numeric evidence.
        signature = [
            (c["id"], c["status"])
            for c in evaluation["checks"]
            if c["status"] not in {"pass", "not_applicable"}
        ]
        fingerprint = hashlib.sha256(json.dumps(signature).encode()).hexdigest()
        payload = {
            "event": "endpoint_compliance",
            "device_id": report["device_id"],
            "state": evaluation["state"],
            "score": evaluation["score"],
            "controls": signature,
            "policy_hash": evaluation["policy_hash"],
        }
        # Serialise send/record to avoid duplicate alerts from concurrent report submissions.
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT * FROM alerts WHERE device_id=?", (report["device_id"],)
            ).fetchone()
            now = time.time()
            if (
                previous
                and previous["fingerprint"] == fingerprint
                and (now - previous["sent_at"] < cooldown_minutes * 60)
            ):
                return "debounced"
            try:
                self.sender(self.url, payload)
            except Exception:
                # Never log a secret webhook URL or block report persistence on delivery failure.
                LOG.warning("Webhook delivery failed; will retry on the next fresh report")
                return "failed"
            db.execute(
                "INSERT OR REPLACE INTO alerts VALUES (?,?,?)",
                (report["device_id"], fingerprint, now),
            )
        return "sent"
