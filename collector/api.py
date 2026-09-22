"""Authenticated report ingestion, fleet views and policy-aware history."""

import hashlib
import json
import math
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from jsonschema import ValidationError
from starlette.concurrency import run_in_threadpool

from collector.alert import Alerter
from collector.contract import ROOT, validate_report
from collector.db import Database
from collector.evaluate import evaluate, load_policy

MAX_BODY_BYTES = 512 * 1024


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite numeric value")
    return number


def utcnow():
    return datetime.now(timezone.utc)


def parse_time(value):
    return datetime.fromisoformat(value.upper().replace("Z", "+00:00")).astimezone(timezone.utc)


def create_app(database_path=None, policy_path=None, api_key=None, webhook_url=None, sender=None):
    policy_file = Path(policy_path or os.getenv("POLICY_PATH", ROOT / "policy/baseline.yaml"))

    @asynccontextmanager
    async def lifespan(app):
        key = api_key if api_key is not None else os.getenv("API_KEY", "")
        if len(key) < 24:
            raise RuntimeError("Set API_KEY to a random secret of at least 24 characters")
        app.state.api_key = key
        load_policy(policy_file)  # Fail startup clearly on invalid configuration.
        app.state.db = Database(database_path or os.getenv("DATABASE_PATH", "data/compliance.db"))
        url = webhook_url if webhook_url is not None else os.getenv("WEBHOOK_URL", "")
        app.state.alerter = Alerter(app.state.db, url, **({"sender": sender} if sender else {}))
        yield

    app = FastAPI(
        title="Endpoint Compliance Agent",
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def authenticate(request: Request):
        supplied = request.headers.get("authorization", "")
        if not secrets.compare_digest(supplied.encode(), f"Bearer {app.state.api_key}".encode()):
            raise HTTPException(
                401, "A valid Bearer API key is required", headers={"WWW-Authenticate": "Bearer"}
            )

    def policy():
        try:
            return load_policy(policy_file)
        except (OSError, ValueError, ValidationError, yaml.YAMLError):
            raise HTTPException(503, "Policy configuration is invalid or unavailable") from None

    @app.middleware("http")
    async def response_headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return response

    @app.get("/health")
    def health():
        return {"status": "ok", "version": "1.0.0"}

    # Only the empty dashboard shell/assets are public. All endpoint data is authenticated.
    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(ROOT / "collector/static/index.html")

    @app.get("/assets/{name}", include_in_schema=False)
    def asset(name: str):
        if name not in {"dashboard.js", "style.css"}:
            raise HTTPException(404)
        return FileResponse(ROOT / "collector/static" / name)

    def ingest(report):
        current_policy = policy()
        try:
            validate_report(report)
            collected = parse_time(report["collected_at"])
            age = (utcnow() - collected).total_seconds()
            limits = current_policy["reporting"]
            if age > limits["max_age_hours"] * 3600:
                raise ValueError("Report is too old; collect fresh evidence")
            if age < -limits["future_tolerance_seconds"]:
                raise ValueError("Report timestamp is too far in the future")
        except (ValidationError, ValueError) as exc:
            detail = exc.message if isinstance(exc, ValidationError) else str(exc)
            raise HTTPException(422, detail[:500]) from None
        # Canonical timestamps ensure chronological SQL ordering across timezones.
        report["collected_at"] = collected.isoformat()
        fingerprint = hashlib.sha256(
            json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        evaluation = evaluate(report, current_policy)
        report_id, inserted, latest = app.state.db.save(
            fingerprint, report, evaluation, utcnow().isoformat()
        )
        alert = "duplicate" if not inserted else "historical"
        if inserted and latest:
            alert = app.state.alerter.notify(
                report, evaluation, current_policy["alerts"]["cooldown_minutes"]
            )
        return JSONResponse(
            status_code=201 if inserted else 200,
            content={
                "report_id": report_id,
                "duplicate": not inserted,
                "is_latest": latest,
                "evaluation": evaluation,
                "alert": alert,
            },
        )

    @app.post("/reports", dependencies=[Depends(authenticate)])
    async def reports(request: Request):
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_BODY_BYTES:
                raise HTTPException(413, "Report exceeds 512 KiB")
        try:
            report = json.loads(
                body,
                parse_float=finite_float,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"Invalid JSON constant: {value}")
                ),
            )
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(400, "Malformed JSON") from None
        return await run_in_threadpool(ingest, report)

    @app.get("/fleet", dependencies=[Depends(authenticate)])
    def fleet():
        current_policy = policy()
        devices = []
        for stored in app.state.db.latest():
            report = stored["report"]
            # Existing evidence is re-evaluated on every view so policy edits take effect at once.
            result = evaluate(report, current_policy)
            age = (utcnow() - parse_time(report["collected_at"])).total_seconds() / 3600
            devices.append(
                {
                    "device_id": report["device_id"],
                    "hostname": report["hostname"],
                    "os": report["os"],
                    "os_version": report["os_version"],
                    "collected_at": report["collected_at"],
                    "report_id": stored["report_id"],
                    **result,
                    "stale": age > current_policy["reporting"]["stale_after_hours"],
                    "previous_score": stored["evaluation"]["score"],
                    "policy_changed": stored["evaluation"]["policy_hash"] != result["policy_hash"],
                }
            )
        counts = {
            state: 0 for state in ["compliant", "non_compliant", "warning", "unknown", "stale"]
        }
        for device in devices:
            counts["stale" if device["stale"] else device["state"]] += 1
        return {
            "devices": devices,
            "summary": counts,
            "total": len(devices),
            "generated_at": utcnow().isoformat(),
        }

    @app.get("/devices/{device_id}/history", dependencies=[Depends(authenticate)])
    def history(device_id: str, limit: int = Query(50, ge=1, le=200)):
        rows = app.state.db.history(device_id, limit)
        if not rows:
            raise HTTPException(404, "Device not found")
        return {"device_id": device_id, "reports": rows}

    @app.get("/policy", dependencies=[Depends(authenticate)])
    def get_policy():
        return policy()

    return app


app = create_app()
