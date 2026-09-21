from __future__ import annotations

from fastapi import FastAPI

from .sync import SyncConfig, SyncRunner


config = SyncConfig.from_env()
runner = SyncRunner(config)
app = FastAPI(title="WAF Intelligence Signature Sync", version="1.0.0")


@app.on_event("startup")
def startup() -> None:
    runner.start()


@app.on_event("shutdown")
def shutdown() -> None:
    runner.stop()


@app.get("/healthz")
def healthz() -> dict[str, object]:
    return {"status": "ok", "service": "signature-sync"}


@app.get("/status")
def status() -> dict[str, object]:
    return {
        "service": "signature-sync",
        "source_url": config.source_url,
        "target_release": config.target_release,
        "target_build": config.target_build,
        "interval_seconds": config.interval_seconds,
        "state": runner.state,
    }


@app.post("/run")
def run_now() -> dict[str, object]:
    return runner.run_once()
