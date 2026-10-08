"""A deliberately small service. The pipeline around it is the subject."""

import os

from fastapi import FastAPI

# FastAPI's interactive docs and OpenAPI schema are switched off, so the
# service has the two endpoints below and nothing else.
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Answer liveness and readiness probes."""
    return {"status": "ok"}


@app.get("/version")
def version() -> dict[str, str]:
    """Report the commit this image was built from. The Dockerfile sets it."""
    return {"revision": os.environ.get("APP_REVISION", "unknown")}
