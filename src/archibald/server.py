"""The web UI's backend. Loopback only, enforced here and not just in cli.py.

`archibald serve` refuses a non-loopback bind, but nothing stops someone running
`uvicorn archibald.server:app --host 0.0.0.0` directly. So the app checks every
request itself:

* the peer must be a loopback address, and
* the Host header must name loopback (`127.0.0.1`, `localhost`, `[::1]`).

The second check is not redundant. A web page open in the operator's own browser
can point a name it controls at 127.0.0.1 (DNS rebinding) and then talk to this
server from a loopback peer — but its requests carry its own name as the Host,
and are refused.

`archibald serve --allow-remote` sets ARCHIBALD_ALLOW_REMOTE=1, which lifts both,
for an operator who has put it behind something that authenticates.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from archibald import __version__
from archibald.extract import MAX_BYTES
from archibald.fetch import FetchError
from archibald.models import NotScannedError, Verdict
from archibald.samples import BY_ID, SAMPLES
from archibald.scan import scan_bytes, scan_string, scan_url

WEB = Path(__file__).parent / "web"

# The UI renders attacker-written text. Nothing here may become markup or script:
# no inline script, no inline style attributes in HTML, nothing from elsewhere.
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'"
)

ALLOW_REMOTE_ENV = "ARCHIBALD_ALLOW_REMOTE"
LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})


def _is_loopback_peer(host: str | None) -> bool:
    if host is None:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _host_name(header: str) -> str:
    """The name in a Host header, without its port: `[::1]:8741` → `::1`."""
    header = header.strip().lower()
    if header.startswith("["):
        return header[1 : header.find("]")] if "]" in header else header
    return header.rsplit(":", 1)[0] if header.count(":") == 1 else header


app = FastAPI(
    title="Archibald", version=__version__, docs_url=None, redoc_url=None, openapi_url=None
)


@app.middleware("http")
async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    if os.environ.get(ALLOW_REMOTE_ENV) != "1":
        peer = request.client.host if request.client else None
        host = _host_name(request.headers.get("host", ""))
        if not _is_loopback_peer(peer) or host not in LOOPBACK_NAMES:
            return JSONResponse(
                {"detail": "Archibald only answers on loopback; see archibald serve --help"},
                status_code=403,
                headers={"Content-Security-Policy": CSP, "Cache-Control": "no-store"},
            )
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


class TextRequest(BaseModel):
    text: str = Field(max_length=2_000_000)
    kind: Literal["auto", "text", "html"] = "auto"


class UrlRequest(BaseModel):
    url: str = Field(max_length=2048)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/api/scan/text", response_model=Verdict)
def scan_text_endpoint(body: TextRequest) -> Verdict:
    if not body.text.strip():
        raise HTTPException(400, "Nothing to scan")
    return scan_string(body.text, body.kind)


@app.post("/api/scan/url", response_model=Verdict)
def scan_url_endpoint(body: UrlRequest) -> Verdict:
    try:
        return scan_url(body.url.strip())
    except FetchError as exc:
        raise HTTPException(400, str(exc)) from exc
    except NotScannedError as exc:
        raise HTTPException(415, str(exc)) from exc


@app.post("/api/scan/file", response_model=Verdict)
def scan_file_endpoint(file: UploadFile = File(...)) -> Verdict:  # noqa: B008 — FastAPI idiom
    data = file.file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, f"Files over {MAX_BYTES // 1_000_000} MB are not scanned")
    if not data:
        raise HTTPException(400, "The file is empty")
    try:
        return scan_bytes(data, file.filename)
    except NotScannedError as exc:
        raise HTTPException(415, str(exc)) from exc


@app.get("/api/samples")
def samples() -> list[dict[str, str]]:
    return [
        {"id": s.id, "title": s.title, "description": s.description, "filename": s.filename}
        for s in SAMPLES
    ]


@app.post("/api/scan/sample/{sample_id}", response_model=Verdict)
def scan_sample(sample_id: str) -> Verdict:
    sample = BY_ID.get(sample_id)
    if sample is None:
        raise HTTPException(404, "No such sample")
    return scan_bytes(sample.data(), sample.filename)


@app.exception_handler(HTTPException)
async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


app.mount("/static", StaticFiles(directory=WEB), name="static")
