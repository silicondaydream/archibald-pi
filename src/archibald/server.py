"""The web UI's backend. Loopback by default — see cli.py for why."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from archibald import __version__
from archibald.extract import MAX_BYTES
from archibald.fetch import FetchError
from archibald.models import Verdict
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

app = FastAPI(title="Archibald", version=__version__, docs_url=None, redoc_url=None,
              openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
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


@app.post("/api/scan/file", response_model=Verdict)
def scan_file_endpoint(file: UploadFile = File(...)) -> Verdict:  # noqa: B008 — FastAPI idiom
    data = file.file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, f"Files over {MAX_BYTES // 1_000_000} MB are not scanned")
    if not data:
        raise HTTPException(400, "The file is empty")
    return scan_bytes(data, file.filename)


@app.get("/api/samples")
def samples() -> list[dict[str, str]]:
    return [{"id": s.id, "title": s.title, "description": s.description,
             "filename": s.filename} for s in SAMPLES]


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
