from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from scan_manager import ScanError, ScanManager
from scan_config import MAX_FILE_SIZE, SCAN_TIMEOUT_SECONDS, MAX_CONCURRENT_SCANS, public_config

BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app):
    app.state.scans = ScanManager(
        BASE_DIR / "scan_worker.py", BASE_DIR / "models" / "EMBER2024_PE.model",
        timeout_seconds=SCAN_TIMEOUT_SECONDS, max_concurrent=MAX_CONCURRENT_SCANS,
        max_file_size=MAX_FILE_SIZE,
    )
    try:
        yield
    finally:
        # close() can wait briefly for child processes; do not block the event loop.
        from starlette.concurrency import run_in_threadpool
        await run_in_threadpool(app.state.scans.close)


app = FastAPI(title="eNVy", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/", response_class=FileResponse)
def home():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/health")
def health(request: Request):
    return {"status": "ok", **request.app.state.scans.status(),
            "model_available": (BASE_DIR / "models" / "EMBER2024_PE.model").is_file()}


@app.get("/config")
def config():
    return public_config()


@app.post("/scan")
def scan(request: Request, file: UploadFile):
    try:
        if Path(file.filename or "").suffix.lower() not in {".exe", ".dll"}:
            raise HTTPException(400, ".exe 또는 .dll 파일을 선택해 주세요.")
        if file.size is not None and file.size > MAX_FILE_SIZE:
            raise HTTPException(413, public_config()["max_file_size_label"] + " 이하의 파일을 선택해 주세요.")
        result = request.app.state.scans.scan_file(file.file)
    except ScanError as error:
        headers = {"Retry-After": "1"} if error.status_code == 429 else None
        raise HTTPException(error.status_code, error.detail, headers=headers) from None
    finally:
        file.file.close()
    return {"filename": file.filename, **result}
