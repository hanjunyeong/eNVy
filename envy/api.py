"""Upload, queue admission, history and result APIs. No PE parser/model loading."""
import asyncio
from contextlib import asynccontextmanager, suppress
import hashlib
import logging
import ntpath
from pathlib import Path
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import httpx
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile

from .config import Settings
from .store import Store, CapacityError
from .cache import RedisCache

TERMINAL = {"succeeded", "failed"}


class UploadLimits:
    """Bound simultaneous multipart parsing and request-body bytes before routing."""
    def __init__(self, app, settings):
        self.app = app
        self.settings = settings
        self.active = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/scan" or scope["method"] != "POST":
            return await self.app(scope, receive, send)
        limit = self.settings.max_file_size + 64 * 1024
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"detail": "올바르지 않은 요청 크기입니다."}, 400)(scope, receive, send)
        if length > limit or length < 0:
            return await JSONResponse({"detail": "허용한 업로드 요청 크기를 초과했습니다."}, 413)(scope, receive, send)
        # All increments occur before an await on this ASGI event loop.
        if self.active >= self.settings.max_concurrent_uploads:
            return await JSONResponse({"detail": "다른 파일을 업로드 중입니다. 잠시 후 다시 시도해 주세요."},
                                      429, headers={"Retry-After": "2"})(scope, receive, send)
        self.active += 1
        received = 0

        async def bounded_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise HTTPException(413, "허용한 업로드 요청 크기를 초과했습니다.")
            return message
        try:
            await self.app(scope, bounded_receive, send)
        finally:
            self.active -= 1


class ScanService:
    def __init__(self, settings, store, cache, publish, model_info):
        self.settings, self.store, self.cache = settings, store, cache
        self.publish, self.model_info = publish, model_info

    def remove_input(self, job_id):
        try:
            self.settings.input_path(job_id).unlink(missing_ok=True)
            self.store.mark_cleaned(job_id)
        except OSError:
            logging.exception("Could not remove an analysis input; maintenance will retry")

    def payload(self, job):
        body = dict(job)
        body["job_id"] = body["id"]
        if body.get("result"):
            body["result"] = {"filename": body["filename"], **body["result"]}
        body["cached"] = body.get("result_source") == "cache"
        return body

    def submit(self, upload):
        filename = ntpath.basename(upload.filename or "")
        filename = "".join(c for c in filename if c.isprintable())[:200]
        if Path(filename).suffix.lower() not in {".exe", ".dll"}:
            raise HTTPException(400, ".exe 또는 .dll 파일을 선택해 주세요.")
        if upload.size is not None and upload.size > self.settings.max_file_size:
            raise HTTPException(413, "300 MiB 이하의 파일을 선택해 주세요.")
        job_id = uuid.uuid4().hex
        try:
            self.store.create_job(job_id, filename, self.model_info["model_version"])
        except CapacityError:
            raise HTTPException(429, "분석 대기열이 가득 찼습니다. 잠시 후 다시 시도해 주세요.",
                                headers={"Retry-After": "5"}) from None
        try:
            digest = hashlib.sha256()
            size = 0
            with self.settings.input_path(job_id).open("xb") as target:
                while True:
                    block = upload.file.read(self.settings.chunk_size)
                    if not block:
                        break
                    size += len(block)
                    if size > self.settings.max_file_size:
                        raise HTTPException(413, "300 MiB 이하의 파일을 선택해 주세요.")
                    digest.update(block)
                    target.write(block)
            if not size:
                raise HTTPException(400, "빈 파일입니다.")
            sha = digest.hexdigest()
            self.store.set_uploaded(job_id, sha, size)
            cached = self.cache.get(sha, self.model_info["model_version"])
            if cached is not None:
                self.store.mark_cache_hit(job_id, cached)
                self.remove_input(job_id)
                return JSONResponse(self.payload(self.store.get_job(job_id)), 200)
            self.publish(job_id)
            submitted = self.store.get_job(job_id)
            if submitted["status"] in TERMINAL:
                self.remove_input(job_id)
            return JSONResponse(self.payload(submitted), 202)
        except HTTPException as error:
            self.store.finish(job_id, None, error=error.detail)
            self.remove_input(job_id)
            raise
        except Exception:
            logging.exception("Could not prepare or enqueue analysis")
            self.store.finish(job_id, None, error="작업 준비 또는 대기열 등록에 실패했습니다.")
            self.remove_input(job_id)
            raise HTTPException(503, "작업을 등록하지 못했습니다. 서버 상태를 확인한 뒤 다시 시도해 주세요.") from None

    def maintenance(self):
        for job in self.store.maintenance():
            self.remove_input(job["id"])


def create_app(settings=None, store=None, cache=None, publish=None, model_info=None, maintenance=True):
    settings = settings or Settings()
    supplied_model = model_info

    @asynccontextmanager
    async def lifespan(app):
        settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        app.state.store = store or Store(settings)
        app.state.cache = cache or RedisCache(settings)
        await run_in_threadpool(app.state.store.init)
        info = supplied_model
        if info is None:
            async with httpx.AsyncClient(timeout=20.0, trust_env=False) as client:
                response = await client.get(settings.inference_url + "/health")
                response.raise_for_status()
                info = response.json()
        if info.get("status") != "ready" or not isinstance(info.get("model_version"), str):
            raise RuntimeError("Inference service is not ready")
        if (info.get("pipeline_version") != settings.pipeline_version
                or info.get("threshold") != settings.threshold
                or info.get("pipeline_fingerprint") != settings.pipeline_fingerprint()
                or info.get("model_version") != settings.model_version(info.get("model_sha256"))):
            raise RuntimeError("API and inference analysis versions do not match")

        def enqueue(job_id):
            from .tasks import scan_job
            return scan_job.apply_async(args=[job_id], task_id=job_id, expires=settings.queue_ttl, retry=False)

        app.state.service = ScanService(settings, app.state.store, app.state.cache, publish or enqueue, info)

        async def cleanup_loop():
            while True:
                await asyncio.sleep(30)
                try:
                    await run_in_threadpool(app.state.service.maintenance)
                except Exception:
                    logging.exception("Job maintenance failed; retrying later")
        cleanup = asyncio.create_task(cleanup_loop()) if maintenance else None
        try:
            yield
        finally:
            if cleanup:
                cleanup.cancel()
                with suppress(asyncio.CancelledError):
                    await cleanup
            app.state.store.close()

    app = FastAPI(title="eNVy", lifespan=lifespan)
    app.add_middleware(UploadLimits, settings=settings)
    root = Path(__file__).resolve().parents[1]
    app.mount("/static", StaticFiles(directory=str(root / "static")), name="static")

    @app.get("/", response_class=FileResponse)
    def home():
        return FileResponse(root / "static" / "index.html")

    @app.get("/config")
    def config():
        return settings.public()

    @app.get("/health")
    def health(request: Request):
        return {"status": "ok", "reserved_workspaces": request.app.state.store.capacity(),
                "max_pending_jobs": settings.max_pending_jobs,
                "model_version": request.app.state.service.model_info["model_version"]}

    @app.post("/scan")
    async def scan(request: Request):
        async with request.form(max_files=1, max_fields=0) as form:
            upload = form.get("file")
            if len(form) != 1 or not isinstance(upload, UploadFile):
                raise HTTPException(400, "file 필드에 검사할 파일 하나를 업로드해 주세요.")
            return await run_in_threadpool(request.app.state.service.submit, upload)

    @app.get("/jobs/{job_id}")
    def job(job_id: str, request: Request):
        if len(job_id) != 32 or any(c not in "0123456789abcdef" for c in job_id):
            raise HTTPException(404, "작업을 찾을 수 없습니다.")
        found = request.app.state.store.get_job(job_id)
        if found is None:
            raise HTTPException(404, "작업을 찾을 수 없습니다.")
        if found["status"] in TERMINAL:
            request.app.state.service.remove_input(job_id)
        return request.app.state.service.payload(found)

    @app.get("/history")
    def history(request: Request):
        jobs = request.app.state.store.recent(limit=20)
        return {"items": jobs}

    return app


app = create_app()
