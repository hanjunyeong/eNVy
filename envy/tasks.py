"""Celery tasks and parent-side failure hooks for bounded PE analysis.

The model lives only in the inference service. Celery prefork children retain
their Python libraries/clients across jobs, but do not load a Booster.
"""
import logging
import os
from datetime import datetime, timezone

from billiard.exceptions import SoftTimeLimitExceeded
from billiard.einfo import ExceptionWithTraceback
from celery import Celery, Task
from celery.exceptions import Retry, Ignore, Reject
from celery.signals import worker_process_init, worker_process_shutdown
from celery.worker.request import Request

from .config import Settings
from .engine import AnalysisError, InferenceClient, analyze_job

settings = Settings()
celery_app = Celery("envy", broker=settings.broker_url)
celery_app.conf.update(
    task_serializer="json", accept_content=["json"], result_serializer="json",
    task_ignore_result=True, task_acks_late=True, task_acks_on_failure_or_timeout=True,
    task_reject_on_worker_lost=False, worker_prefetch_multiplier=1,
    task_soft_time_limit=settings.soft_timeout, task_time_limit=settings.hard_timeout,
    worker_max_memory_per_child=1536000,  # KiB; recycle after a task, not a hard peak limit.
    broker_transport_options={"visibility_timeout": settings.queue_ttl + settings.hard_timeout + 600},
    broker_connection_retry_on_startup=True, task_track_started=False,
    worker_enable_remote_control=False,
)

_services = None


def services():
    global _services
    pid = os.getpid()
    if _services is None or _services[0] != pid:
        from .store import Store
        from .cache import RedisCache
        current = Settings()
        _services = (pid, current, Store(current), RedisCache(current), InferenceClient(current))
    return _services[1:]


@worker_process_init.connect
def _reset_after_fork(**kwargs):
    # No model or network connection is initialized in the parent process.
    global _services
    _services = None


@worker_process_shutdown.connect
def _close_services(**kwargs):
    global _services
    if _services is not None and _services[0] == os.getpid():
        for service in _services[2:]:
            close = getattr(service, "close", None)
            if close:
                try:
                    close()
                except Exception:
                    pass
    _services = None


def _release_lock(cache, job, owner):
    if not job or not job.get("sha256"):
        return
    try:
        cache.release(job["sha256"], job["model_version"], owner)
    except Exception:
        logging.exception("Could not release a completed analysis lock")


def fail_in_parent(job_id, message):
    """Called by the Celery parent even if a task child was killed mid-analysis."""
    from .store import Store
    from .cache import RedisCache
    current = Settings()
    store = Store(current)
    cache = RedisCache(current)
    try:
        job = store.get_job(job_id)
        if job:
            store.finish(job_id, None, error=message)
            _release_lock(cache, job, job_id)
    except Exception:
        # API maintenance marks stale jobs failed if DB/network recovery is needed.
        logging.exception("Could not finalize failed Celery job in parent")
    finally:
        store.close()
        close = getattr(cache, "close", None)
        if close:
            close()


class ManagedRequest(Request):
    def _job_id(self):
        if self.args and isinstance(self.args[0], str):
            return self.args[0]
        return (self.kwargs or {}).get("job_id")

    def on_timeout(self, soft, timeout):
        super().on_timeout(soft, timeout)
        if not soft and self._job_id():
            fail_in_parent(self._job_id(), "분석 제한 시간을 초과해 작업 프로세스가 종료됐습니다.")

    def on_failure(self, exc_info, send_failed_event=True, return_ok=False):
        try:
            return super().on_failure(exc_info, send_failed_event=send_failed_event, return_ok=return_ok)
        finally:
            error = getattr(exc_info, "exception", None)
            if isinstance(error, ExceptionWithTraceback):
                error = error.exc
            if self._job_id() and not isinstance(error, (Retry, Ignore, Reject)):
                fail_in_parent(self._job_id(), "작업 프로세스 오류로 분석이 종료됐습니다.")


class ManagedTask(Task):
    Request = "envy.tasks:ManagedRequest"


@celery_app.task(bind=True, base=ManagedTask, name="envy.scan", max_retries=200)
def scan_job(self, job_id):
    current, store, cache, inference = services()
    job = store.get_job(job_id)
    if not job or job["status"] not in {"queued", "running"}:
        return
    # A duplicate delivery must not run a second copy of an active job.
    if job["status"] == "running":
        return
    created = datetime.fromisoformat(job["created_at"])
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    if (datetime.now(timezone.utc) - created).total_seconds() > current.queue_ttl:
        store.finish(job_id, None, error="대기 시간이 초과됐습니다. 파일을 다시 제출해 주세요.")
        return
    cached = cache.get(job["sha256"], job["model_version"])
    if cached is not None:
        store.mark_cache_hit(job_id, cached)
        return
    owner = job_id
    acquired = False
    try:
        acquired = cache.acquire(job["sha256"], job["model_version"], owner,
                                 current.hard_timeout + 60)
    except Exception:
        # Cache outages must not fabricate a hit or block every analysis forever.
        logging.warning("Hash lock unavailable; continuing without cache deduplication")
        acquired = None
    if acquired is False:
        if self.request.retries >= self.max_retries:
            store.finish(job_id, None, error="같은 파일의 분석 대기가 길어져 중단했습니다. 다시 시도해 주세요.")
            return
        raise self.retry(countdown=2)
    try:
        running = store.start_job(job_id)
        if running is None:
            return
        result = analyze_job(running, current, inference,
                             report_stage=lambda stage: store.set_stage(job_id, stage))
        store.finish(job_id, result)
        cache.put(job["sha256"], job["model_version"], result)
    except SoftTimeLimitExceeded:
        last = store.get_job(job_id)
        stage = last.get("stage", "unknown") if last else "unknown"
        store.finish(job_id, None, error=f"분석 제한 시간을 초과했습니다. 마지막 단계: {stage}")
    except AnalysisError as error:
        store.finish(job_id, None, error=str(error))
    except Exception:
        logging.exception("File analysis failed")
        store.finish(job_id, None, error="파일 분석 중 오류가 발생했습니다. 서버 기록을 확인해 주세요.")
    finally:
        if acquired:
            _release_lock(cache, job, owner)
