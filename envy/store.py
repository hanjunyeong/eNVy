"""Persistent jobs and bounded workspace admission, using PostgreSQL in deployment.

The database stores metadata/results only. Raw samples stay in an API-owned
upload volume and are cleaned separately after a job reaches a terminal state.
"""
from datetime import datetime, timedelta, timezone
import json
import math
import re

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer, JSON, MetaData, String, Table,
    create_engine, delete, event, insert, select, update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

TERMINAL = {"succeeded", "failed"}
JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class CapacityError(Exception):
    """The persistent sample workspace capacity is already reserved."""


def utcnow():
    return datetime.now(timezone.utc)


def _iso(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


class Store:
    def __init__(self, settings):
        self.settings = settings
        arguments = {"pool_pre_ping": True}
        if settings.database_url.startswith("sqlite"):
            arguments["connect_args"] = {"check_same_thread": False, "timeout": 30}
            if settings.database_url.endswith(":memory:"):
                arguments["poolclass"] = StaticPool
        self.engine = create_engine(settings.database_url, **arguments)
        if settings.database_url.startswith("sqlite"):
            @event.listens_for(self.engine, "connect")
            def sqlite_pragmas(connection, _record):
                cursor = connection.cursor()
                cursor.execute("PRAGMA busy_timeout=30000")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.close()
        self.metadata = MetaData()
        self.jobs = Table(
            "jobs", self.metadata,
            Column("id", String(32), primary_key=True),
            Column("filename", String(255), nullable=False),
            Column("sha256", String(64), index=True),
            Column("size_bytes", Integer),
            Column("model_version", String(512), nullable=False),
            Column("status", String(16), nullable=False, index=True),
            Column("stage", String(64), nullable=False),
            Column("result", JSON),
            Column("score", Float),
            Column("verdict", String(32)),
            Column("error", String(1000)),
            Column("result_source", String(32), nullable=False),
            Column("slot_reserved", Boolean, nullable=False, default=True),
            Column("input_cleaned", Boolean, nullable=False, default=False),
            Column("created_at", DateTime(timezone=True), nullable=False, index=True),
            Column("updated_at", DateTime(timezone=True), nullable=False),
            Column("started_at", DateTime(timezone=True)),
            Column("finished_at", DateTime(timezone=True)),
        )
        self.gate = Table(
            "queue_capacity", self.metadata,
            Column("id", Integer, primary_key=True),
            Column("used", Integer, nullable=False),
        )

    def init(self):
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            # A savepoint leaves a PostgreSQL transaction usable when another
            # application instance has already initialized this singleton row.
            try:
                with connection.begin_nested():
                    connection.execute(insert(self.gate).values(id=1, used=0))
            except IntegrityError:
                pass

    @staticmethod
    def _dict(row):
        if row is None:
            return None
        result = dict(row._mapping)
        for key in ("created_at", "updated_at", "started_at", "finished_at"):
            if key in result:
                result[key] = _iso(result[key])
        result.pop("slot_reserved", None)
        return result

    @staticmethod
    def _job_id(job_id):
        if not isinstance(job_id, str) or JOB_ID.fullmatch(job_id) is None:
            raise ValueError("Invalid job ID")

    def create_job(self, job_id, filename, model_version):
        self._job_id(job_id)
        if not isinstance(model_version, str) or not 1 <= len(model_version) <= 512:
            raise ValueError("Invalid model version")
        name = str(filename or "unnamed").replace("\x00", "\ufffd")[:255]
        now = utcnow()
        with self.engine.begin() as connection:
            reserved = connection.execute(
                update(self.gate).where(
                    self.gate.c.id == 1,
                    self.gate.c.used < self.settings.max_pending_jobs,
                ).values(used=self.gate.c.used + 1).returning(self.gate.c.used)
            ).first()
            if reserved is None:
                raise CapacityError("작업 대기 한도에 도달했습니다. 잠시 후 다시 시도해 주세요.")
            connection.execute(insert(self.jobs).values(
                id=job_id, filename=name, model_version=model_version,
                status="uploading", stage="uploading", result_source="analysis",
                slot_reserved=True, input_cleaned=False,
                created_at=now, updated_at=now,
            ))
            return self._dict(connection.execute(select(self.jobs).where(self.jobs.c.id == job_id)).first())

    def get_job(self, job_id):
        if not isinstance(job_id, str) or JOB_ID.fullmatch(job_id) is None:
            return None
        with self.engine.connect() as connection:
            return self._dict(connection.execute(select(self.jobs).where(self.jobs.c.id == job_id)).first())

    def recent(self, limit=20):
        limit = max(1, min(100, int(limit)))
        columns = [column for column in self.jobs.c if column.name != "result"]
        with self.engine.connect() as connection:
            rows = connection.execute(select(*columns).order_by(self.jobs.c.created_at.desc()).limit(limit))
            return [self._dict(row) for row in rows]

    def set_uploaded(self, job_id, sha256, size_bytes):
        self._job_id(job_id)
        if not isinstance(sha256, str) or SHA256.fullmatch(sha256) is None:
            raise ValueError("Invalid SHA-256")
        if not isinstance(size_bytes, int) or not 0 < size_bytes <= self.settings.max_file_size:
            raise ValueError("Invalid file size")
        with self.engine.begin() as connection:
            row = connection.execute(update(self.jobs).where(
                self.jobs.c.id == job_id, self.jobs.c.status == "uploading",
            ).values(sha256=sha256, size_bytes=size_bytes, status="queued", stage="queued",
                     updated_at=utcnow()).returning(self.jobs)).first()
            return self._dict(row)

    def start_job(self, job_id):
        self._job_id(job_id)
        now = utcnow()
        with self.engine.begin() as connection:
            row = connection.execute(update(self.jobs).where(
                self.jobs.c.id == job_id, self.jobs.c.status == "queued",
            ).values(status="running", stage="starting", started_at=now,
                     updated_at=now).returning(self.jobs)).first()
            return self._dict(row)

    def set_stage(self, job_id, stage):
        self._job_id(job_id)
        with self.engine.begin() as connection:
            row = connection.execute(update(self.jobs).where(
                self.jobs.c.id == job_id, self.jobs.c.status == "running",
            ).values(stage=str(stage).replace("\x00", "\ufffd")[:64],
                     updated_at=utcnow()).returning(self.jobs)).first()
            return self._dict(row)

    def finish(self, job_id, result=None, error=None, result_source="analysis"):
        self._job_id(job_id)
        if result is not None:
            if not isinstance(result, dict):
                raise ValueError("A result must be an object")
            result = json.loads(json.dumps(result, allow_nan=False))
        if error is None and result is None:
            error = "분석 결과가 없습니다."
        if error is not None:
            error = str(error).replace("\x00", "\ufffd")[:1000]
            result = None
        score = result.get("score") if result is not None else None
        if isinstance(score, bool) or not isinstance(score, (float, int)) or not math.isfinite(score) or not 0 <= score <= 1:
            score = None
        verdict = result.get("verdict") if result is not None else None
        verdict = verdict[:32] if isinstance(verdict, str) else None
        now = utcnow()
        with self.engine.begin() as connection:
            # Conditional UPDATE is an atomic compare-and-set in PostgreSQL
            # and SQLite, including concurrent calls from failure handlers.
            row = connection.execute(update(self.jobs).where(
                self.jobs.c.id == job_id, self.jobs.c.slot_reserved.is_(True),
                self.jobs.c.status.not_in(TERMINAL),
            ).values(status="failed" if error is not None else "succeeded",
                     result=result, error=error, result_source=str(result_source)[:32],
                     score=score, verdict=verdict,
                     updated_at=now, finished_at=now,
                     **({"stage": "completed"} if error is None else {})).returning(self.jobs)).first()
            # A completed task may still have a 300 MiB sample on disk.
            # Capacity is released only after the API confirms raw-file cleanup.
            if row is None:
                row = connection.execute(select(self.jobs).where(self.jobs.c.id == job_id)).first()
            return self._dict(row)

    def mark_cache_hit(self, job_id, result):
        return self.finish(job_id, result=result, result_source="cache")

    def capacity(self):
        with self.engine.connect() as connection:
            value = connection.execute(select(self.gate.c.used).where(self.gate.c.id == 1)).scalar_one_or_none()
            return int(value or 0)

    def cleanable_jobs(self, limit=1000):
        with self.engine.connect() as connection:
            rows = connection.execute(select(self.jobs.c.id, self.jobs.c.status).where(
                self.jobs.c.status.in_(TERMINAL), self.jobs.c.input_cleaned.is_(False),
            ).order_by(self.jobs.c.created_at).limit(max(1, min(1000, int(limit)))))
            return [self._dict(row) for row in rows]

    def mark_cleaned(self, job_id):
        self._job_id(job_id)
        with self.engine.begin() as connection:
            released_job = connection.execute(update(self.jobs).where(
                self.jobs.c.id == job_id, self.jobs.c.status.in_(TERMINAL),
                self.jobs.c.slot_reserved.is_(True), self.jobs.c.input_cleaned.is_(False),
            ).values(input_cleaned=True, slot_reserved=False).returning(self.jobs.c.id)).first()
            if released_job is not None:
                released = connection.execute(update(self.gate).where(
                    self.gate.c.id == 1, self.gate.c.used > 0,
                ).values(used=self.gate.c.used - 1))
                if released.rowcount != 1:
                    raise RuntimeError("Sample workspace capacity invariant failed")
            else:
                # Permit cleanup bookkeeping for a record whose reservation was
                # already released, without decrementing shared capacity again.
                connection.execute(update(self.jobs).where(
                    self.jobs.c.id == job_id, self.jobs.c.status.in_(TERMINAL),
                    self.jobs.c.slot_reserved.is_(False), self.jobs.c.input_cleaned.is_(False),
                ).values(input_cleaned=True))

    def maintenance(self, now=None):
        now = now or utcnow()
        uploading_before = now - timedelta(seconds=300)
        queued_before = now - timedelta(seconds=self.settings.queue_ttl)
        # updated_at changes with a stage. started_at bounds a long/stuck stage
        # even if no child failure notification survives a container restart.
        running_before = now - timedelta(seconds=self.settings.hard_timeout + 120)
        with self.engine.begin() as connection:
            connection.execute(update(self.jobs).where(
                self.jobs.c.slot_reserved.is_(True),
                ((self.jobs.c.status == "uploading") & (self.jobs.c.created_at < uploading_before)) |
                ((self.jobs.c.status == "queued") & (self.jobs.c.created_at < queued_before)) |
                ((self.jobs.c.status == "running") & (self.jobs.c.started_at < running_before))
            ).values(status="failed", error="작업 보관 또는 실행 제한 시간을 초과했습니다.",
                     result=None, updated_at=now, finished_at=now))
        # Purge only records whose raw-file cleanup has already been confirmed.
        retention_before = now - timedelta(days=self.settings.history_days)
        with self.engine.begin() as connection:
            connection.execute(delete(self.jobs).where(
                self.jobs.c.status.in_(TERMINAL), self.jobs.c.input_cleaned.is_(True),
                self.jobs.c.finished_at < retention_before,
            ))
        return self.cleanable_jobs()

    def close(self):
        self.engine.dispose()
