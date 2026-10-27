"""Internal inference RPC: one resident LightGBM model per service process.

Workers send numeric features, never PE bytes. Run one Uvicorn worker here;
horizontal replicas intentionally have one independent model each.
"""
from contextlib import asynccontextmanager
import hashlib
import math
from pathlib import Path
import threading
from typing import Annotated

from fastapi import FastAPI, HTTPException, Request
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings

FLOAT32_MAX = float(np.finfo(np.float32).max)
Feature = Annotated[float, Field(strict=True, allow_inf_nan=False,
                                 ge=-FLOAT32_MAX, le=FLOAT32_MAX)]


class PredictionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    features: list[Feature] = Field(min_length=1, max_length=4096)
    model_version: str = Field(min_length=1, max_length=256)


class _BodyLimit:
    def __init__(self, app, limit=65536):
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != "/predict":
            return await self.app(scope, receive, send)
        count = 0

        async def limited_receive():
            nonlocal count
            message = await receive()
            if message["type"] == "http.request":
                count += len(message.get("body", b""))
                if count > self.limit:
                    raise HTTPException(413, "특징 요청 크기를 초과했습니다.")
            return message

        await self.app(scope, limited_receive, send)


class ModelServer:
    def __init__(self, settings, booster_factory=None):
        self.settings = settings
        digest = hashlib.sha256()
        with settings.model_path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        self.model_sha256 = digest.hexdigest()
        self.model_version = settings.model_version(self.model_sha256)
        if booster_factory is None:
            import lightgbm as lgb
            booster_factory = lgb.Booster
        self.model = booster_factory(model_file=str(settings.model_path))
        self.feature_count = int(self.model.num_feature())
        if self.feature_count != 2568:
            raise ValueError("This service expects the EMBER2024 PE 2568-feature model")
        self._lock = threading.Lock()

    def metadata(self):
        return {"status": "ready", "model_sha256": self.model_sha256,
                "model_version": self.model_version, "feature_count": self.feature_count,
                "pipeline_version": self.settings.pipeline_version,
                "pipeline_fingerprint": self.settings.pipeline_fingerprint(),
                "threshold": self.settings.threshold}

    def predict(self, body):
        if body.model_version != self.model_version:
            raise HTTPException(409, "모델 버전이 달라졌습니다. 작업을 다시 제출해 주세요.")
        if len(body.features) != self.feature_count:
            raise HTTPException(422, "모델의 특징 개수가 일치하지 않습니다.")
        vector = np.asarray(body.features, dtype=np.float32).reshape(1, -1)
        if not np.isfinite(vector).all():
            raise HTTPException(422, "유효하지 않은 특징 값입니다.")
        # Inference is short and serialized; untrusted parsing never runs here.
        with self._lock:
            prediction = self.model.predict(vector, num_threads=1)
        score = float(prediction[0])
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise HTTPException(503, "모델의 응답이 올바르지 않습니다.")
        return {"score": score,
                "verdict": "악성으로 의심" if score >= self.settings.threshold else "정상으로 추정",
                "model_version": self.model_version}


def create_app(settings=None, booster_factory=None):
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app):
        # Import/model load happens once, before readiness and request handling.
        app.state.model = ModelServer(settings, booster_factory)
        yield

    app = FastAPI(title="eNVy internal inference", lifespan=lifespan)
    app.add_middleware(_BodyLimit)

    @app.get("/health")
    def health(request: Request):
        return request.app.state.model.metadata()

    @app.post("/predict")
    def predict(body: PredictionInput, request: Request):
        return request.app.state.model.predict(body)

    return app


app = create_app()
