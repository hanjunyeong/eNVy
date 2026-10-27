"""PE feature extraction in Celery workers; model inference uses internal RPC."""
import hashlib
import math
import re
import stat
import time

from billiard.exceptions import SoftTimeLimitExceeded
import httpx
import numpy as np


class AnalysisError(Exception):
    """An expected analysis failure safe to show in job history."""


class InferenceClient:
    def __init__(self, settings, client=None):
        self.settings = settings
        self.client = client or httpx.Client(base_url=settings.inference_url, timeout=15.0, trust_env=False,
                                            limits=httpx.Limits(max_connections=2))

    def metadata(self):
        response = self.client.get("/health")
        response.raise_for_status()
        metadata = response.json()
        if (not isinstance(metadata, dict) or metadata.get("status") != "ready"
                or type(metadata.get("feature_count")) is not int
                or metadata["feature_count"] != 2568
                or not isinstance(metadata.get("model_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", metadata["model_sha256"]) is None
                or metadata.get("pipeline_version") != self.settings.pipeline_version
                or metadata.get("threshold") != self.settings.threshold
                or metadata.get("pipeline_fingerprint") != self.settings.pipeline_fingerprint()
                or metadata.get("model_version") != self.settings.model_version(metadata["model_sha256"])):
            raise AnalysisError("추론 서비스의 설정을 확인하지 못했습니다.")
        return metadata

    def predict(self, vector, model_version):
        response = self.client.post("/predict", json={"features": vector.tolist(),
                                                      "model_version": model_version})
        response.raise_for_status()
        output = response.json()
        score = output.get("score") if isinstance(output, dict) else None
        if (isinstance(score, bool) or not isinstance(score, (float, int))
                or not math.isfinite(score) or not 0 <= score <= 1
                or output.get("model_version") != model_version):
            raise AnalysisError("추론 서비스의 결과가 올바르지 않습니다.")
        verdict = "악성으로 의심" if score >= self.settings.threshold else "정상으로 추정"
        if output.get("verdict") != verdict:
            raise AnalysisError("추론 서비스의 판정 기준이 일치하지 않습니다.")
        return {"score": float(score), "verdict": verdict}

    def close(self):
        self.client.close()


def analyze_job(job, settings, inference, report_stage=lambda stage: None,
                extractor_factory=None):
    """Use the same float32 feature representation as thrember.predict_sample."""
    started = time.monotonic()
    report_stage("read_file")
    path = settings.input_path(job["id"])
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise AnalysisError("유효한 임시 검사 파일이 아닙니다.")
    with path.open("rb") as source:
        data = source.read(settings.max_file_size + 1)
    if not data or len(data) > settings.max_file_size:
        raise AnalysisError("검사 파일의 크기가 올바르지 않습니다.")
    if len(data) != job["size_bytes"] or hashlib.sha256(data).hexdigest() != job["sha256"]:
        raise AnalysisError("임시 파일의 크기 또는 해시가 제출한 파일과 일치하지 않습니다.")

    report_stage("pe_validation")
    import pefile
    from .pe_details import analyze_pe
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        raise AnalysisError("분석 가능한 Windows PE 파일이 아닙니다.") from None
    details = None
    details_error = None
    try:
        report_stage("metadata")
        details = analyze_pe(data, pe)
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        details_error = "상세정보 일부를 읽지 못했습니다. 모델 판정과 별도로 확인해 주세요."
    finally:
        pe.close()

    metadata = inference.metadata()
    if metadata["model_version"] != job["model_version"]:
        raise AnalysisError("분석 모델 버전이 변경됐습니다. 파일을 다시 제출해 주세요.")
    report_stage("feature_extraction")
    if extractor_factory is None:
        from thrember.features import PEFeatureExtractor
        extractor_factory = PEFeatureExtractor
    extractor = extractor_factory()
    features = np.asarray(extractor.feature_vector(data), dtype=np.float32)
    if features.shape != (metadata["feature_count"],) or not np.isfinite(features).all():
        raise AnalysisError("모델에 전달할 특징 형식이 올바르지 않습니다.")
    report_stage("inference")
    result = inference.predict(features, job["model_version"])
    result.update({"details": details, "details_error": details_error,
                   "analysis_seconds": round(time.monotonic() - started, 3)})
    return result
