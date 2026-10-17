from pathlib import Path
import logging
import math
from threading import Lock

import lightgbm as lgb
import pefile
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from thrember.model import predict_sample

BASE_DIR = Path(__file__).resolve().parent
MAX_SIZE = 10 * 1024 * 1024
app = FastAPI(title="eNVy")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
model = lgb.Booster(model_file=str(BASE_DIR / "models" / "EMBER2024_PE.model"))
model_lock = Lock()


@app.get("/", response_class=FileResponse)
def home():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.post("/scan")
def scan(file: UploadFile):
    # 업로드 파일을 프로그램으로 실행하지 않습니다.
    try:
        file_data = file.file.read(MAX_SIZE + 1)
    finally:
        file.file.close()
    if not file_data:
        raise HTTPException(400, "빈 파일입니다.")
    if len(file_data) > MAX_SIZE:
        raise HTTPException(413, "10 MiB 이하의 파일을 선택해 주세요.")
    if Path(file.filename or "").suffix.lower() not in {".exe", ".dll"}:
        raise HTTPException(400, ".exe 또는 .dll 파일을 선택해 주세요.")
    try:
        pe = pefile.PE(data=file_data, fast_load=True)
        pe.close()
    except pefile.PEFormatError:
        raise HTTPException(400, "분석 가능한 Windows PE 파일이 아닙니다.")
    try:
        # 동시에 들어온 요청의 모델 추론을 순서대로 처리합니다.
        with model_lock:
            score = float(predict_sample(model, file_data))
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError("Invalid model score")
    except Exception:
        logging.exception("PE feature extraction or prediction failed")
        raise HTTPException(422, "이 파일의 특징 추출 또는 모델 분석에 실패했습니다.")
    return {
        "filename": file.filename,
        "score": score,
        "verdict": "악성으로 의심" if score >= 0.5 else "정상으로 추정",
    }
