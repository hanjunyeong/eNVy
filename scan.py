import sys
from pathlib import Path

import lightgbm as lgb
import pefile
from thrember.model import predict_sample

# 검사할 파일 경로
file_path = Path(sys.argv[1])
file_data = file_path.read_bytes()

# Windows PE 파일인지 확인 — 파일을 실행하지 않음
pe = pefile.PE(data=file_data, fast_load=True)
pe.close()

# 사전학습 모델 불러오기
model_path = Path(__file__).parent / "models" / "EMBER2024_PE.model"
model = lgb.Booster(model_file=str(model_path))

# 특징 추출 및 모델 분석
score = predict_sample(model, file_data)

print(f"파일: {file_path.name}")
print(f"악성 모델 점수: {score:.6f}")