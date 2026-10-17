from pathlib import Path

import lightgbm as lgb
import pefile
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from thrember.model import predict_sample

app = FastAPI()

# 서버가 시작될 때 모델을 한 번 불러옴
BASE_DIR = Path(__file__).resolve().parent
model = lgb.Booster(
    model_file=str(BASE_DIR / "models" / "EMBER2024_PE.model")
)
MAX_SIZE = 10 * 1024 * 1024  # 분석할 파일 크기 제한: 10MiB


@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>eNVy 파일 검사</title>
<style>
body { font-family: sans-serif; background: #141414; color: #eee;
       max-width: 540px; margin: 80px auto; padding: 24px; }
h1 { font-size: 48px; }
span { color: #ff4545; }
button { padding: 12px 24px; margin-top: 20px; cursor: pointer; }
pre { white-space: pre-wrap; background: #242424; padding: 20px; }
</style>
</head>
<body>
<h1>e<span>NV</span>y</h1>
<p>Windows 실행 파일 검사 · 최대 10MiB</p>
<form id="form">
  <input id="file" type="file" accept=".exe,.dll" required>
  <br>
  <button id="button" type="submit">검사하기</button>
</form>
<pre id="result">파일을 선택해 주세요.</pre>
<p>모델의 추정 결과이며 파일의 안전을 보장하지 않습니다.</p>
<script>
const form = document.getElementById("form");
const button = document.getElementById("button");
const result = document.getElementById("result");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData();
  data.append("file", document.getElementById("file").files[0]);

  button.disabled = true;
  result.textContent = "분석 중입니다...";

  try {
    const response = await fetch("/scan", {
      method: "POST",
      body: data
    });
    if (!response.ok) {
      let message = "분석에 실패했습니다. 서버 로그를 확인해 주세요.";
      try { message = (await response.json()).detail || message; }
      catch {}
      throw new Error(message);
    }
    const output = await response.json();
    result.textContent =
      "파일: " + output.filename +
      "\\n판정: " + output.verdict +
      "\\n악성 모델 점수: " + output.score.toFixed(6);
  } catch (error) {
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
</script>
</body>
</html>
"""


@app.post("/scan")
def scan(file: UploadFile):
    # 원본 파일명으로 저장하거나 파일을 실행하지 않음
    try:
        file_data = file.file.read(MAX_SIZE + 1)
    finally:
        file.file.close()

    if not file_data:
        raise HTTPException(400, "빈 파일입니다.")

    if len(file_data) > MAX_SIZE:
        raise HTTPException(413, "10MiB 이하의 파일을 선택해 주세요.")

    if Path(file.filename or "").suffix.lower() not in {".exe", ".dll"}:
        raise HTTPException(400, ".exe 또는 .dll 파일을 선택해 주세요.")

    try:
        pe = pefile.PE(data=file_data, fast_load=True)
        pe.close()
    except pefile.PEFormatError:
        raise HTTPException(400, "분석 가능한 Windows PE 파일이 아닙니다.")

    score = predict_sample(model, file_data)

    return {
        "filename": file.filename,
        "score": score,
        # 첫 시연용 기준값. 이후 성능 평가를 통해 조정할 수 있음
        "verdict": "악성으로 의심" if score >= 0.5 else "정상으로 추정",
    }