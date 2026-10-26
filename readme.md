# eNVy

Windows 실행 파일을 업로드하면 사전학습 머신러닝 모델로 악성 여부를 추정하고 결과를 보여주는 웹 프로젝트입니다.

파일을 실행하지 않고 내부 구조와 바이트 등의 특징을 추출하는 **정적 분석 방식**을 사용합니다.

## 주요 기능

- `.exe`, `.dll` 파일 업로드
- EMBER2024 사전학습 모델을 이용한 분석
- 파일명, 모델 점수, 판정 결과 표시
- 빈 파일, 지원하지 않는 파일, 손상된 PE 파일 처리
- 분석 대상 파일 크기 제한: 10MiB

## 기술 구성

| 구분 | 사용 기술 |
|---|---|
| 개발 언어 | Python 3.33 |
| 웹 서버 | FastAPI, Uvicorn |
| 화면 | HTML, CSS, JavaScript |
| 머신러닝 모델 | LightGBM |
| 특징 추출 | thrember, pefile |
| 사전학습 모델 | EMBER2024_PE.model |

## 분석 흐름

1. 사용자가 웹 화면에서 파일을 업로드합니다.
2. 서버가 파일 크기, 확장자, PE 형식의 유효성을 확인합니다.
3. thrember가 파일에서 특징을 추출합니다.
4. LightGBM 모델이 악성 모델 점수를 산출합니다.
5. 웹 화면에 점수와 판정 결과를 표시합니다.

## 설치 및 실행

아래 명령어는 **Windows PowerShell 기준**입니다.

프로젝트를 내려받은 뒤 `eNVy` 폴더에서 실행합니다.

### 1. 가상환경 생성

```powershell
py -3.11 -m venv .venv
```

### 2. 패키지 설치

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

특징 추출에 필요한 `signify`는 호환성을 위해 **0.7.1**을 사용합니다.

### 3. 사전학습 모델 다운로드

다음 명령어를 한 줄로 실행합니다.

```powershell
.\.venv\Scripts\python.exe -c "from huggingface_hub import hf_hub_download; print(hf_hub_download(repo_id='joyce8/EMBER2024-benchmark-models', filename='EMBER2024_PE.model', local_dir='models'))"
```

다운로드가 완료되면 다음 위치에 모델 파일이 생성됩니다.

```text
models/EMBER2024_PE.model
```

웹서비스 실행에는 전체 학습 데이터셋을 다운로드할 필요가 없습니다.

### 4. 웹 서버 실행

```powershell
.\.venv\Scripts\python.exe -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

브라우저에서 아래 주소로 접속합니다.

[http://127.0.0.1:8000](http://127.0.0.1:8000)

서버를 종료하려면 터미널에서 `Ctrl + C`를 누릅니다.

## 사용 방법

1. 웹 화면에서 `.exe` 또는 `.dll` 파일을 선택합니다.
2. **검사하기** 버튼을 누릅니다.
3. 분석이 끝나면 파일명, 판정, 악성 모델 점수를 확인합니다.

터미널에서도 파일을 분석할 수 있습니다.

```powershell
.\.venv\Scripts\python.exe scan.py "C:\Windows\System32\where.exe"
```

## 판정 기준

현재 웹서비스는 **시연용 기준값 0.5**를 사용합니다.

| 모델 점수 | 표시 결과 |
|---|---|
| 0.5 미만 | 정상으로 추정 |
| 0.5 이상 | 악성으로 의심 |
| 파일 검증 실패 | 오류 안내 |

모델 점수는 높을수록 모델이 악성 쪽으로 판단했다는 의미입니다. 검증 없이 이를 실제 악성 확률이나 탐지 정확도로 해석할 수는 없습니다.

판정 기준값은 향후 테스트 데이터의 탐지율과 오탐률을 평가하여 조정할 수 있습니다.

## 주요 파일

| 파일 | 역할 |
|---|---|
| `app.py` | 웹 화면, 업로드 API, 모델 분석 |
| `scan.py` | 터미널에서 개별 파일 분석 |
| `requirements.txt` | 설치 패키지와 버전 정보 |
| `.gitignore` | 가상환경, 모델, 실행 파일 등의 Git 추적 제외 |
| `models/EMBER2024_PE.model` | 별도로 다운로드하는 사전학습 모델 |

## 한계

- 본 프로젝트는 공개된 사전학습 모델을 사용하며, 자체 학습한 모델은 아닙니다.
- 정상 파일이 악성으로 분류되는 오탐과 악성 파일을 놓치는 미탐이 발생할 수 있습니다.
- 파일의 실행 중 행동은 관찰하지 않습니다.
- 개별 파일의 분석 성공만으로 탐지 성능이 검증되지는 않습니다.
- 현재는 로컬 시연용이며, 외부 공개 배포를 위한 보안 검토는 수행하지 않았습니다.

**‘정상으로 추정’이라는 결과는 파일의 안전을 보장하지 않습니다.**

## 모델 및 참고 자료

- [EMBER2024 공식 GitHub](https://github.com/FutureComputing4AI/EMBER2024)
- [EMBER2024 사전학습 모델](https://huggingface.co/joyce8/EMBER2024-benchmark-models)
- [EMBER2024 논문](https://arxiv.org/abs/2506.05074)
- [signify 호환성 관련 이슈](https://github.com/FutureComputing4AI/EMBER2024/issues/4)