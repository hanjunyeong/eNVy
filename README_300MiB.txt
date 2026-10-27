eNVy 300 MiB 업로드 지원 (2026-10-26)

이 버전은 기존 상세 분석 화면에 프로세스 분리와 대용량 업로드를 함께 적용합니다.
이전 프로세스 분리 패키지를 먼저 적용할 필요는 없습니다.

설정:
  최대 300 MiB = 314,572,800 bytes
  동시 분석 1개
  분석 제한 120초 (전송/임시 파일 준비 시간은 별도)
  exe / dll 지원, 모델과 판정 기준 0.5 유지

적용:
1. 서버를 Ctrl+C로 종료합니다.
2. 기존 app.py, scan_manager.py, scan_worker.py, scan_config.py,
   pe_details.py(있는 파일만)와 static/index.html을 프로젝트 밖에 백업합니다.
3. 압축의 Python 파일 5개를 기존 eNVy 폴더에 복사합니다.
   app.py / scan_config.py / scan_manager.py / scan_worker.py / pe_details.py
4. 압축의 static/index.html을 기존 static/index.html에 덮어씁니다.
   기존 static의 envy.png, details.css, details.js도 함께 사용하는 구성입니다.
5. 서버를 실행합니다.
   .\.venv\Scripts\python.exe -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
6. http://127.0.0.1:8000 접속 후 Ctrl+F5로 새로고침합니다.
   화면에 최대 300 MiB가 표시되는지 확인합니다.
7. 기존 where.exe를 올려 점수와 상세정보가 같은지 확인합니다.
   이후 실제 보유한 10 MiB 이상의 정상 PE 파일로 확인하세요.
   큰 파일을 분석할 때는 시간과 메모리가 더 필요할 수 있습니다.

동작과 자원 사용:
  - 화면은 /config에서 서버의 실제 용량 제한을 읽어 검사합니다.
  - FastAPI가 받은 업로드를 서버가 1 MiB씩 읽어 임시 폴더의 sample.bin에 저장합니다.
  - 실제 읽은 누적 용량을 기준으로 300 MiB 초과를 거절합니다.
  - 임시 파일을 닫은 뒤 신뢰된 scan_worker.py가 파일 경로를 받아 분석합니다.
  - 업로드 파일명은 실행 명령/저장 경로로 사용하지 않으며 파일을 실행하지 않습니다.
  - 분석 프로세스의 종료가 확인된 후 임시 검사 파일과 결과를 정리합니다.
  - 이 방식은 웹서버에서 300 MiB를 한꺼번에 메모리에 읽는 것을 피합니다.
    특징 추출기는 분석 프로세스에서 파일 전체를 읽으므로 메모리 사용량이 증가합니다.
    운영체제 수준의 메모리 제한이나 보안 샌드박스를 제공하는 것은 아닙니다.
  - FastAPI 업로드 임시 파일과 분석용 복사본이 동시에 존재할 수 있습니다.
    최대 크기 파일 하나에 임시 디스크 공간 약 600 MiB와 추가 여유가 필요합니다.
  - multipart 수신은 분석 API 실행 전에 이루어집니다. 현재 300 MiB 검사는
    네트워크 수신량/동시 업로드 수를 제한하는 공개 서비스용 게이트웨이 제한이 아닙니다.
    현재와 같이 로컬 시연으로 사용합니다.
  - 정상 완료/오류/시간 초과 후 정리합니다. 종료를 확인할 수 없는 예외 상황에서는
    프로세스가 정리될 때까지 해당 슬롯과 임시 폴더를 유지합니다.

설정 변경:
  scan_config.py의 MAX_FILE_SIZE / SCAN_TIMEOUT_SECONDS / MAX_CONCURRENT_SCANS를 수정합니다.
  서버 재시작 후 페이지를 새로고침하면 화면도 서버의 제한에 맞춰집니다.
  동시 분석 한도는 Uvicorn 프로세스당 적용되므로 --workers 옵션은 추가하지 마세요.

확인용 주소:
  http://127.0.0.1:8000/config
  http://127.0.0.1:8000/health

선택: 테스트
  tests/test_scan_manager.py를 같은 이름의 기존 테스트에 덮어쓰거나 tests 폴더에 복사합니다.
   .\.venv\Scripts\python.exe -m unittest discover -s tests -v
  가짜 작업 프로세스를 사용하므로 모델이나 실제 악성 파일은 필요 없습니다.
  300 MiB 경계 테스트는 실제로 해당 크기의 임시 파일을 기록했다가 삭제합니다.
  오류 복구 테스트의 ERROR 로그는 의도한 것이며 마지막 OK가 완료 기준입니다.

검증:
  - 300 MiB 생성 스트림이 1 MiB 이하 단위로 실제 저장/전달되는 것을 확인했습니다.
  - 300 MiB + 1 byte는 분석 프로세스 실행 전에 거절됐습니다.
  - 임시 파일 정리, 시간 초과, 동시 요청, 오류 후 재사용을 검증했습니다.
  - API와 화면이 10 MiB 초과를 허용하고 공통 300 MiB 설정을 사용하는지 확인했습니다.
  - 테스트의 대용량 전달 성공은 모든 300 MiB 파일의 모델 분석 성공을 뜻하지 않습니다.
    실제 EMBER2024 모델과 Windows 환경은 사용자 PC에서 확인해야 합니다.

Git 저장:
   git add app.py scan_config.py scan_manager.py scan_worker.py pe_details.py static/index.html
   git commit -m "Support 300 MiB uploads with staged analysis"
   git push
  선택 테스트도 복사했다면 tests/test_scan_manager.py를 함께 저장합니다.

원상복구:
  서버를 종료하고 백업한 Python 파일과 static/index.html을 복원한 뒤 재시작합니다.
