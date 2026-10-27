# 실행 격리와 자원 제한

이 구성은 **파일을 실행하지 않는 정적 분석**을 대상으로 합니다. PE 파서나 특징 추출기의 취약점으로 작업 프로세스에서 임의 코드가 실행될 가능성을 위협 모델에 포함합니다. 컨테이너는 피해 범위를 줄이는 방어 계층이며, 안전성을 증명하거나 가상머신 수준으로 격리하는 수단은 아닙니다.

## 서비스 경계

| 서비스 | 역할 | 원본 검사 파일 접근 | 호스트 공개 포트 |
|---|---|---|---|
| API | 업로드, 해시, 작업 상태, 기록 조회 | 작업 볼륨 읽기·쓰기 | `127.0.0.1:8000` |
| Celery worker | PE 파싱·특징 추출 | 작업 볼륨 읽기 전용 | 없음 |
| Inference | 상주 모델로 특징 벡터 예측 | 없음 | 없음 |
| Broker Redis | 작업 메시지 전달 | 없음 | 없음 |
| Cache Redis | 버전별 결과 캐시 | 없음 | 없음 |
| PostgreSQL | 검사 기록·작업 상태 | 없음 | 없음 |

원본 파일은 서버가 만든 UUID 경로에 저장합니다. Celery 메시지에는 작업 ID만 보내고, 원본 파일이나 Python pickle을 메시지로 보내지 않습니다. API가 작업 파일 정리를 담당하므로 파싱 작업자는 업로드 볼륨에 파일을 생성·수정·삭제할 권한이 없습니다.

## 적용한 Docker 설정

API·worker·inference에는 다음 설정을 적용했습니다.

- UID/GID `10001:10001`의 비관리자 사용자
- 읽기 전용 루트 파일시스템
- Linux capability 전체 제거와 `no-new-privileges`
- 기본 Docker seccomp 프로필 유지: `seccomp=unconfined`, `privileged`를 사용하지 않음
- CPU·메모리·프로세스 수 제한
- 실행·장치 파일·setuid 사용을 제한한 `/tmp` tmpfs
- Docker 소켓, 호스트 PID 네임스페이스, 호스트 네트워크 미사용
- 내부 전용 Compose 네트워크 사용
- 로그 파일 크기 및 개수 제한

worker 기본 제한은 **메모리 3 GiB, CPU 2개 상당, 프로세스 수 128개**입니다. `memswap_limit`도 3 GiB로 설정해 추가 스왑 사용을 허용하지 않도록 요청합니다. 실제 적용 여부는 Docker 호스트의 cgroup·메모리 설정에서 확인해야 합니다.

메모리 제한에 도달하면 작업 프로세스 또는 컨테이너가 종료될 수 있습니다. 이러한 실패가 분석 성공으로 처리되어서는 안 되며, API의 작업 상태와 회수 동작을 확인해야 합니다. Celery의 자식 메모리 재활용 기준은 **작업 종료 후** 프로세스를 교체하는 기준으로, Docker의 실행 중 메모리 상한을 대체하지 않습니다.

## 네트워크·권한의 남은 범위

내부 네트워크는 일반적인 외부 네트워크 연결을 차단하는 구성입니다. 서비스 간 통신은 허용되며, worker는 필요한 Redis·DB·추론 서비스 연결 정보를 가집니다. 파서가 침해되면 이 자격 증명과 내부 서비스가 노출될 수 있습니다. 서비스별 Redis ACL·DB 역할 분리, DNS·호스트 방화벽 정책까지 구현한 구성은 아닙니다.

Docker 컨테이너들은 호스트 커널을 공유합니다. 커널·컨테이너 런타임 취약점이나 호스트 관리자에 대한 방어를 보장하지 않습니다. `noexec`도 인터프리터를 통한 데이터 해석까지 막지는 않습니다. 실제 악성 파일을 실행하는 동적 분석은 이 컨테이너에서 수행하지 않습니다.

기본 공개 주소는 localhost이며, 사용자 인증·권한 분리·TLS를 갖춘 공개 인터넷 서비스로 평가한 상태는 아닙니다.

## 저장 공간과 큐

- 준비·대기·실행 중인 작업과 종료 후 파일 정리를 기다리는 작업을 합쳐 기본 8개로 제한합니다. API가 원본 파일을 삭제하고 정리를 확인한 뒤에만 해당 저장 슬롯을 반환합니다.
- 최대 300 MiB 파일 8개의 작업 저장 공간은 최대 약 **2,400 MiB**입니다. 동시에 multipart 수신 중인 업로드 임시 파일과 DB·로그·모델 공간은 별도입니다.
- API는 업로드 수신 동시성을 기본 2개로 제한하도록 설계되어 있습니다. 300 MiB 파일 두 개의 수신 임시 공간은 추가로 약 **600 MiB**가 필요할 수 있습니다.
- API의 multipart 임시 공간은 메모리 tmpfs 대신 디스크 기반 `api-spool` 볼륨을 사용합니다. 작업 파일은 별도 `uploads` 볼륨에 저장합니다.
- PostgreSQL 기록·Broker AOF·로그에는 별도 디스크 사용량이 발생합니다. Compose named volume 자체에 디스크 할당량을 설정한 것은 아니므로 호스트 디스크 잔량을 감시해야 합니다.
- 파일 삭제가 실패하면 해당 슬롯을 유지해 새 작업을 제한합니다. 작업 상태만 완료로 바꾼 뒤 무조건 슬롯을 반환하지 않습니다.
- Broker와 Cache Redis를 분리했습니다. 캐시의 LRU 퇴출이 큐 메시지를 제거하지 않습니다. Broker는 `noeviction`이며 메모리 부족 시 새 메시지 쓰기가 실패할 수 있습니다.

## 비밀값과 모델

`scripts/setup.ps1`은 독립적인 32바이트 난수 비밀값으로 `.env`를 생성하고 기존 파일을 덮어쓰지 않습니다. `.env`는 Git과 Docker 빌드 컨텍스트에서 제외합니다. 기존 PostgreSQL 볼륨을 유지하면서 `.env`의 DB 비밀번호만 바꾸면 접속이 실패할 수 있으므로 별도 비밀번호 변경 절차가 필요합니다.

모델은 호스트의 `models` 폴더를 inference 서비스에 읽기 전용으로 마운트합니다. worker에는 모델 마운트가 없습니다. 배포 전에 공식 모델 SHA-256을 확인하고, 모델·파이프라인 변경 시 캐시 버전이 바뀌는지 점검합니다.

기본 이미지 태그는 유지보수되는 minor 계열을 사용하지만 digest로 고정하지 않았습니다. 검증한 배포 환경에서는 실제 이미지 digest와 패키지 목록을 함께 기록하고 보안 업데이트 시 재검증해야 합니다.

## 시작 전 확인

```powershell
.\scripts\setup.ps1
docker compose config --quiet
docker compose up --build -d
docker compose ps
docker compose logs --tail=100 api worker inference
```

모델을 먼저 `models/EMBER2024_PE.model`에 준비해야 합니다. `models` 폴더가 없으면 읽기 전용 마운트가 빈 폴더를 자동 생성하지 않도록 설정했습니다.

분산 작업자는 다음과 같이 **같은 Docker 호스트**에서 늘릴 수 있습니다.

```powershell
docker compose up -d --scale worker=2
```

이때 worker 메모리·CPU 사용량도 증가합니다. named upload volume을 공유하는 단일 호스트 구성이므로, 여러 물리 호스트로 확장하려면 객체 저장소 또는 인증된 공유 저장소를 추가해야 합니다.

## 검증 범위

현재 제작 환경에는 Docker CLI/daemon이 없어 이미지 빌드·컨테이너 기동·cgroup 적용·Docker Desktop의 네트워크 연결을 실행 검증하지 못했습니다. Compose YAML과 설정 간 일관성을 정적으로 확인한 구성입니다. 위의 실제 기동 확인과 모델 분석, 시간 초과·메모리 초과 후 작업 상태 회수, 볼륨 권한, worker의 외부 연결 차단을 대상 환경에서 확인해야 합니다.

참고: [Docker Compose 서비스 설정](https://docs.docker.com/reference/compose-file/services/), [Compose 네트워크](https://docs.docker.com/compose/how-tos/networking/), [Celery 작업자 가이드](https://docs.celeryq.dev/en/stable/userguide/workers.html).
