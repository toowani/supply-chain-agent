# SW 공급망 스캐닝 AI 에이전트

> 취약점 경고를 **서비스 영향도**로 잇고, **근거와 함께 거르고**, 조치안과 사람 피드백으로 닫는다.
> LOTTE AX Challenge 2026 · 롯데이노베이트 [인프라] 예선 PoC

![python](https://img.shields.io/badge/python-3.11-3776AB) ![tests](https://img.shields.io/badge/tests-131%20passed-2ea44f) ![LLM](https://img.shields.io/badge/LLM-gpt--oss%3A20b%20(local)-6f42c1) ![scope](https://img.shields.io/badge/pilot-5%20repos%20%C2%B7%20174%20findings-lightgrey)

<br>

## 왜 만들었나

**보이지 않는 부품**
- 설치된 패키지 698개 중 직접 선언은 **24개(3.4%)**
- 취약 패키지 30개 중 **27개**가 선언하지 않은 부품

**경고는 많고, 진짜 위험은 적다**
- 스캐너 경고 **174건**
- 표본 56건 중 실제 영향은 **2건** (AI 라벨 초안 기준)

**병목: 경고마다 사람이 하는 일**

| 단계 | 지금 (사람) | 이 에이전트 |
|---|---|---|
| ① 어느 서비스·경로로 들어왔나 | 수작업 추적 | 코드 (의존성 그래프) |
| ② 권고문의 발동 조건은 | 문서 정독 | LLM (조건 추출) |
| ③ 우리 코드가 그 조건을 쓰나 | 코드 검색 | 코드 (검색·규칙) |
| ④ 고칠까 말까 | 판단 | 확신 없는 건만 사람에게 |

<br>

## 왜 내 프로젝트로 했나

- **실제 운영 중인 서비스 5개** — SSO, 팟캐스트 파이프라인, 수업 사이트, 크론·배치
- **그룹 SI의 축소판** — Python·npm 혼합, 노출·내부, 팀이 서로 다름
- **정답을 확인할 수 있음** — 코드를 알기 때문에 판정을 검증 가능
- **내부 정보 보호를 실제로 시험** — 비공개 코드는 LLM에 보내지 않음

<p align="center"><img src="docs/assets/deps_map.png" width="900" alt="전체 서비스 의존성 지도"></p>

<br>

## 결과

| 지표 | 파일럿 결과 |
|---|---|
| **거르기** | 경고 **174 → 129건** (25.9%) |
| **정확성** | 결정한 8건 **모두 정답** · 실제 위험 놓침 **0건** |
| **고치기** | 업그레이드 3건으로 잔여 위험 **71.2%** 해소 |
| **속도** | 건당 **22.7초** · 재실행 일치 **164/174** |

<p align="center"><img src="docs/assets/warnings.png" width="860" alt="경고 174건의 행방"></p>

<br>

## 구조

<p align="center"><img src="docs/assets/architecture.png" width="860" alt="구조도"></p>

<br>

## 판정 — LLM은 조건만, 판정은 코드가

<p align="center"><img src="docs/assets/judge.png" width="760" alt="판정 예시"></p>

- 외부 LLM에는 **공개 권고문만** 보낸다
- 모델은 환경변수로 교체 (기본 로컬 gpt-oss:20b)

<br>

## 개선 루프 — 사람의 결정이 다음 판정이 된다

<p align="center"><img src="docs/assets/loop.png" width="760" alt="개선 루프"></p>

<br>

## 실행

<p align="center"><img src="docs/assets/demo.png" width="760" alt="실행 출력"></p>

```bash
brew install syft grype uv ollama && ollama pull gpt-oss:20b
uv venv --python 3.11 .venv && uv pip install -e '.[dev]'
cp config/services.example.yaml config/services.local.yaml
.venv/bin/python -m sca run
```

산출물: [리포트](out/report.md) · [위험 순위](out/ranked.csv) · [티켓](out/tickets) · [OpenVEX](out/vex.json) · [검증 기록](docs/verification.md)

<br>

## 한계

- 파일럿 규모: 본인 레포 5개, 경고 174건
- 정답셋은 AI 초안, 본인 검수 진행 중
- 사람 검토 비율 67.2% → 콜그래프 연동이 다음 과제

<br>

## 로드맵

콜그래프 연동 → PR 게이트 → 샌드박스 테스트 후 자동 PR → 펌웨어/HBOM
