# SW 공급망 스캐닝 AI 에이전트

> SBOM과 취약점 스캔 결과를 **서비스 영향도·우선순위**로 잇고, 공개 권고문의 발동 조건을 코드에서 확인해 **근거와 함께 경고를 거른 뒤**, 조치안과 사람 피드백 루프로 닫는 에이전트.
> LOTTE AX Challenge 2026 · 롯데이노베이트 [인프라] 과제 예선 PoC

![python](https://img.shields.io/badge/python-3.11-3776AB) ![tests](https://img.shields.io/badge/tests-131%20passed-2ea44f) ![LLM](https://img.shields.io/badge/LLM-gpt--oss%3A20b%20(local)-6f42c1) ![scope](https://img.shields.io/badge/pilot-5%20repos%20%C2%B7%20174%20findings-lightgrey)

<p align="center"><img src="out/graph_top_path.png" width="760" alt="최고 위험 경로: 팀 → 서비스 → 직접 의존 → 취약 패키지 → CVE"></p>

## 한눈에 보기

| | 결과 (본인 레포 5개 파일럿) |
|---|---|
| 🔎 **거르기** | 경고 **174 → 129건** (에이전트 단독 25.9%, 걸러낸 건마다 `file:line` 근거와 OpenVEX 기록) |
| 🎯 **정확성** | 테스트셋에서 에이전트가 결정한 **8건 모두 정답**, 실제 위험을 잘못 거른 건 **0건** · 전체 정답 일치는 9/20(45%), 나머지는 사람에게 넘김 |
| 🛠 **고치기** | 업그레이드 **3건으로 잔여 위험 71.2%** 해소 (메이저 변경·Python 런타임 호환성 표시) |
| ⏱ **속도·재현성** | 건당 **22.7초** (LLM 캐시 없이 실측) · 캐시 없이 재실행해도 판정 **164/174건 일치** |

```mermaid
pie showData
  title 경고 174건은 어디로 갔나
  "근거와 함께 제외 (에이전트)" : 45
  "제외 (사람 피드백, 데모)" : 4
  "영향 있음 (affected)" : 8
  "사람 검토 대기 (uncertain)" : 117
```

## 구조 — 계산은 코드, 해석은 LLM, 결정은 사람

```mermaid
flowchart LR
  subgraph IN["입력"]
    direction TB
    s1["Syft SBOM<br/>(설치 상태)"]
    s2["Grype / Trivy<br/>스캔 결과"]
    s3["assets.yaml<br/>노출·중요도·담당팀"]
  end
  subgraph CORE["에이전트 (python -m sca run)"]
    direction LR
    ing["① ingest<br/>공통 스키마"] --> enr["② enrich<br/>OSV·EPSS·KEV"] --> grp["③ 그래프<br/>팀–서비스–패키지–CVE"] --> scr["④ 위험 점수"]
    scr --> jdg["⑤ 판정<br/>조건 추출 + 코드 확인"] --> pln["⑥ 조치 계획<br/>가중 집합 덮개"] --> rep["⑦ 리포트·티켓"]
  end
  subgraph OUT["산출물"]
    direction TB
    o1["순위 CSV · 리포트"]
    o2["담당팀별 티켓"]
    o3["OpenVEX · KPI"]
  end
  IN --> ing
  rep --> OUT
  rep --> fb["⑧ 사람 승인·기각"] -->|다음 실행에 반영| jdg

  classDef code fill:#e3f2fd,stroke:#1e88e5,color:#0d47a1
  classDef llm fill:#f3e5f5,stroke:#8e24aa,color:#4a148c
  classDef human fill:#fff3e0,stroke:#fb8c00,color:#e65100
  class ing,enr,grp,scr,pln code
  class jdg,rep llm
  class fb human
```

<sub>파랑 = 결정적 코드 · 보라 = LLM이 일부 담당(권고문 조건 추출, 티켓 문장) · 주황 = 사람</sub>

| 단계 | 하는 일 | 위치 |
|---|---|---|
| ① ingest | SBOM·스캔 결과 → 공통 스키마. 입력 형식이 바뀌면 파서만 교체 (`kind: sbom`으로 SBOM + Grype/Trivy JSON만으로도 실행) | `sca/ingest/` |
| ② enrich | OSV 권고문, FIRST EPSS, CISA KEV (공개 ID만 외부 조회, 디스크 캐시) | `sca/enrich/` |
| ③ 그래프 | 같은 취약 부품을 쓰는 서비스 전체와 "서비스 → 직접 의존 → … → 취약 패키지" 경로 | `sca/graph/` |
| ④ 점수 | $risk = 100 \times likelihood \times impact$ (가중치는 가정, `config/scoring.yaml`) | `sca/score/` |
| ⑤ 판정 | 아래 그림 참고. 규칙 12개, 적극/보수 모드 | `sca/judge/` |
| ⑥ 조치 | 업그레이드·삭제 Top-k와 위험 감소율, 호환성 위험 | `sca/plan/` |
| ⑦ 리포트 | 순위 CSV, Markdown 리포트, 티켓 초안, 그래프 PNG, OpenVEX | `sca/report/` |
| ⑧ 피드백 | 승인·기각 사유 저장 → 같은 경고 자동 정리, 재스캔으로 조치 확인 | `sca/feedback/` |

## 판정 — LLM은 조건만 뽑고, 판정은 코드가

```mermaid
flowchart TD
  adv["공개 권고문 (OSV/GHSA)"] --> llm["LLM: 발동 조건 추출<br/>API · 설정 · 플랫폼 · 입력 · 원문 인용"]
  llm --> chk{"권고문에 있는<br/>함수명·인용인가?"}
  chk -->|아니오| drop["버림"]
  chk -->|예| code["코드 검색<br/>서비스 + 의존 패키지 소스"]
  ver["버전 범위 (PEP 440 / semver)"] --> rules
  code --> rules["규칙 12개 (sca/judge/rules.py)"]
  rules --> na["not_affected<br/>근거 file:line + VEX"]
  rules --> af["affected"]
  rules --> un["uncertain → 사람"]

  classDef llm fill:#f3e5f5,stroke:#8e24aa,color:#4a148c
  classDef code fill:#e3f2fd,stroke:#1e88e5,color:#0d47a1
  classDef human fill:#fff3e0,stroke:#fb8c00,color:#e65100
  class llm llm
  class chk,code,ver,rules code
  class un human
```

- **내부 정보 보호**: 외부 LLM에는 공개 권고문만 보낸다. 자산 정보와 소스 코드는 코드에서만 결합한다.
- **모델 교체**: OpenAI SDK + `base_url`. 기본은 로컬 Ollama(gpt-oss:20b), 환경변수로 OpenAI·사내 모델로 바꾼다(OpenAI 경로는 미검증).
- **모드**: 적극(기본) = 필수 조건 하나만 없어도 제외 · 보수 = 근거가 완전할 때만 제외 (경고 감소 12.1%).

## 사람 검토가 남는 이유

```mermaid
pie showData
  title 사람 검토 117건의 원인
  "의존 패키지 내부 호출 여부 (콜그래프 필요)" : 87
  "공격자 입력인지 판단 필요" : 25
  "코드로 확인할 수 없는 조건" : 5
```

74%가 콜그래프 문제다. 콜그래프를 붙이면 검토율이 67.2%에서 약 19%로 줄 것으로 추정한다(추정치, `out/report.md`).

## 실행

```bash
brew install syft grype uv ollama && ollama pull gpt-oss:20b
uv venv --python 3.11 .venv && uv pip install -e '.[dev]'
cp config/services.example.yaml config/services.local.yaml   # 스캔할 레포 경로 입력
.venv/bin/python -m sca run                                  # → out/report.md
```

| 옵션 | 뜻 |
|---|---|
| `--skip-scan --offline` | 이전 스캔·캐시로 네트워크 없이 재실행 |
| `--judge-mode conservative` | 보수 모드 |
| `sca feedback add …` | 승인·기각 기록 → 다음 실행에 반영 |
| `sca review export / import` | 정답셋 사람 검수표(xlsx) |

파일럿 서비스 레포는 비공개라 이 레포만으로 결과를 그대로 재현할 수는 없다. 산출물은 `out/`에 커밋되어 있다.

## 산출물

| 파일 | 내용 |
|---|---|
| [`out/report.md`](out/report.md) | KPI, 판정 분포, 모드 비교, Top-3 조치, 사람 검토 대기열 |
| [`out/ranked.csv`](out/ranked.csv) | 위험 순위 (점수·판정·수정 버전·경로) |
| [`out/tickets/`](out/tickets) | 담당팀별 티켓 초안 (근거, 호환성 위험, 검증 명령) |
| [`out/vex.json`](out/vex.json) | OpenVEX v0.2.0 |
| [`out/metrics.json`](out/metrics.json) | KPI 원본 |
| [`docs/verification.md`](docs/verification.md) | AI 검증 에이전트 4회차 기록 |

## 한계

- 파일럿은 본인 레포 5개, 탐지 174건이다. 일반화된 수치가 아니다.
- 정답셋 56건(테스트 20 / 튜닝 36)은 AI 초안이고 본인 검수는 진행 중이다(현재 0/20건).
- 저장된 피드백 2건은 데모 기록이고, 파일럿에서 실제 조치로 해소된 사례는 아직 없다.
- 22.7초는 LLM 캐시 없이 한 번 재실행한 값이다(캐시를 쓰면 10.7초). 사람 처리 시간은 미측정.

## 로드맵

콜그래프 연동 → PR 게이트(새 위험만 코멘트·차단) → 샌드박스 테스트 후 자동 PR → 펌웨어/HBOM
