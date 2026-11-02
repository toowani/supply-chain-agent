# supply-chain-agent (PoC)

SBOM 생성부터 취약점 판정, 조치안, 개선 루프까지 한 줄로 실행하는 SW 공급망 스캐닝 에이전트.
LOTTE AX Challenge 2026 롯데이노베이트 [인프라] 과제 예선용 PoC. 범위: **본인 레포 5개 파일럿** (가상 계열사 서비스). 서비스 이름은 작성자 본인 레포 이름이다.

## 결과 (본인 레포 5개 파일럿, 실행 2026-11-01T03:00Z)

값은 `out/metrics.json`에서 옮겼다. 자세한 산출 근거는 [`out/report.md`](out/report.md).

| 지표 | 값 | 비고 |
|---|---|---|
| 스캐너 탐지 | 174행 | 서비스 × 패키지 × 취약점 |
| 경고 감소율 (에이전트 단독) | 25.9% (174 → 129) | 데모 피드백 4행 제외 |
| 사람 검토 비율 (보류) | 67.2% (117건) | 그중 87건은 의존 패키지 내부 호출 여부 → 콜그래프 대상 |
| 테스트셋 정답 일치 | 45.0% (9/20) | 다수 클래스(전부 not_affected) 기준선 85.0%, 대신 affected 0건 검출 |
| 판정한 건의 정밀도 (테스트셋) | 100% (8/8) | 보류 12건. not_affected 오판 0건, affected 2건 중 1건 적중·1건 보류 |
| Top-3 업그레이드 위험 커버율 | 71.2% | pillow·aiohttp·urllib3 (모두 podcast4life) |
| 보수 모드 경고 감소율 | 12.1% | 판정 정밀도 100% (4/4) |
| 에이전트 처리 시간 | 22.7초/건 | LLM 캐시 없이 전체 재실행한 실측(중앙값 23.5초, `data/eval/cold_run.json`) |
| 재현성 | 164/174건 판정 일치 (94.3%) | 캐시 없이 재실행해 비교. 차이는 LLM 조건 추출 차이라 운영은 조건 캐시로 재현 |

정답셋은 AI 초안(Claude가 판정 결과를 보지 않고 두 번 따로 작성, 56건 일치)이고, 본인 검수는 진행 중이다(현재 0/20건).
검증 기록: [`docs/verification.md`](docs/verification.md) · 포트폴리오: [`docs/portfolio/portfolio.pdf`](docs/portfolio/portfolio.pdf)

## 구조 — 계산은 코드, 해석은 LLM, 결정은 사람

```mermaid
flowchart LR
  scan["scan (CODE)"] --> ingest["ingest (CODE)"] --> enrich["enrich (CODE)"] --> graph["graph (CODE)"] --> score["score (CODE)"]
  score --> judge["judge: 조건 추출 (LLM) + 판정 (CODE)"] --> plan["plan (CODE)"] --> report["report (CODE + LLM 티켓 초안)"]
  report --> feedback["feedback (HUMAN)"] --> judge
```

| 단계 | 모듈 | 방식 |
|---|---|---|
| scan | `sca/ingest/scan.py` | Syft CycloneDX SBOM(설치 상태: venv dist-info, npm lock) → Grype JSON |
| ingest | `sca/ingest/` | 공통 스키마(pydantic). 입력 형식이 바뀌면 `parsers.py`만 교체. 스캔 없이 받은 파일은 `kind: sbom`(CycloneDX SBOM + Grype/Trivy JSON, `repo` 생략 가능) — `config/services.example.yaml` 참고 |
| enrich | `sca/enrich/` | OSV(권고문·CVE alias), FIRST EPSS, CISA KEV. 디스크 캐시, 공개 ID만 외부로 나감 |
| graph | `sca/graph/` | Team–Service–Package–Vuln (networkx), 서비스 내부 경로, blast radius |
| score | `sca/score/` | `risk = 100 × likelihood × impact` (코드) |
| judge | `sca/judge/` | LLM: 공개 권고문 → 조건 JSON / 코드: 버전 범위·import·심볼 검색 → 규칙 12개(`sca/judge/rules.py`, R0–R9·R8a(검색할 코드 없음) + LLM 불가 보류)로 판정 |
| plan | `sca/plan/` | 가중 집합 덮개(탐욕) → 업그레이드·삭제 Top-k, 위험 감소율, 메이저 변경·Python 런타임 호환성 표시 |
| report | `sca/report/` | 순위 CSV, Markdown 리포트, 티켓 초안, 그래프 PNG |
| feedback | `sca/feedback/` | 승인·기각 사유 저장 → 같은 패키지·취약점 자동 정리, 로컬 모델일 때 few-shot 예시, OpenVEX, 재스캔 검증 |
| eval | `sca/eval/` | 정답셋 대비 정확도·혼동 행렬, KPI(`out/metrics.json`), 사람 검수표(`sca review`) |

- likelihood = KEV면 1, 아니면 EPSS (없으면 실측 중앙값 + "정보 부족" 표시)
- impact = CVSS/10 × 노출 가중 × 중요도 가중 × dev 전용 0.5 (가중치는 **가정**, `config/scoring.yaml`)
- 버전 비교는 `sca/versions.py` (PEP 440 / semver). 문자열 비교 금지
- 외부 LLM에는 공개 권고문만 보낸다. `config/assets.yaml`(노출·중요도·담당 팀)과 소스 코드는 코드에서만 결합한다. 사람의 검토 사유(내부 정보)는 로컬 모델일 때만 프롬프트 예시로 들어간다
- LLM 백엔드는 OpenAI SDK + `base_url`: 로컬 Ollama 기본, 환경변수로 OpenAI·사내 모델로 교체하도록 만들었다 (`.env.example`, OpenAI 경로는 미검증)

## 실행

서비스 레포는 비공개라 이 레포만으로는 그대로 재현되지 않는다. 본인 레포로 돌리려면 `services.local.yaml`의 repo 경로를 바꾸고, `config/assets.yaml`에 같은 이름으로 노출·중요도·담당팀을 적는다.

```bash
brew install syft grype uv ollama
ollama pull gpt-oss:20b                      # 로컬 LLM. 다른 모델: SCA_LLM_MODEL=gemma4:12b
uv venv --python 3.11 .venv && uv pip install -e '.[dev]'
cp config/services.example.yaml config/services.local.yaml   # 실제 레포 경로 입력
.venv/bin/python -m sca run                  # scan → … → out/report.md
.venv/bin/python -m sca run --skip-scan --offline   # 서비스 레포·work/venvs·out/raw·data/cache가 로컬에 있고 LLM 백엔드가 켜져 있을 때 네트워크 없이 재실행
.venv/bin/python -m sca run --judge-mode conservative   # 기본은 proactive(적극: 필수 조건 하나만 없어도 not_affected). conservative(보수) = 근거가 완전할 때만
.venv/bin/python -m sca feedback add --by demo-reviewer --service podcast4life --package pypi:pillow \
    --vuln CVE-2026-112893 --decision reject --verdict not_affected --reason not_reachable --note "폰트는 고정 경로 (데모 기록)"
.venv/bin/python -m sca review export        # 정답셋 core 20건 사람 검수표(xlsx) → 채운 뒤 review import
```

예시 `feedback add` 명령은 `data/feedback/decisions.jsonl`에 데모 기록을 남기고 다음 실행 지표를 바꾼다. 실제 검토 기록은 `--by <이름>`으로 남긴다. 현재 저장된 결정 2건은 데모 기록(`demo-reviewer`)이다.

## 평가 데이터

- 정답셋 56건: core 20건(테스트) / extended 36건(튜닝). 규칙은 튜닝셋 기준으로 고쳤고, 테스트셋에서 처음 드러난 1건(G04)은 수정 전 수치를 `docs/verification.md`에 함께 남겼다.
- 라벨 근거에는 비공개 코드 내용이 들어 있어 `data/eval/ground_truth.yaml`은 로컬 전용이다.
- 사람 검수: `sca review export` → xlsx에 판정·소요 시간 입력 → `sca review import` → `sca run --skip-scan --offline`으로 지표 재계산.

## 출력

| 파일 | 내용 |
|---|---|
| `out/report.md` | KPI, 판정 분포, 업그레이드 Top-3, 사람 검토 대기열, 그래프 |
| `out/ranked.csv` | 서비스·패키지·버전·의존 유형·CVE·CVSS·EPSS·KEV·점수·판정·수정 버전·경로 |
| `out/tickets/*.md` | 조치별 티켓 초안 (담당팀, 근거, 검증 방법) |
| `out/graph.png` | 팀 → 서비스 → 패키지 → 취약점 영향 그래프 |
| `out/vex.json` | OpenVEX v0.2.0 (판정 결과 공유용) |
| `out/metrics.json` | 경고 감소율, 판정 정확도, Top-3 커버율, 사람 검토 비율, 처리 시간 |
| `out/summary.md` | 직접/전이 의존성, 공유 패키지, 심각도 정렬 vs 종합 정렬 |
| `out/history/`, `out/judgments.json` | 실행별 스냅샷·판정 상세 (로컬 전용, 비공개 코드 인용 포함 — 공개 레포에는 없음) |

## 한계

- 파일럿 범위는 본인 레포 5개, 탐지 174행이다. 일반화된 수치가 아니다.
- 콜그래프 분석이 없어 의존 패키지 내부 호출 여부는 사람에게 넘긴다(보류 67.2%의 주원인).
- 정답셋은 AI 초안이고 본인 검수는 진행 중이다(현재 0/20건).
- 저장된 피드백 2건은 데모 기록이다. 재스캔 비교는 구현·테스트했지만 파일럿에서 실제 조치로 해소된 사례는 아직 없다.
- 처리 시간 22.7초는 LLM 캐시 없이 한 번 재실행한 값이다(로컬 gpt-oss:20b). 캐시를 쓰면 10.7초다(out/metrics.json). 사람 처리 시간은 미측정.
- OpenAI·사내 모델 경로는 실행 검증 전이다.

## 테스트

```bash
.venv/bin/python -m pytest -q    # 131 passed
```

## 로드맵

PR 게이트(새로 생긴 위험만 코멘트·차단) · 콜그래프 연동(전이 의존 uncertain 해소) · 샌드박스 테스트 후 Auto-PR · 펌웨어/HBOM

