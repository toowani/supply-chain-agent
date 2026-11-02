# 교차 검증 기록 (AI 리뷰 에이전트)

개발 중 네 차례(4차는 제출물 자체 검토), 구현 에이전트와 분리된 검증 에이전트(Claude Code 워크플로, 읽기 전용)가 원시 데이터에서 숫자를 다시 계산하고 코드를 감사했다. 검증 에이전트도 AI이므로 독립된 제3자 검증은 아니다. 실행 기록 시각은 UTC이고(예: `2026-10-31T18:20Z` = 한국 시각 11-01), 커밋 날짜와 대조할 때 주의한다.

## 1차 — scan·ingest·graph·score
검증 축 6개: 의존성 분류, 탐지 행 완전성, 점수 계산, 그래프 요약, 유출, 코드 리뷰.
- 점수·CVSS 선택·KEV/EPSS·수정 버전·순위는 174행 모두 독립 재계산값과 일치
- 수정한 문제 4건
  1. Python 의존 엣지에 extra 전용 선택 의존성이 포함됨 → 전이/미참조 오분류, 거짓 경로 99행 (설치 METADATA + 마커 평가로 재구성)
  2. npm 프로젝트 루트가 패키지로 집계됨 (631 → 628)
  3. `.claude/worktrees` 아래 lockfile까지 스캔해 탐지가 중복됨
  4. 심각도 라벨과 CVSS의 출처가 달랐음 (`severity_cvss` 열 추가), 동점 정렬이 문자열 비교였음

## 2차 — judge·plan·feedback·report·eval 구현 직후 교차 리뷰
모듈마다 리뷰 에이전트 1개가 붙어 버그를 찾고 수정했다(13건). 이 문서에는 아래 4건만 개별로 기록했고, 각각 회귀 테스트가 있다.
| 문제 | 회귀 테스트 |
|---|---|
| 버전 파싱 실패를 범위 밖(not_affected)으로 처리 | `tests/test_judge.py::test_range_unparseable_version_is_unknown_not_out_of_range` |
| 백포트 브랜치 fix 버전 선택 오류 | `tests/test_plan_feedback.py::test_backport_fix_versions_use_lowest_newer_fix` |
| 재스캔 실패를 "조치 확인"으로 처리 | `tests/test_plan_feedback.py::test_rescan_fixed_needs_service_rescanned` |
| OpenVEX에 accepted_risk가 not_affected로 나감 | `tests/test_plan_feedback.py::test_openvex_feedback_reason_and_accepted_risk` |

## 3차 — 최종 검증 5축: KPI 재계산, 판정 안전성, 조치 계획, 유출, 지원서 문구
- KPI: 모든 수치 재현. 단, 데모 피드백 4행이 경고 감소율에 섞여 있음 → "에이전트 단독" 지표 분리
- 판정 안전성: not_affected를 잘못 내는 체계적 원인 확인 → 규칙 v4로 수정
  - 배포판·import 이름 불일치 (`lightning` ↔ `pytorch_lightning`): 테스트셋 G04 오판정의 원인
  - 의존 패키지의 `dist/`·`build/`·1MB 초과 번들 미검색인데 "참조 없음"으로 결론
  - 선언되지 않은 import 패키지(rembg)의 하위 의존 누락
  - input 조건의 데이터 토큰(`SOF3`, `fcTL`)을 API로 사용
  - 조건 간 AND 판정 (LLM이 대안을 별개 조건으로 나누면 오판)
  - "Windows 제외" 같은 부정형 플랫폼 문구 오독
- 조치 계획: Top-3 중 pillow 13.0.0(Python >=3.11)과 aiohttp 3.14.4(Python >=3.10)가 서비스 런타임 3.9.6과 맞지 않음 → 런타임 호환성 검사 추가
- 유출: `metrics.json`에 비공개 레포 내용을 담은 라벨 근거 문구 포함 → 현재 파일에서 제거, 공개 산출물에는 `file:line`만. 공개 레포는 이 문구가 없는 새 기록으로 시작했다.

## 3차 이후 추가분 (검증 전)
판정 모드 비교(적극/보수), 조치 대안 분석, 사람 검수표(`sca review`), 6쪽 포트폴리오 PDF, 판정 규칙 v5(code_unavailable 규칙, 미지원 생태계는 코드 판정 없이 보류), 메이저 변경과 Python 런타임 호환성 분리(aiohttp는 메이저 아님·런타임 업그레이드 필요), ingest 이름 결합 수정(PURL 없는 Trivy maven 항목·npm scope 패키지), SBOM 전용 서비스의 `repo` 생략 허용은 위 검증 이후 추가되어 별도 검증 회차를 거치지 않았다. 공개 전 점검 결과는 이 아래에 4차로 추가한다.

## 4차 — 제출물 전체 자체 검토 (2026-11-01)
심사위원 관점·사실과 수치 일관성·공개 레포 준비·코드 견고성 4개 축으로 비평 71건(high 13)을 받고, 문서·포트폴리오·코드 담당 에이전트가 파일을 나눠 반영한 뒤 재실행·재검증했다. 주요 반영:
- 문서: 현재 테스트셋 정확도 45%를 숨기지 않고 표기, 운영 시나리오·운영 KPI·본선 1박 2일 계획 추가, 데모 결정·미검증(OpenAI 실호출, 아이멤버 연동) 명시
- 코드: OpenAI 추론 모델(o-series, gpt-5)에 temperature를 보내지 않도록 수정, 메이저 변경과 Python 런타임 업그레이드 분리, 티켓 LLM 서술의 입력 밖 내용 차단, CycloneDX SBOM + Grype/Trivy JSON만으로 도는 `kind: sbom` 입력(본선 데이터 대비), 코드가 없거나 미지원 생태계면 `code_unavailable`로 보류, LLM 서버가 꺼지면 캐시만 쓰고 새 호출이 필요하면 out/을 덮어쓰기 전에 중단
- 재검증 지적 6건(npm scope 이름, PURL 없는 Trivy 항목, gpt-5-chat 파라미터, Trivy 수정 상태, unknown 분류 범위, repo 생략) 수정, 테스트 131건 통과
- 콜드 측정: LLM 캐시를 지운 별도 사본에서 전체 재실행 → 건당 22.7초(중앙값 23.5초), 판정 164/174건 일치(94.3%), 테스트셋 결정 9건 모두 정답. 기록: `data/eval/cold_run.json`

## 측정 원칙
- 정답셋은 core(20, 테스트) / extended(36, 튜닝)로 나눴고, 규칙은 extended 기준으로 고쳤다.
- 3차의 안전성 수정은 테스트셋 오답이 아니라 코드 감사에서 나온 일반 결함이다. 다만 G04는 테스트셋에서 처음 발견됐으므로, 수정 전 수치(v3: 정확도 55%, 판정 정밀도 11/13, 놓친 affected 1건)도 함께 기록한다.
- 정답셋 라벨은 Claude가 판정 결과를 보지 않고 두 번 따로 만든 초안(56건 모두 일치)이며, 사용자 검수 전이다.
- `data/feedback/decisions.jsonl`의 결정 2건은 시연용 데모 기록(`by: demo-reviewer`)이다.
