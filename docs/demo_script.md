# 시연 영상 대본 (2–3분)

녹화는 본인이 한다. 아래 명령은 레포 루트에서 실행한다. 화면에 비공개 서비스 소스 코드, 절대 경로(`/Users/...`), 레포 소유자 이름, `.env`가 보이지 않게 한다.

## 녹화 전 준비 (영상에 넣지 않음)

```bash
cd supply-chain-agent
ollama serve >/dev/null 2>&1 &              # LLM 백엔드 (이미 켜져 있으면 생략)
cp data/feedback/decisions.jsonl /tmp/decisions.backup.jsonl   # 시연용 피드백을 나중에 되돌리기 위해
.venv/bin/python -m sca run --skip-scan --offline               # 캐시를 채워 녹화 중 실행을 짧게
```

- 터미널 프롬프트를 짧게 바꾼다: `PS1='$ '` (zsh는 `PROMPT='$ '`)
- 글자 크기를 키우고, 에디터에서 `out/report.md` 미리보기를 열어 둔다.

## 샷 목록

| # | 시간 | 화면 | 말할 내용 (요지) |
|---|---|---|---|
| 1 | 0:00–0:15 | README 상단 결과표 | 본인 레포 5개 파일럿. 스캐너 경고 174건을 근거와 함께 거르고, 조치안과 개선 루프까지 잇는 에이전트입니다. |
| 2 | 0:15–0:45 | 터미널: `run` 실행 | 한 줄로 8단계가 돕니다. 계산·판정은 코드, 권고문 해석만 LLM, 결정은 사람입니다. |
| 3 | 0:45–1:10 | `out/graph.png`, `out/summary.md` 직접/전이 표 | 패키지 698개 중 직접 선언은 24개입니다. 취약 패키지 30개 중 27개는 선언하지 않은 부품입니다. |
| 4 | 1:10–1:40 | `out/report.md` 핵심 지표·판정 분포 | 에이전트 단독으로 25.9%를 걸렀고, 결정한 테스트셋 8건은 모두 맞았습니다. 테스트셋 전체 일치는 45%이고, 나머지는 사람에게 넘깁니다. |
| 5 | 1:40–2:00 | `out/tickets/T01-*.md` | Top-3 업그레이드로 잔여 위험의 71.2%가 줄고, 메이저 변경·Python 런타임 문제를 티켓에 표시합니다. |
| 6 | 2:00–2:35 | 터미널: `feedback add` → 재실행 → 판정 분포의 `feedback_suppressed` 증가 | 담당자의 기각 사유를 기록하면 다음 실행에서 같은 경고가 자동 정리되고 OpenVEX로 남습니다. (데모 기록이라고 말한다) |
| 7 | 2:35–2:50 | 터미널: `pytest` | 자동 테스트 131건이 통과합니다. 버전 비교는 문자열이 아니라 PEP 440/semver 코드로 합니다. |

## 녹화 중 명령

```bash
# 2
.venv/bin/python -m sca run --skip-scan --offline

# 3, 4, 5
open out/graph.png
sed -n '/## 직접 vs 전이/,/미참조:/p' out/summary.md
sed -n '/## 핵심 지표/,/## 판정 분포/p' out/report.md
cat out/tickets/T01-upgrade-pypi-pillow.md

# 6 (out/report.md의 사람 검토 대기열에서 보류 건 하나를 골라 값을 바꾼다)
.venv/bin/python -m sca feedback add --by demo-reviewer --service {{서비스}} --package {{eco:name}} \
    --vuln {{CVE-ID}} --decision reject --verdict not_affected --reason not_reachable --note "{{사유}} (데모 기록)"
.venv/bin/python -m sca run --skip-scan --offline
sed -n '/## 판정 분포/,/^$/p' out/report.md

# 7
.venv/bin/python -m pytest -q
```

## 녹화 후 되돌리기

```bash
cp /tmp/decisions.backup.jsonl data/feedback/decisions.jsonl   # 시연용 피드백 제거
.venv/bin/python -m sca run --skip-scan --offline               # out/ 지표를 제출 기준값으로 복원
```

복원 뒤 `out/metrics.json`의 값이 지원서 ①②의 숫자와 같은지 확인한다. 영상 URL은 포트폴리오(`docs/portfolio/build.py --video {{URL}}`)에 넣는다.
