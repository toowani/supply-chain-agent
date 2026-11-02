"""python -m sca run [--skip-scan] [--offline] [--refresh-venv] [--no-llm]
                   [--judge-mode proactive|conservative] [--k 3] [--top-k 10]
python -m sca feedback add --service S --package eco:name --vuln ID --decision approve|reject
                           --verdict V --reason R [--note ...] [--scope service|all_services]
python -m sca feedback list
python -m sca review export [--out PATH] [--force]
python -m sca review import [PATH]"""
from __future__ import annotations

import argparse
import typing

from sca.contracts import ReasonCode, Verdict


def main() -> None:
    ap = argparse.ArgumentParser(prog="sca", description="SW 공급망 스캐닝 에이전트 (PoC)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="스캔 → 판정 → 조치안 → out/report.md · ranked.csv · tickets/ · vex.json")
    r.add_argument("--skip-scan", action="store_true", help="out/raw 재사용 (syft·grype 생략)")
    r.add_argument("--offline", action="store_true", help="위협 피드(OSV·EPSS·KEV)는 data/cache만 사용")
    r.add_argument("--refresh-venv", action="store_true", help="임시 venv 재생성 (의존성 재해석)")
    r.add_argument("--no-llm", action="store_true", help="LLM 생략 (조건이 필요한 건은 보류, 티켓은 템플릿)")
    r.add_argument("--judge-mode", default="proactive", choices=["conservative", "proactive"],
                   help="proactive(적극, 기본): 필수 조건 하나가 코드에 없으면 not_affected · "
                        "conservative(보수): 검색이 완전하고 근거가 모두 없을 때만 not_affected")
    r.add_argument("--k", type=int, default=3, help="조치안 개수")
    r.add_argument("--top-k", type=int, default=10, help="심각도 정렬 vs 종합 점수 정렬 비교 행 수")

    fb = sub.add_parser("feedback", help="사람의 승인·기각 기록 → 다음 실행에 반영 (개선 루프)")
    fsub = fb.add_subparsers(dest="fcmd", required=True)
    add = fsub.add_parser("add", help="판정 결정 1건 추가")
    add.add_argument("--service", required=True)
    add.add_argument("--package", required=True, help="생태계:이름, 예: pypi:pillow")
    add.add_argument("--vuln", required=True)
    add.add_argument("--decision", required=True, choices=["approve", "reject"])
    add.add_argument("--verdict", required=True, choices=typing.get_args(Verdict))
    add.add_argument("--reason", required=True, choices=typing.get_args(ReasonCode))
    add.add_argument("--note", default="")
    add.add_argument("--scope", default="service", choices=["service", "all_services"])
    add.add_argument("--by", default="reviewer", help="결정한 사람 (시연용 기록은 demo-reviewer)")
    fsub.add_parser("list", help="저장된 결정 목록")

    rv = sub.add_parser("review", help="정답셋 core 20건 사람 검수표 (xlsx) 내보내기 / 가져오기")
    rsub = rv.add_subparsers(dest="rcmd", required=True)
    rex = rsub.add_parser("export", help="검수표 xlsx 내보내기")
    rex.add_argument("--out", default=None, help="기본값 data/eval/review_core.xlsx")
    rex.add_argument("--force", action="store_true", help="이미 채운 판정이 있어도 덮어쓰기")
    rim = rsub.add_parser("import", help="채운 검수표를 정답셋에 반영")
    rim.add_argument("path", nargs="?", default=None)

    a = ap.parse_args()
    if a.cmd == "run":
        from sca.pipeline import run
        run(skip_scan=a.skip_scan, offline=a.offline, refresh_venv=a.refresh_venv,
            top_k=a.top_k, k=a.k, no_llm=a.no_llm, judge_mode=a.judge_mode)
    elif a.cmd == "feedback":
        from sca.feedback.cli import add_decision_from_args
        from sca.feedback.store import FeedbackStore
        if a.fcmd == "add":
            d = add_decision_from_args(a.service, a.package, a.vuln, a.decision, a.verdict, a.reason,
                                       note=a.note, scope=a.scope, by=a.by, store=FeedbackStore())
            print(f"saved: {d.service} {d.package} {d.vuln_id} → {d.verdict} ({d.reason})")
        else:
            for d in FeedbackStore().decisions():
                print(f"{d.at} {d.service} {d.package} {d.vuln_id} {d.decision} → {d.verdict} ({d.reason}) {d.note}")
    elif a.cmd == "review":
        _review(a)


def _review(a: argparse.Namespace) -> None:
    from sca.eval import review as rv
    if a.rcmd == "export":
        try:
            r = rv.export_review(a.out or rv.REVIEW_PATH, force=a.force)
        except FileExistsError as e:
            raise SystemExit(f"내보내기 중단: {e}")
        print(f"검수표 저장: {r['path']} ({r['rows']}건, 코드 스니펫 {r['snippets']}줄)")
        if r["missing_advisory"]:
            print(f"  OSV 권고문 없음: {', '.join(r['missing_advisory'])}")
        print("  '안내' 시트를 읽고 내 판정·소요 시간(분)을 채운 뒤: python -m sca review import")
        return
    try:
        r = rv.import_review(a.path or rv.REVIEW_PATH)
    except ValueError as e:
        raise SystemExit(f"가져오기 실패: {e}")
    print(f"검수 반영: {r['reviewed']}건 (reviewed: true, labeled_by: {rv.REVIEWED_BY})")
    if r["changed_labels"]:
        print(f"  라벨 변경 {len(r['changed_labels'])}건: "
              + ", ".join(f"{c['id']} {c['from']}→{c['to']}" for c in r["changed_labels"]))
    else:
        print("  라벨 변경 없음 (AI 라벨과 모두 일치)")
    mean = "-" if r["mean_minutes"] is None else f"{r['mean_minutes']}분"
    print(f"  소요 시간 기록 {r['timed']}건, 평균 {mean}")
    if r["missing_minutes"]:
        print(f"  소요 시간 미기입: {', '.join(r['missing_minutes'])}")
    if r["unfilled"]:
        print(f"  판정 미기입(건너뜀): {', '.join(r['unfilled'])}")
    print("  지표 재계산: python -m sca run --skip-scan --offline")


if __name__ == "__main__":
    main()
