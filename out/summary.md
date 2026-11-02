# 스캔 요약 (본인 레포 5개 파일럿)
실행 2026-11-01T03:00:50Z · syft 1.55.0 · grype 0.121.0 (DB 빌드 2026-10-31T06:18:17Z) · KEV 카탈로그 2026.10.30 · EPSS 수집 2026-10-31T14:47:05Z · 소요 95.6s (스캔 0.3s)

## 그래프 요약
| 서비스 | 팀 | 패키지(name@ver, 고유) | 패키지(name, 고유) | 취약점(고유 ID) | 탐지 행(서비스×패키지×취약점) | 서비스 간 공유 패키지 |
|---|---|---|---|---|---|---|
| 5 | 5 | 628 | 563 | 150 | 174 | 99 |

## 직접 vs 전이 의존성 (서비스별, 고유 name@version)
| 서비스 | 전체 | 직접 | 전이 | 미참조* | dev 전용 | 탐지 행 | 취약 패키지 | └ 직접 | └ 전이 | └ 미참조 |
|---|---|---|---|---|---|---|---|---|---|---|
| podcast4life | 235 | 12 | 202 | 21 | 91 | 143 | 21 | 3 | 15 | 3 |
| wani-briefing-routine | 12 | 5 | 7 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| lms-watch | 8 | 2 | 6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| class-toowani | 350 | 2 | 348 | 0 | 350 | 11 | 7 | 0 | 7 | 0 |
| toowani-auth | 93 | 3 | 90 | 0 | 93 | 20 | 2 | 0 | 2 | 0 |
| **합계** | 698 | 24 | 653 | 21 | 534 | 174 | 30 | 3 | 24 | 3 |

\* 미참조: 설치돼 있지만 직접 의존성에서 도달하지 않음 (venv의 pip/setuptools, 이전 설치 잔여물 등)

## 서비스 간 공유 패키지 상위 10
| # | 생태계 | 패키지 | 서비스 수 | 서비스 | 버전 |
|---|---|---|---|---|---|
| 1 | npm | @emnapi/runtime | 3 | class-toowani, podcast4life, toowani-auth | 1.10.0, 1.11.3 |
| 2 | npm | @jridgewell/resolve-uri | 3 | class-toowani, podcast4life, toowani-auth | 3.1.2 |
| 3 | npm | @jridgewell/sourcemap-codec | 3 | class-toowani, podcast4life, toowani-auth | 1.6.0 |
| 4 | npm | @jridgewell/trace-mapping | 3 | class-toowani, podcast4life, toowani-auth | 0.3.31, 0.3.9 |
| 5 | npm | detect-libc | 3 | class-toowani, podcast4life, toowani-auth | 2.1.2 |
| 6 | npm | semver | 3 | class-toowani, podcast4life, toowani-auth | 6.3.1, 7.8.5 |
| 7 | npm | supports-color | 3 | class-toowani, podcast4life, toowani-auth | 10.2.2, 7.2.0, 8.1.1 |
| 8 | npm | tslib | 3 | class-toowani, podcast4life, toowani-auth | 2.8.1 |
| 9 | npm | ws | 3 | class-toowani, podcast4life, toowani-auth | 8.21.0, 8.21.3 |
| 10 | pypi | certifi | 3 | lms-watch, podcast4life, wani-briefing-routine | 2026.10.23, 2026.7.22 |

## 심각도 단독 정렬 vs 종합 점수 정렬 (Top 10)
| # | 심각도(CVSS) 정렬 | CVSS | KEV | EPSS | →종합순위 | 종합 점수 정렬 | 점수 | CVSS | KEV | EPSS | →심각도순위 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | podcast4life · pillow@11.3.0 · CVE-2026-96639 | 9.8 |  | 0.0066 | 9 | podcast4life · urllib3@1.26.20 · CVE-2026-21441 | 1.53 | 7.5 |  | 0.0292 | 45 |
| 2 | podcast4life · pillow@11.3.0 · CVE-2026-112393 | 9.8 |  | 0.0102 | 6 | podcast4life · setuptools@58.0.4 · CVE-2024-6345 | 1.19 | 8.8 |  | 0.0194 | 18 |
| 3 | podcast4life · pillow@11.3.0 · CVE-2026-112398 | 9.8 |  | 0.0070 | 8 | podcast4life · setuptools@58.0.4 · CVE-2022-40897 | 1.09 | 5.9 |  | 0.0263 | 139 |
| 4 | podcast4life · pillow@11.3.0 · CVE-2026-112403 | 9.8 |  | 0.0095 | 7 | podcast4life · setuptools@58.0.4 · CVE-2025-47273 | 0.98 | 8.8 |  | 0.0159 | 19 |
| 5 | podcast4life · pillow@11.3.0 · CVE-2026-112900 | 9.8 |  | 0.0130 | 5 | podcast4life · pillow@11.3.0 · CVE-2026-112900 | 0.89 | 9.8 |  | 0.0130 | 5 |
| 6 | podcast4life · anyio@4.12.1 · CVE-2026-63374 | 9.3 |  | 0.0029 | 78 | podcast4life · pillow@11.3.0 · CVE-2026-112393 | 0.70 | 9.8 |  | 0.0102 | 2 |
| 7 | podcast4life · pillow@11.3.0 · CVE-2026-54058 | 9.1 |  | 0.0052 | 16 | podcast4life · pillow@11.3.0 · CVE-2026-112403 | 0.65 | 9.8 |  | 0.0095 | 4 |
| 8 | podcast4life · undici@7.29.0 · CVE-2026-84961 | 9.1 |  | 0.0018 | 159 | podcast4life · pillow@11.3.0 · CVE-2026-112398 | 0.48 | 9.8 |  | 0.0070 | 3 |
| 9 | toowani-auth · undici@7.29.0 · CVE-2026-84961 | 9.1 |  | 0.0018 | 137 | podcast4life · pillow@11.3.0 · CVE-2026-96639 | 0.45 | 9.8 |  | 0.0066 | 1 |
| 10 | podcast4life · undici@7.29.0 · CVE-2026-109383 | 9.1 |  | 0.0018 | 156 | podcast4life · pillow@11.3.0 · CVE-2026-112396 | 0.36 | 7.5 |  | 0.0069 | 90 |

| 지표 | 심각도 Top10 | 종합 Top10 |
|---|---|---|
| 겹치는 항목 | 5 | 5 |
| KEV 포함 | 0 | 0 |
| 인터넷 노출 서비스 | 10 | 10 |
| EPSS 보유 / 정보 부족(prior) | 10 / 0 | 10 / 0 |
| 평균 EPSS (보유 행만) | 0.006 | 0.0144 |
| 최대 EPSS | 0.013 | 0.0292 |
| 수정 버전 있음 | 10 | 10 |
| 관련 서비스 수 | 2 | 1 |

KEV 해당 행: 0
EPSS 보유 CVE: 141/145 · OSV 권고문 캐시: 150/150 · OSV alias로 CVE 보강: 3행
