# [T02] 업그레이드 pypi:aiohttp 3.13.5 → 3.14.4

- 조치: **업그레이드 pypi:aiohttp 3.13.5 → 3.14.4**
- 대상 서비스: podcast4life
- 담당팀: 미디어서비스팀
- 위험 감소량: 3.729 (전체 잔여 위험 25.481 중 14.6%, 앞선 티켓과 겹치는 행 제외)
- 호환성 위험: Python 런타임 업그레이드 필요(Python 3.9.6 → >=3.10)
- 비고: podcast4life: 목표 버전은 Python >=3.10 필요, 서비스는 3.9.6 → 런타임 업그레이드 필요

## 요약
aiohttp 패키지를 3.14.4 버전으로 업그레이드하고, Python 런타임을 먼저 업그레이드한 뒤 테스트를 수행하여 배포합니다.

## 영향 (권고문 기준, 조건 충족 시)
조건이 충족될 경우, 공격자는 HTTP 파서 버그를 이용해 무제한 메모리 사용, 파일 디스크립터 고갈, 요청 스머글링, 쿠키 스코프 탈취 등 다양한 공격을 수행할 수 있습니다. 현재 일부 취약점은 추가 검토 중입니다.

## 작업 단계
1. Python 런타임 업그레이드 (Python 3.9.6 → >=3.10)
2. aiohttp를 3.14.4 버전으로 의존성 파일을 수정합니다.
3. 업그레이드 후 단위 테스트와 통합 테스트를 실행합니다.
4. 테스트가 통과하면 프로덕션 환경에 배포합니다.
5. 재스캔(`python -m sca run`) 후 위 취약점이 `out/ranked.csv`에서 사라졌는지 확인

## 해소 취약점 (18건)
| 취약점 | 서비스 | 패키지 | CVSS | EPSS | KEV | 판정(규칙) | 점수 |
|---|---|---|---|---|---|---|---|
| CVE-2026-54277 | podcast4life | aiohttp@3.13.5 | 7.5 | 0.0056 |  | uncertain (transitive_needs_callgraph) | 0.296 |
| CVE-2026-50269 | podcast4life | aiohttp@3.13.5 | 7.5 | 0.0053 |  | uncertain (reachable_via_dependency) | 0.280 |
| CVE-2026-69244 | podcast4life | aiohttp@3.13.5 | 7.1 | 0.0053 |  | uncertain (transitive_needs_callgraph) | 0.262 |
| CVE-2026-54273 | podcast4life | aiohttp@3.13.5 | 7.5 | 0.0049 |  | uncertain (transitive_needs_callgraph) | 0.259 |
| CVE-2026-54278 | podcast4life | aiohttp@3.13.5 | 7.5 | 0.0049 |  | uncertain (transitive_needs_callgraph) | 0.259 |
| CVE-2026-54279 | podcast4life | aiohttp@3.13.5 | 7.5 | 0.0049 |  | uncertain (reachable_via_dependency) | 0.259 |
| CVE-2026-59881 | podcast4life | aiohttp@3.13.5 | 6.9 | 0.0052 |  | uncertain (transitive_needs_callgraph) | 0.253 |
| GHSA-2g87-pp6c-29x5 | podcast4life | aiohttp@3.13.5 | 8.7 | - |  | uncertain (transitive_needs_callgraph) | 0.247 |
| CVE-2026-54280 | podcast4life | aiohttp@3.13.5 | 7.5 | 0.0046 |  | uncertain (transitive_needs_callgraph) | 0.241 |
| CVE-2026-111066 | podcast4life | aiohttp@3.13.5 | 8.2 | 0.0041 |  | uncertain (reachable_via_dependency) | 0.236 |
| CVE-2026-111064 | podcast4life | aiohttp@3.13.5 | 8.2 | 0.0040 |  | uncertain (transitive_needs_callgraph) | 0.229 |
| CVE-2026-69243 | podcast4life | aiohttp@3.13.5 | 6.3 | 0.0044 |  | uncertain (transitive_needs_callgraph) | 0.195 |
| CVE-2026-111748 | podcast4life | aiohttp@3.13.5 | 6.3 | 0.0039 |  | uncertain (reachable_via_dependency) | 0.170 |
| CVE-2026-111750 | podcast4life | aiohttp@3.13.5 | 6.3 | 0.0038 |  | uncertain (transitive_needs_callgraph) | 0.169 |
| CVE-2026-54276 | podcast4life | aiohttp@3.13.5 | 6.1 | 0.0031 |  | uncertain (transitive_needs_callgraph) | 0.131 |
| CVE-2026-111063 | podcast4life | aiohttp@3.13.5 | 6.3 | 0.0023 |  | uncertain (transitive_needs_callgraph) | 0.103 |
| CVE-2026-47265 | podcast4life | aiohttp@3.13.5 | 7.5 | 0.0015 |  | uncertain (reachable_via_dependency) | 0.079 |
| CVE-2026-111749 | podcast4life | aiohttp@3.13.5 | 2.3 | 0.0038 |  | uncertain (transitive_needs_callgraph) | 0.062 |

## 근거
- **CVE-2026-54277** · podcast4life
  - 권고문: "If using the optimised C parser (the default in pre-built wheels), then an attacker may be able to send oversized lines through the HTTP parser and use an excessive amount of memory, potentially leading to DoS."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-50269** · podcast4life
  - 권고문: "In the unlikely situation that an application is passing user-controlled strings into `MultipartWriter.append(headers=...)` or `Payload.headers`, then an attacker may be able to modify the request to inject headers or change the contents of the request."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-69244** · podcast4life
  - 권고문: "An out-of-bounds heap read could occur in the C response parser while building an error message for a malformed response."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-54273** · podcast4life
  - 권고문: "No limit was present on the number of pipelined requests that could be queued."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-54278** · podcast4life
  - 권고문: "During cleanup it is possible for a compressed request body to be decompressed into memory in one chunk."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-54279** · podcast4life
  - 권고문: "Host-only cookies that are saved with ``CookieJar.save()`` and then restored later with ``CookieJar.load()`` lose their host-only status."
  - 코드 검색: aiohttp 직접 import 0곳; API ['CookieJar.load', 'CookieJar.save']: 서비스 코드 0곳, 의존 패키지 5곳 · 검색 범위: 서비스 코드(aiohttp import 파일 0개); fsspec; google-auth; huggingface-hub; rembg; google-api-core
- **CVE-2026-59881** · podcast4life
  - 권고문: "The client accepts and decompresses frames with the RSV1 bit set even when the `permessage-deflate` extension was not negotiated."
  - 코드 검색: aiohttp 직접 import 0곳
- **GHSA-2g87-pp6c-29x5** · podcast4life
  - 권고문: "An attacker could cause resource exhaustion through specially crafted requests."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-54280** · podcast4life
  - 권고문: "Payload resources are not closed correctly when a client disconnects in the middle of a write."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-111066** · podcast4life
  - 권고문: "If a handler uses `Request.post()`, it may be possible for an attacker to use an unlimited number of file descriptors, potentially resulting in resource exhaustion."
  - 코드 검색: aiohttp 직접 import 0곳; API ['Request.post']: 서비스 코드 0곳, 의존 패키지 9곳 · 검색 범위: 서비스 코드(aiohttp import 파일 0개); fsspec; google-auth; huggingface-hub; rembg; google-api-core
- **CVE-2026-111064** · podcast4life
  - 권고문: "The keepalive timeout was not used during the initial portion of a request."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-69243** · podcast4life
  - 권고문: "If using the server-side component, it may be possible for an attacker to execute a request smuggling vulnerability using an edge case in the WebSocket upgrade procedure."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-111748** · podcast4life
  - 권고문: "If user code depends on the `Request.scheme` attribute for anything security related, an attacker may be able to circumvent this logic."
  - 코드 검색: aiohttp 직접 import 0곳; API ['Request.scheme']: 서비스 코드 0곳, 의존 패키지 1곳 · 검색 범위: 서비스 코드(aiohttp import 파일 0개); fsspec; google-auth; huggingface-hub; rembg; google-api-core
- **CVE-2026-111750** · podcast4life
  - 권고문: "If users are using the Python parser (`AIOHTTP_NO_EXTENSIONS`, or not a standard wheel installed), then an application may be vulnerable to a request smuggling attack."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-54276** · podcast4life
  - 권고문: "If the client follows a redirect (the default option) to an attacker controlled domain, the attacker may be able to extract the auth digest."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-111063** · podcast4life
  - 권고문: "The Secure attribute was not being enforced for the shared cookie."
  - 코드 검색: aiohttp 직접 import 0곳
- **CVE-2026-47265** · podcast4life
  - 권고문: "Cookies set with the `cookies` parameter on requests are sent after following a cross‑origin redirect."
  - 코드 검색: aiohttp 직접 import 0곳; API ['cookies']: 서비스 코드 0곳, 의존 패키지 5곳 · 검색 범위: 서비스 코드(aiohttp import 파일 0개); fsspec; google-auth; huggingface-hub; rembg; google-api-core
- **CVE-2026-111749** · podcast4life
  - 권고문: "A subdomain can remove the Host-Only flag from an existing cookie to a parent domain."
  - 코드 검색: aiohttp 직접 import 0곳

## 검증 방법
1. 조치 반영 후 `python -m sca run` 재실행 (직전 실행 결과는 `out/history/`에 보관)
2. 위 표의 취약점이 `out/ranked.csv`에서 사라졌는지 확인
3. `--reason fixed`로 기록하면 다음 실행의 재스캔 검증이 해소 여부를 자동 대조

## 승인/기각 기록
판정이 맞으면 approve, 틀리면 reject와 올바른 verdict·사유를 남긴다. 다음 판정에 반영된다.

```
python -m sca feedback add --service podcast4life --package pypi:aiohttp --vuln <취약점 ID> --decision approve|reject --verdict affected|not_affected|uncertain --reason <not_reachable|platform|dev_only|false_positive|accepted_risk|fixed|confirmed> --note "..."
```

대상 취약점 ID: CVE-2026-47265 CVE-2026-50269 CVE-2026-54273 CVE-2026-54276 CVE-2026-54277 CVE-2026-54278 CVE-2026-54279 CVE-2026-54280 CVE-2026-59881 CVE-2026-69243 CVE-2026-69244 CVE-2026-111063 CVE-2026-111064 CVE-2026-111066 CVE-2026-111748 CVE-2026-111749 CVE-2026-111750 GHSA-2g87-pp6c-29x5

<sub>서술 생성: cache:gpt-oss:20b@local (공개 권고문 정보만 입력) · 서비스·팀·점수·코드 근거는 코드가 채움</sub>
