# [T03] 업그레이드 pypi:urllib3 1.26.20 → 2.8.0

- 조치: **업그레이드 pypi:urllib3 1.26.20 → 2.8.0**
- 대상 서비스: podcast4life
- 담당팀: 미디어서비스팀
- 위험 감소량: 2.868 (전체 잔여 위험 25.481 중 11.3%, 앞선 티켓과 겹치는 행 제외)
- 호환성 위험: 메이저 버전 변경(1.26.20 → 2.8.0) — 변경 내역·테스트 확인 필요

## 요약
urllib3 패키지를 2.8.0 버전으로 업그레이드하면 CVE-2026-21441, CVE-2025-66418, CVE-2025-66471, CVE-2025-50181, CVE-2026-97689, CVE-2026-44431, CVE-2026-97687에 대한 취약점이 해결됩니다.

## 영향 (권고문 기준, 조건 충족 시)
조건이 충족될 경우, 공격자는 압축 폭탄을 우회하거나 무제한 압축 체인을 이용해 메모리 고갈을 일으키고, 과도하게 압축된 데이터를 통해 서비스 거부를 유발할 수 있습니다. 또한, 재시도 비활성화 시에도 리다이렉트가 발생하거나, TLS 설정이 무시되어 중간자 공격이 가능해질 수 있습니다. 현재 일부 취약점은 추가 검토 중입니다.

## 작업 단계
1. urllib3 의존성을 2.8.0 버전으로 변경합니다.
2. 업그레이드 후 테스트를 실행하여 기능이 정상 동작하는지 확인합니다.
3. 변경 사항을 배포 환경에 반영합니다.
4. 재스캔(`python -m sca run`) 후 위 취약점이 `out/ranked.csv`에서 사라졌는지 확인

## 해소 취약점 (7건)
| 취약점 | 서비스 | 패키지 | CVSS | EPSS | KEV | 판정(규칙) | 점수 |
|---|---|---|---|---|---|---|---|
| CVE-2026-21441 | podcast4life | urllib3@1.26.20 | 7.5 | 0.0292 |  | uncertain (reachable_via_dependency) | 1.534 |
| CVE-2025-66418 | podcast4life | urllib3@1.26.20 | 7.5 | 0.0068 |  | uncertain (transitive_needs_callgraph) | 0.358 |
| CVE-2025-66471 | podcast4life | urllib3@1.26.20 | 7.5 | 0.0068 |  | uncertain (reachable_via_dependency) | 0.358 |
| CVE-2025-50181 | podcast4life | urllib3@1.26.20 | 6.1 | 0.0047 |  | uncertain (transitive_needs_callgraph) | 0.202 |
| CVE-2026-97689 | podcast4life | urllib3@1.26.20 | 7.5 | 0.0034 |  | uncertain (reachable_via_dependency) | 0.176 |
| CVE-2026-44431 | podcast4life | urllib3@1.26.20 | 5.3 | 0.0033 |  | uncertain (reachable_via_dependency) | 0.123 |
| CVE-2026-97687 | podcast4life | urllib3@1.26.20 | 8.1 | 0.0021 |  | uncertain (reachable_via_dependency) | 0.117 |

## 근거
- **CVE-2026-21441** · podcast4life
  - 권고문: "Applications and libraries using urllib3 version 2.6.2 and earlier to stream content from untrusted sources by setting preload_content=False when they do not disable redirects."
  - 코드 검색: urllib3 직접 import 0곳; API ['stream']: 서비스 코드 0곳, 의존 패키지 12곳 · 검색 범위: 서비스 코드(urllib3 import 파일 0개); botocore; google-auth; requests; torch; google-api-core
- **CVE-2025-66418** · podcast4life
  - 권고문: "unless they disable content decoding explicitly."
  - 코드 검색: urllib3 직접 import 0곳
- **CVE-2025-66471** · podcast4life
  - 권고문: "When streaming a compressed response, urllib3 can perform decoding or decompression based on the HTTP `Content-Encoding` header (e.g., `gzip`, `deflate`, `br`, or `zstd`)."
  - 코드 검색: urllib3 직접 import 0곳; API ['read', 'read1', 'read_chunked', 'readinto', 'stream']: 서비스 코드 0곳, 의존 패키지 29곳 · 검색 범위: 서비스 코드(urllib3 import 파일 0개); botocore; google-auth; requests; torch; google-api-core
- **CVE-2025-50181** · podcast4life
  - 권고문: "Passing `retries` on `PoolManager` instantiation to disable redirects or restrict their number."
  - 코드 검색: urllib3 직접 import 0곳
- **CVE-2026-97689** · podcast4life
  - 권고문: "Applications and libraries using urllib3 versions earlier than 2.8.0 may be affected when streaming a chunked response from untrusted sources."
  - 코드 검색: urllib3 직접 import 0곳
- **CVE-2026-44431** · podcast4life
  - 권고문: "cross-origin redirects followed from the low-level API via `ProxyManager.connection_from_url().urlopen(..., assert_same_host=False)` still forward these sensitive headers."
  - 코드 검색: urllib3 직접 import 0곳; API ['HTTPConnection.urlopen', 'ProxyManager.connection_from_url']: 서비스 코드 0곳, 의존 패키지 16곳 · 검색 범위: 서비스 코드(urllib3 import 파일 0개); botocore; google-auth; requests; torch; google-api-core
- **CVE-2026-97687** · podcast4life
  - 권고문: "In urllib3 versions 1.26.0 through 2.7.0, these configurations were not consistently separated. Depending on the proxy mode, urllib3 could: 1. Ignore proxy_ssl_context and use the target server's SSL context for the TLS connection to an HTTPS forwarding proxy."
  - 코드 검색: urllib3 직접 import 0곳; API ['cert_reqs', 'proxy_ssl_context', 'ssl_context']: 서비스 코드 0곳, 의존 패키지 29곳 · 검색 범위: 서비스 코드(urllib3 import 파일 0개); botocore; google-auth; requests; torch; google-api-core

## 검증 방법
1. 조치 반영 후 `python -m sca run` 재실행 (직전 실행 결과는 `out/history/`에 보관)
2. 위 표의 취약점이 `out/ranked.csv`에서 사라졌는지 확인
3. `--reason fixed`로 기록하면 다음 실행의 재스캔 검증이 해소 여부를 자동 대조

## 승인/기각 기록
판정이 맞으면 approve, 틀리면 reject와 올바른 verdict·사유를 남긴다. 다음 판정에 반영된다.

```
python -m sca feedback add --service podcast4life --package pypi:urllib3 --vuln <취약점 ID> --decision approve|reject --verdict affected|not_affected|uncertain --reason <not_reachable|platform|dev_only|false_positive|accepted_risk|fixed|confirmed> --note "..."
```

대상 취약점 ID: CVE-2025-50181 CVE-2025-66418 CVE-2025-66471 CVE-2026-21441 CVE-2026-44431 CVE-2026-97687 CVE-2026-97689

<sub>서술 생성: cache:gpt-oss:20b@local (공개 권고문 정보만 입력) · 서비스·팀·점수·코드 근거는 코드가 채움</sub>
