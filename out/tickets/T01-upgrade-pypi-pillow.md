# [T01] 업그레이드 pypi:pillow 11.3.0 → 13.0.0

- 조치: **업그레이드 pypi:pillow 11.3.0 → 13.0.0**
- 대상 서비스: podcast4life
- 담당팀: 미디어서비스팀
- 위험 감소량: 11.545 (전체 잔여 위험 25.481 중 45.3%, 앞선 티켓과 겹치는 행 제외)
- 호환성 위험: 메이저 버전 변경(11.3.0 → 13.0.0) — 변경 내역·테스트 확인 필요 · Python 런타임 업그레이드 필요(Python 3.9.6 → >=3.11)
- 비고: podcast4life: 목표 버전은 Python >=3.11 필요, 서비스는 3.9.6 → 런타임 업그레이드 필요

## 요약
Pillow 13.0.0 버전으로 업그레이드하면 CVE‑2026‑112900, CVE‑2026‑112393, CVE‑2026‑112398, CVE‑2026‑96639, CVE‑2026‑112396, CVE‑2026‑40192, CVE‑2026‑112401, CVE‑2026‑54058, CVE‑2026‑112394, CVE‑2026‑96640, CVE‑2026‑112400, CVE‑2026‑112402, CVE‑2026‑112894, CVE‑2026‑112390, CVE‑2026‑112391, CVE‑2026‑112397, CVE‑2026‑112406, CVE‑2026‑112891, CVE‑2026‑112893, CVE‑2026‑96778 등 20개 이상의 취약점을 해결합니다.

## 영향 (권고문 기준, 조건 충족 시)
조건이 충족될 경우 공격자는 Pillow를 통해 RCE, DoS, 메모리 손상, 무한 루프, 리소스 고갈 등 다양한 공격을 수행할 수 있습니다. 예를 들어, CVE‑2026‑112900이 활성화된 경우 Ghostscript 호출에서 인자 주입을 통해 원격 코드 실행이 가능하며, CVE‑2026‑112393, CVE‑2026‑112398, CVE‑2026‑112396, CVE‑2026‑112402, CVE‑2026‑112894, CVE‑2026‑112406 등은 버퍼 오버플로우·무한 루프·자원 고갈을 유발할 수 있습니다. 현재 일부 취약점은 추가 검토 중입니다.

## 작업 단계
1. Python 런타임 업그레이드 (Python 3.9.6 → >=3.11)
2. requirements.txt 또는 Pipfile에 Pillow==13.0.0 으로 버전을 지정합니다.
3. 의존성 설치 후 단위 테스트를 실행하여 기능이 정상 동작하는지 확인합니다.
4. 테스트가 통과하면 배포 파이프라인에 반영하고 프로덕션 환경에 배포합니다.
5. 재스캔(`python -m sca run`) 후 위 취약점이 `out/ranked.csv`에서 사라졌는지 확인

## 해소 취약점 (42건)
| 취약점 | 서비스 | 패키지 | CVSS | EPSS | KEV | 판정(규칙) | 점수 |
|---|---|---|---|---|---|---|---|
| CVE-2026-112900 | podcast4life | pillow@11.3.0 | 9.8 | 0.0130 |  | uncertain (input_trust_needs_human) | 0.894 |
| CVE-2026-112393 | podcast4life | pillow@11.3.0 | 9.8 | 0.0102 |  | uncertain (reachable_via_dependency) | 0.699 |
| CVE-2026-112398 | podcast4life | pillow@11.3.0 | 9.8 | 0.0070 |  | uncertain (input_trust_needs_human) | 0.477 |
| CVE-2026-96639 | podcast4life | pillow@11.3.0 | 9.8 | 0.0066 |  | uncertain (input_trust_needs_human) | 0.452 |
| CVE-2026-112396 | podcast4life | pillow@11.3.0 | 7.5 | 0.0069 |  | uncertain (input_trust_needs_human) | 0.364 |
| CVE-2026-40192 | podcast4life | pillow@11.3.0 | 7.5 | 0.0067 |  | uncertain (reachable_via_dependency) | 0.352 |
| CVE-2026-112401 | podcast4life | pillow@11.3.0 | 7.5 | 0.0065 |  | uncertain (input_trust_needs_human) | 0.341 |
| CVE-2026-54058 | podcast4life | pillow@11.3.0 | 9.1 | 0.0052 |  | uncertain (reachable_via_dependency) | 0.332 |
| CVE-2026-112394 | podcast4life | pillow@11.3.0 | 8.2 | 0.0056 |  | uncertain (reachable_via_dependency) | 0.319 |
| CVE-2026-96640 | podcast4life | pillow@11.3.0 | 7.5 | 0.0060 |  | uncertain (input_trust_needs_human) | 0.317 |
| CVE-2026-112400 | podcast4life | pillow@11.3.0 | 7.5 | 0.0059 |  | uncertain (condition_not_checkable) | 0.312 |
| CVE-2026-112402 | podcast4life | pillow@11.3.0 | 7.5 | 0.0059 |  | uncertain (reachable_via_dependency) | 0.312 |
| CVE-2026-112894 | podcast4life | pillow@11.3.0 | 7.5 | 0.0059 |  | affected (condition_symbol_in_code) | 0.312 |
| CVE-2026-112390 | podcast4life | pillow@11.3.0 | 7.5 | 0.0059 |  | uncertain (reachable_via_dependency) | 0.311 |
| CVE-2026-112391 | podcast4life | pillow@11.3.0 | 7.5 | 0.0058 |  | uncertain (input_trust_needs_human) | 0.305 |
| CVE-2026-112397 | podcast4life | pillow@11.3.0 | 7.5 | 0.0057 |  | uncertain (input_trust_needs_human) | 0.301 |
| CVE-2026-112406 | podcast4life | pillow@11.3.0 | 7.5 | 0.0057 |  | uncertain (input_trust_needs_human) | 0.301 |
| CVE-2026-112891 | podcast4life | pillow@11.3.0 | 7.5 | 0.0055 |  | uncertain (input_trust_needs_human) | 0.288 |
| CVE-2026-112893 | podcast4life | pillow@11.3.0 | 7.5 | 0.0055 |  | uncertain (input_trust_needs_human) | 0.288 |
| CVE-2026-96778 | podcast4life | pillow@11.3.0 | 8.8 | 0.0045 |  | uncertain (input_trust_needs_human) | 0.280 |
| CVE-2026-112901 | podcast4life | pillow@11.3.0 | 7.5 | 0.0053 |  | uncertain (input_trust_needs_human) | 0.279 |
| CVE-2026-55380 | podcast4life | pillow@11.3.0 | 7.5 | 0.0052 |  | affected (condition_symbol_in_code) | 0.272 |
| CVE-2026-112902 | podcast4life | pillow@11.3.0 | 8.8 | - |  | affected (condition_symbol_in_code) | 0.249 |
| CVE-2026-112896 | podcast4life | pillow@11.3.0 | 7.1 | 0.0047 |  | uncertain (input_trust_needs_human) | 0.236 |
| GHSA-78g4-xqwv-q3g8 | podcast4life | pillow@11.3.0 | 8.1 | - |  | uncertain (input_trust_needs_human) | 0.230 |
| CVE-2026-54060 | podcast4life | pillow@11.3.0 | 7.5 | 0.0042 |  | uncertain (input_trust_needs_human) | 0.219 |
| CVE-2026-25990 | podcast4life | pillow@11.3.0 | 7.5 | 0.0041 |  | uncertain (condition_not_checkable) | 0.215 |
| CVE-2026-112897 | podcast4life | pillow@11.3.0 | 6.2 | 0.0048 |  | uncertain (input_trust_needs_human) | 0.208 |
| CVE-2026-59199 | podcast4life | pillow@11.3.0 | 7.5 | 0.0039 |  | uncertain (input_trust_needs_human) | 0.202 |
| CVE-2026-59204 | podcast4life | pillow@11.3.0 | 7.5 | 0.0039 |  | uncertain (input_trust_needs_human) | 0.202 |
| CVE-2026-59205 | podcast4life | pillow@11.3.0 | 7.5 | 0.0039 |  | uncertain (input_trust_needs_human) | 0.202 |
| CVE-2026-112899 | podcast4life | pillow@11.3.0 | 6.9 | - |  | uncertain (input_trust_needs_human) | 0.196 |
| CVE-2026-96637 | podcast4life | pillow@11.3.0 | 6.5 | 0.0037 |  | uncertain (input_trust_needs_human) | 0.170 |
| CVE-2026-96643 | podcast4life | pillow@11.3.0 | 6.5 | 0.0037 |  | uncertain (reachable_via_dependency) | 0.170 |
| CVE-2026-59198 | podcast4life | pillow@11.3.0 | 7.5 | 0.0031 |  | uncertain (input_trust_needs_human) | 0.164 |
| CVE-2026-96636 | podcast4life | pillow@11.3.0 | 6.5 | 0.0034 |  | affected (condition_symbol_in_code) | 0.157 |
| CVE-2026-96638 | podcast4life | pillow@11.3.0 | 6.5 | 0.0034 |  | uncertain (reachable_via_dependency) | 0.157 |
| CVE-2026-96641 | podcast4life | pillow@11.3.0 | 6.5 | 0.0034 |  | uncertain (input_trust_needs_human) | 0.157 |
| CVE-2026-112898 | podcast4life | pillow@11.3.0 | 5.3 | 0.0034 |  | uncertain (reachable_via_dependency) | 0.126 |
| CVE-2026-42311 | podcast4life | pillow@11.3.0 | 7.8 | 0.0015 |  | uncertain (condition_not_checkable) | 0.082 |
| CVE-2026-42309 | podcast4life | pillow@11.3.0 | 5.5 | 0.0013 |  | uncertain (input_trust_needs_human) | 0.051 |
| CVE-2026-42308 | podcast4life | pillow@11.3.0 | 5.5 | 0.0011 |  | uncertain (condition_not_checkable) | 0.044 |

## 근거
- **CVE-2026-112900** · podcast4life
  - 권고문: "PIL.EpsImagePlugin.Ghostscript() builds the Ghostscript command line using the input file path (fp.name) **without sanitization**, placing it at `-f <infile>`."
  - 코드 검색: pillow 직접 import 35곳
  - 코드: `pipeline/ahn_tag_headaware.py:49`
  - 코드: `pipeline/ahn_tag_headaware.py:58`
  - 코드: `pipeline/ahn_tag_headaware.py:95`
  - 코드: `pipeline/audit_no_box_v7.py:52`
  - 코드: `pipeline/audit_thumb_v7.py:11`
- **CVE-2026-112393** · podcast4life
  - 권고문: "Pillow can write attacker‑chosen data past the end of a heap buffer when it saves a TIFF image to an in‑memory destination such as io.BytesIO rather than to a file."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.save', 'io.BytesIO']: 서비스 코드 10곳, 의존 패키지 52곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:358`
  - 코드: `pipeline/batch_thumbnails_overnight.py:78`
  - 코드: `pipeline/batch_thumbnails_overnight.py:108`
  - 코드: `pipeline/build_cover.py:145`
  - 코드: `pipeline/build_ep3_thumbnails.py:140`
- **CVE-2026-112398** · podcast4life
  - 권고문: "The file is recognized by content (the OLE2 magic), not by extension, so any service that opens or thumbnails untrusted uploads with the optional olefile dependency installed is reachable with no user interaction."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.open']: 서비스 코드 5곳, 의존 패키지 23곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/ahn_tag_headaware.py:49`
  - 코드: `pipeline/ahn_tag_headaware.py:58`
  - 코드: `pipeline/ahn_tag_headaware.py:95`
  - 코드: `pipeline/audit_no_box_v7.py:52`
  - 코드: `pipeline/audit_thumb_v7.py:11`
- **CVE-2026-96639** · podcast4life
  - 권고문: "If frame 0 allocates storage for a narrow mode such as L, and a later frame of the same dimensions switches to a wider mode such as RGB or CMYK, Pillow may decode wider pixels into the stale narrow native buffer."
  - 코드 검색: pillow 직접 import 35곳; API ['ImageSequence.Iterator', 'frame.load']: 서비스 코드 1곳, 의존 패키지 27곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/audit_thumb_v7.py:10`
- **CVE-2026-112396** · podcast4life
  - 권고문: "Saving an image as TIFF to an in‑memory buffer can trigger a heap use‑after‑free if libtiff rejects a tag at encode time."
  - 코드 검색: pillow 직접 import 35곳
  - 코드: `pipeline/batch_shorts_episode.py:358`
  - 코드: `pipeline/batch_thumbnails_overnight.py:78`
  - 코드: `pipeline/batch_thumbnails_overnight.py:108`
  - 코드: `pipeline/build_cover.py:145`
  - 코드: `pipeline/build_ep3_thumbnails.py:140`
- **CVE-2026-40192** · podcast4life
  - 권고문: "Pillow did not limit the amount of GZIP-compressed data read when decoding a FITS image, making it vulnerable to decompression bomb attacks."
  - 코드 검색: pillow 직접 import 35곳
- **CVE-2026-112401** · podcast4life
  - 권고문: "Opening a crafted GIF file with `Image.open()` takes time that grows with the square of the file's size, so anyone who can submit an image to a service that uses Pillow can keep one worker busy at full processor load for a long time with a small file."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.open']: 서비스 코드 5곳, 의존 패키지 23곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/ahn_tag_headaware.py:49`
  - 코드: `pipeline/ahn_tag_headaware.py:58`
  - 코드: `pipeline/ahn_tag_headaware.py:95`
  - 코드: `pipeline/audit_no_box_v7.py:52`
  - 코드: `pipeline/audit_thumb_v7.py:11`
- **CVE-2026-54058** · podcast4life
  - 권고문: "When Pillow loads an uncompressed image whose tile uses the `raw` codec and a mode in `Image._MAPMODES`, and the image was opened **from a filename**, it memory‑maps the file and builds the image's row pointers directly into the mapping via `PyImaging_MapBuffer`."
  - 코드 검색: pillow 직접 import 35곳; API ['McIdasImagePlugin._open']: 서비스 코드 0곳, 의존 패키지 5곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
- **CVE-2026-112394** · podcast4life
  - 권고문: "Image.frombytes("P", (1, 4), array("B", [0] * 4), "raw", "P;2L")"
  - 코드 검색: pillow 직접 import 35곳
- **CVE-2026-96640** · podcast4life
  - 권고문: "An attacker who can supply an existing PDF to an application that appends an image with `Image.save(..., format="PDF", append=True)` can provide a malformed `/Pages` tree where each level repeats the same child `/Pages` reference in `/Kids`."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.save']: 서비스 코드 5곳, 의존 패키지 33곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:358`
  - 코드: `pipeline/batch_thumbnails_overnight.py:78`
  - 코드: `pipeline/batch_thumbnails_overnight.py:108`
  - 코드: `pipeline/build_cover.py:145`
  - 코드: `pipeline/build_ep3_thumbnails.py:140`
- **CVE-2026-112400** · podcast4life
  - 권고문: "An attacker who can upload a GIF to such a service can exhaust its memory: the process either fails with an out-of-memory error after committing gigabytes, or is killed by the operating system."
  - 코드 검색: pillow 직접 import 35곳
- **CVE-2026-112402** · podcast4life
  - 권고문: "Anyone who can choose the output size of Image.transform() can trigger it, but only on a worker with a memory limit (a common hardening for image workers) or a 32‑bit process."
  - 코드 검색: pillow 직접 import 35곳
- **CVE-2026-112894** · podcast4life
  - 권고문: "The precondition is that the application calls `im.save(..., "PDF", save_all=True)` on the attacker's file; `Image.open()` and `load()` alone do not reach this code."
  - 코드 검색: pillow 직접 import 35곳; API ['PDF', 'save', 'save_all']: 서비스 코드 5곳, 의존 패키지 48곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:358`
  - 코드: `pipeline/batch_thumbnails_overnight.py:78`
  - 코드: `pipeline/batch_thumbnails_overnight.py:108`
  - 코드: `pipeline/build_cover.py:145`
  - 코드: `pipeline/build_ep3_thumbnails.py:140`
- **CVE-2026-112390** · podcast4life
  - 권고문: "This only affects installations that have the optional `olefile` package."
  - 코드 검색: pillow 직접 import 35곳; API ['im.n_frames']: 서비스 코드 0곳, 의존 패키지 5곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
- **CVE-2026-112391** · podcast4life
  - 권고문: "It is reachable through `Image.save(im, fp=<pdf>, format="PDF", append=True)` when the existing PDF file is attacker-controlled."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.save', 'append', 'format']: 서비스 코드 15곳, 의존 패키지 105곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:358`
  - 코드: `pipeline/batch_thumbnails_overnight.py:78`
  - 코드: `pipeline/batch_thumbnails_overnight.py:108`
  - 코드: `pipeline/build_cover.py:145`
  - 코드: `pipeline/build_ep3_thumbnails.py:140`
- **CVE-2026-112397** · podcast4life
  - 권고문: "A PPM or PGM file can declare a width of 0, which Pillow accepts, producing an image of size `(0, N)`."
  - 코드 검색: pillow 직접 import 35곳; API ['ImageMorph.MorphOp.apply']: 서비스 코드 4곳, 의존 패키지 15곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/recapture_feedback.py:8`
  - 코드: `pipeline/recapture_feedback.py:11`
  - 코드: `pipeline/recapture_feedback.py:233`
  - 코드: `pipeline/recapture_feedback.py:279`
- **CVE-2026-112406** · podcast4life
  - 권고문: "Anyone who can supply the existing PDF to an application that calls `im.save(fp, "PDF", append=True)` (or `save_all=True, append=True`) can tie up that worker indefinitely."
  - 코드 검색: pillow 직접 import 35곳; API ['PdfImagePlugin._save', 'save']: 서비스 코드 5곳, 의존 패키지 37곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:358`
  - 코드: `pipeline/batch_thumbnails_overnight.py:78`
  - 코드: `pipeline/batch_thumbnails_overnight.py:108`
  - 코드: `pipeline/build_cover.py:145`
  - 코드: `pipeline/build_ep3_thumbnails.py:140`
- **CVE-2026-112891** · podcast4life
  - 권고문: "On Pillow 12.3.0 and upstream `main` (`ad277e2761b489681e71b51e91367d46b0ceabb9`), a GIF with a long comment makes `_get_global_header()` copy portions of the comment repeatedly when saving, including comments carried over from untrusted images."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.save']: 서비스 코드 5곳, 의존 패키지 33곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:358`
  - 코드: `pipeline/batch_thumbnails_overnight.py:78`
  - 코드: `pipeline/batch_thumbnails_overnight.py:108`
  - 코드: `pipeline/build_cover.py:145`
  - 코드: `pipeline/build_ep3_thumbnails.py:140`
- **CVE-2026-112893** · podcast4life
  - 권고문: "Applications that draw text with `stroke_width != 0` using fonts loaded from untrusted bytes can hit an invalid or double free."
  - 코드 검색: pillow 직접 import 35곳; API ['ImageDraw.text', 'stroke_width']: 서비스 코드 15곳, 의존 패키지 32곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:87`
  - 코드: `pipeline/batch_shorts_episode.py:349`
  - 코드: `pipeline/batch_shorts_episode.py:371`
  - 코드: `pipeline/batch_shorts_episode.py:472`
  - 코드: `pipeline/batch_shorts_episode.py:473`
- **CVE-2026-96778** · podcast4life
  - 권고문: "Triggering it takes only a valid JPEG (or PNG) carrying that profile and any comment, passed through Image.open() and then im.save(..., "JPEG", icc_profile=im.info.get("icc_profile"))"
  - 코드 검색: pillow 직접 import 35곳; API ['Image.save', 'icc_profile']: 서비스 코드 5곳, 의존 패키지 38곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:358`
  - 코드: `pipeline/batch_thumbnails_overnight.py:78`
  - 코드: `pipeline/batch_thumbnails_overnight.py:108`
  - 코드: `pipeline/build_cover.py:145`
  - 코드: `pipeline/build_ep3_thumbnails.py:140`
- **CVE-2026-112901** · podcast4life
  - 권고문: "Anyone who can hand bytes to an application that opens images with Pillow's default settings can trigger this, for example through an upload form, a thumbnailer, or a service that checks whether a blob is an image."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.open']: 서비스 코드 5곳, 의존 패키지 23곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/ahn_tag_headaware.py:49`
  - 코드: `pipeline/ahn_tag_headaware.py:58`
  - 코드: `pipeline/ahn_tag_headaware.py:95`
  - 코드: `pipeline/audit_no_box_v7.py:52`
  - 코드: `pipeline/audit_thumb_v7.py:11`
- **CVE-2026-55380** · podcast4life
  - 권고문: "Any service that calls `PIL.GdImageFile.open(user_file)` followed by `.load()` (or any lazy-load trigger) is vulnerable."
  - 코드 검색: pillow 직접 import 35곳; API ['GdImageFile.open', 'Image.load']: 서비스 코드 6곳, 의존 패키지 57곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/ahn_tag_headaware.py:49`
  - 코드: `pipeline/ahn_tag_headaware.py:58`
  - 코드: `pipeline/ahn_tag_headaware.py:95`
  - 코드: `pipeline/audit_no_box_v7.py:52`
  - 코드: `pipeline/audit_thumb_v7.py:10`
- **CVE-2026-112902** · podcast4life
  - 권고문: "The trigger is an ordinary `Image.open()` followed by a bare `im.save(fp, "TIFF")`."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.save', 'TIFF', 'im.save']: 서비스 코드 10곳, 의존 패키지 75곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:358`
  - 코드: `pipeline/batch_thumbnails_overnight.py:78`
  - 코드: `pipeline/batch_thumbnails_overnight.py:108`
  - 코드: `pipeline/build_cover.py:145`
  - 코드: `pipeline/build_ep3_thumbnails.py:140`
- **CVE-2026-112896** · podcast4life
  - 권고문: "An application must accept the input, retain the relevant TIFF metadata, and invoke the libtiff-backed TIFF save path."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.open', 'format="TIFF', 'image.save']: 서비스 코드 10곳, 의존 패키지 55곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/ahn_tag_headaware.py:49`
  - 코드: `pipeline/ahn_tag_headaware.py:58`
  - 코드: `pipeline/ahn_tag_headaware.py:95`
  - 코드: `pipeline/audit_no_box_v7.py:52`
  - 코드: `pipeline/audit_thumb_v7.py:11`
- **GHSA-78g4-xqwv-q3g8** · podcast4life
  - 권고문: "It is reachable from Image.open(fp); im.load() with default settings."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.open', 'im.load']: 서비스 코드 6곳, 의존 패키지 45곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/ahn_tag_headaware.py:49`
  - 코드: `pipeline/ahn_tag_headaware.py:58`
  - 코드: `pipeline/ahn_tag_headaware.py:95`
  - 코드: `pipeline/audit_no_box_v7.py:52`
  - 코드: `pipeline/audit_thumb_v7.py:11`
- **CVE-2026-54060** · podcast4life
  - 권고문: "FontFile.compile() assembles per‑glyph images into a single combined bitmap using Image.new("1", (xsize, ysize)) without calling Image._decompression_bomb_check()"
  - 코드 검색: pillow 직접 import 35곳; API ['BdfFontFile', 'PcfFontFile', 'save', 'to_imagefont']: 서비스 코드 10곳, 의존 패키지 47곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:358`
  - 코드: `pipeline/batch_thumbnails_overnight.py:78`
  - 코드: `pipeline/batch_thumbnails_overnight.py:108`
  - 코드: `pipeline/build_cover.py:145`
  - 코드: `pipeline/build_ep3_thumbnails.py:140`
- **CVE-2026-25990** · podcast4life
  - 권고문: "An out-of-bounds write may be triggered when loading a specially crafted PSD image."
  - 코드 검색: pillow 직접 import 35곳
- **CVE-2026-112897** · podcast4life
  - 권고문: "Anyone who can get an application to open their image, and can see something produced from its pixels (a thumbnail, a preview, a converted copy), can read heap memory that the process had previously used and freed."
  - 코드 검색: pillow 직접 import 35곳
  - 코드: `pipeline/ahn_tag_headaware.py:49`
  - 코드: `pipeline/ahn_tag_headaware.py:58`
  - 코드: `pipeline/ahn_tag_headaware.py:95`
  - 코드: `pipeline/audit_no_box_v7.py:52`
  - 코드: `pipeline/audit_thumb_v7.py:11`
- **CVE-2026-59199** · podcast4life
  - 권고문: "Pillow's public image coordinate APIs can trigger a native heap out-of-bounds write when given coordinates near the signed 32-bit integer limits."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.alpha_composite', 'Image.crop', 'Image.paste']: 서비스 코드 15곳, 의존 패키지 5곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:357`
  - 코드: `pipeline/build_ep3_thumbnails.py:197`
  - 코드: `pipeline/build_thumbnail_p4l.py:92`
  - 코드: `pipeline/build_thumbnail_p4l.py:283`
  - 코드: `pipeline/build_thumbnail_p4l.py:290`
- **CVE-2026-59204** · podcast4life
  - 권고문: "A crafted tiled JPEG2000 file can therefore force substantially higher transient memory usage and trigger out-of-memory failures during decoding."
  - 코드 검색: pillow 직접 import 35곳
  - 코드: `pipeline/ahn_tag_headaware.py:49`
  - 코드: `pipeline/ahn_tag_headaware.py:58`
  - 코드: `pipeline/ahn_tag_headaware.py:95`
  - 코드: `pipeline/audit_no_box_v7.py:52`
  - 코드: `pipeline/audit_thumb_v7.py:11`
- **CVE-2026-59205** · podcast4life
  - 권고문: "Applications are impacted if untrusted users can control ImageCms transform parameters and/or provide the output image object passed to ImageCmsTransform.apply()."
  - 코드 검색: pillow 직접 import 35곳; API ['ImageCmsTransform.apply']: 서비스 코드 4곳, 의존 패키지 15곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/recapture_feedback.py:8`
  - 코드: `pipeline/recapture_feedback.py:11`
  - 코드: `pipeline/recapture_feedback.py:233`
  - 코드: `pipeline/recapture_feedback.py:279`
- **CVE-2026-112899** · podcast4life
  - 권고문: "When an application opens an untrusted Encapsulated PostScript file and asks Pillow to render it at a larger scale, Pillow has Ghostscript produce an image several times bigger than Pillow's configured size limit allows."
  - 코드 검색: pillow 직접 import 35곳; API ['EpsImageFile.load']: 서비스 코드 1곳, 의존 패키지 26곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/audit_thumb_v7.py:10`
- **CVE-2026-96637** · podcast4life
  - 권고문: "SpiderImagePlugin's seek() bypasses the decompression bomb check, allowing a tiny (<1KB) crafted SPIDER stack file to trigger a multi-gigabyte allocation on im.load()."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.open', 'im.seek']: 서비스 코드 7곳, 의존 패키지 34곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/ahn_tag_headaware.py:49`
  - 코드: `pipeline/ahn_tag_headaware.py:58`
  - 코드: `pipeline/ahn_tag_headaware.py:95`
  - 코드: `pipeline/audit_no_box_v7.py:52`
  - 코드: `pipeline/audit_thumb_v7.py:11`
- **CVE-2026-96643** · podcast4life
  - 권고문: "A PNG file with a large eXIf chunk full of repeated 6-byte markers makes Pillow's EXIF parser take seconds of CPU instead of milliseconds."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.getexif', 'ImageOps.exif_transpose']: 서비스 코드 0곳, 의존 패키지 3곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
- **CVE-2026-59198** · podcast4life
  - 권고문: "Pillow's TGA RLE encoder reads past its row buffer when saving a mode "1" image."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.save']: 서비스 코드 5곳, 의존 패키지 33곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:358`
  - 코드: `pipeline/batch_thumbnails_overnight.py:78`
  - 코드: `pipeline/batch_thumbnails_overnight.py:108`
  - 코드: `pipeline/build_cover.py:145`
  - 코드: `pipeline/build_ep3_thumbnails.py:140`
- **CVE-2026-96636** · podcast4life
  - 권고문: "MpoImageFile.seek() and DcxImageFile.seek() do not."
  - 코드 검색: pillow 직접 import 35곳; API ['DcxImageFile.seek', 'MpoImageFile.seek']: 서비스 코드 4곳, 의존 패키지 30곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/build_short.py:281`
  - 코드: `pipeline/build_short.py:976`
  - 코드: `pipeline/build_short.py:281`
  - 코드: `pipeline/build_short.py:976`
- **CVE-2026-96638** · podcast4life
  - 권고문: "BmpRleDecoder can be forced to allocate gigabytes of memory from a kilobyte-sized crafted BMP file via unbounded growth in the delta escape and absolute mode branches."
  - 코드 검색: pillow 직접 import 35곳
- **CVE-2026-96641** · podcast4life
  - 권고문: "The directly confirmed impact is width semantic integrity violation: getlength() and boundary calculations based on getsize() may return a huge positive value, while the true mathematical width is negative."
  - 코드 검색: pillow 직접 import 35곳; API ['getbbox', 'getlength', 'getmask', 'getsize']: 서비스 코드 7곳, 의존 패키지 5곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/resegment_captions.py:64`
  - 코드: `pipeline/resegment_captions.py:88`
  - 코드: `pipeline/resegment_captions.py:96`
  - 코드: `pipeline/resegment_captions_v2.py:67`
  - 코드: `pipeline/resegment_captions_v2.py:113`
- **CVE-2026-112898** · podcast4life
  - 권고문: "When an application lets a user supply the palette image for Pillow's Image.quantize(palette=...), the user can get back 512 bytes of the server process's stack memory in the pixels of the returned image."
  - 코드 검색: pillow 직접 import 35곳; API ['Image.quantize']: 서비스 코드 10곳, 의존 패키지 49곳 · 검색 범위: 서비스 코드(pillow import 파일 33개); huggingface-hub; imageio; matplotlib; networkx; pymatting; rembg; scikit-image; scikit-learn; torchmetrics; fonttools; torch; pytorch-metric-learning
  - 코드: `pipeline/batch_shorts_episode.py:343`
  - 코드: `pipeline/batch_thumbnails_overnight.py:70`
  - 코드: `pipeline/build_ep3_thumbnails.py:194`
  - 코드: `pipeline/build_short.py:415`
  - 코드: `pipeline/build_short.py:425`
- **CVE-2026-42311** · podcast4life
  - 권고문: "Processing a malicious PSD file could lead to memory corruption, potentially resulting in a crash or arbitrary code execution."
  - 코드 검색: pillow 직접 import 35곳
- **CVE-2026-42309** · podcast4life
  - 권고문: "Passing nested lists as coordinates to APIs that accept coordinates such as `ImagePath.Path`, `ImageDraw.ImageDraw.polygon` and `ImageDraw.ImageDraw.line` could cause a heap buffer overflow, as nested lists were recursively unpacked beyond the allocated buffer."
  - 코드 검색: pillow 직접 import 35곳
  - 코드: `pipeline/ahn_tag_headaware.py:21`
  - 코드: `pipeline/ahn_tag_headaware.py:26`
  - 코드: `pipeline/ahn_tag_headaware.py:45`
  - 코드: `pipeline/audit_no_box_v7.py:16`
  - 코드: `pipeline/audit_no_box_v7.py:29`
- **CVE-2026-42308** · podcast4life
  - 권고문: "If a font advances for each glyph by an exceeding large amount, when Pillow keeps track of the current position, it may lead to an integer overflow."
  - 코드 검색: pillow 직접 import 35곳

## 검증 방법
1. 조치 반영 후 `python -m sca run` 재실행 (직전 실행 결과는 `out/history/`에 보관)
2. 위 표의 취약점이 `out/ranked.csv`에서 사라졌는지 확인
3. `--reason fixed`로 기록하면 다음 실행의 재스캔 검증이 해소 여부를 자동 대조

## 승인/기각 기록
판정이 맞으면 approve, 틀리면 reject와 올바른 verdict·사유를 남긴다. 다음 판정에 반영된다.

```
python -m sca feedback add --service podcast4life --package pypi:pillow --vuln <취약점 ID> --decision approve|reject --verdict affected|not_affected|uncertain --reason <not_reachable|platform|dev_only|false_positive|accepted_risk|fixed|confirmed> --note "..."
```

대상 취약점 ID: CVE-2026-25990 CVE-2026-40192 CVE-2026-42308 CVE-2026-42309 CVE-2026-42311 CVE-2026-54058 CVE-2026-54060 CVE-2026-55380 CVE-2026-59198 CVE-2026-59199 CVE-2026-59204 CVE-2026-59205 CVE-2026-96636 CVE-2026-96637 CVE-2026-96638 CVE-2026-96639 CVE-2026-96640 CVE-2026-96641 CVE-2026-96643 CVE-2026-96778 CVE-2026-112390 CVE-2026-112391 CVE-2026-112393 CVE-2026-112394 CVE-2026-112396 CVE-2026-112397 CVE-2026-112398 CVE-2026-112400 CVE-2026-112401 CVE-2026-112402 CVE-2026-112406 CVE-2026-112891 CVE-2026-112893 CVE-2026-112894 CVE-2026-112896 CVE-2026-112897 CVE-2026-112898 CVE-2026-112899 CVE-2026-112900 CVE-2026-112901 CVE-2026-112902 GHSA-78g4-xqwv-q3g8

<sub>서술 생성: cache:gpt-oss:20b@local (공개 권고문 정보만 입력) · 서비스·팀·점수·코드 근거는 코드가 채움</sub>
