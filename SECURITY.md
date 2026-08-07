# NoteNest 보안 정책

## 취약점 신고

보안 취약점을 발견하셨다면 GitHub 이슈에 공개하지 말고 다음 경로로 알려주세요.

- GitHub Security Advisory: 저장소 상단 **Security → Report a vulnerability**
- 이메일: (본인 이메일 주소를 넣으세요)

가능한 한 다음 정보를 함께 보내주시면 빠르게 대응할 수 있습니다.

- 재현 절차와 예상 결과 / 실제 결과
- 영향받는 버전 (v1.0.0, main 브랜치의 커밋 해시 등)
- PoC (proof-of-concept) 코드 또는 스크린샷
- 신고자 크레딧 표기 여부

**응답 목표**: 영업일 기준 72시간 이내 최초 회신, 유효 취약점은 30일 이내 패치 릴리스를 원칙으로 합니다.

## 지원되는 버전

| 버전 | 보안 업데이트 |
|---|---|
| 최신 릴리스 (main) | ✅ |
| 그 외 | ❌ |

## 위협 모델 (Threat Model)

NoteNest는 **개인 로컬 환경**을 대상으로 하는 텍스트 편집기입니다. 다음을 명시적으로 범위 안/밖으로 구분합니다.

### 범위 안 (In scope)

- 세션 파일(`~/.simple_memo/session.json`)이 조작되었을 때 앱이 임의 파일을 열거나 명령을 실행하지 않도록 방어
- 조작된 파일 경로(UNC, 심볼릭 링크, 널 바이트 삽입)로 인한 예상 밖 파일 접근 차단
- 세션·설정 파일 스키마 검증으로 조작된 값이 앱 상태를 오염시키는 것 방지
- 파일 저장 시 원본 파일 손상 방지 (원자적 저장, 외부 변경 감지)
- 편집기 UI에 표시되는 파일명·폴더명의 HTML 이스케이프
- **암호화 금고(Vault)의 기밀성과 무결성**: 비밀번호 없이 `.enc` 파일 내용을 알아낼 수 없고, 파일이 변조되면 즉시 감지

### 범위 밖 (Out of scope)

- 로컬 관리자 권한을 이미 가진 공격자로부터의 방어 (설계상 불가능)
- 물리적 접근 방어 (전체 디스크 암호화는 OS 수준의 책임)
- 사이드 채널 공격 (전자기, 타이밍 등)
- 사용자가 이미 실행한 악성 실행 파일로부터의 방어

## Notepad++ CVE-2026-48800 / CVE-2026-52886에서 배운 것

Notepad++는 두 가지 유형의 사고를 겪었습니다. 하나는 사용자 설정 파일(`shortcuts.xml`)의 값을 검증 없이 `ShellExecute`에 전달해 임의 코드 실행이 가능했던 사고, 다른 하나는 세션 스냅샷/백업 기능(`session.xml`의 `backupFilePath`)이 접두어(starts_with)만 검사하고 경로를 정규화하지 않아 `..\..\`로 검증을 우회당한 사고입니다. NoteNest는 다음 원칙으로 같은 유형의 사고를 피합니다.

1. **명령 실행 인터페이스를 두지 않는다.** `subprocess`, `os.system`, `ShellExecute` 계열 호출이 코드베이스에 없습니다.
2. **자동 업데이트 서버가 없다.** 업데이트는 GitHub Releases 수동 다운로드 방식입니다.
3. **경로 검증은 정규화 이전 단계에서 수행한다.** `_is_safe_user_path`는 `os.path.normpath()`로 경로를 축약하기 *전에* 원본 문자열의 각 세그먼트를 검사해 `..` 순회를 차단합니다. 정규화 이후에 검사하면 `..`가 이미 사라진 뒤라 검사 자체가 무력화됩니다 — 이것이 CVE-2026-52886이 겪은 정확한 실수입니다.
4. **보조 저장 경로가 주 저장 경로의 보호를 우회하지 않는지 확인한다.** 자동 백업/세션 복원 기능을 만들 때는 "주 저장 경로에만 보안 로직을 넣고 보조 경로는 빠뜨리는" 실수가 반복되기 쉽습니다. NoteNest의 자동 백업(`session.json`)도 초기 구현에서 이 문제가 있었습니다 — 금고(Vault) 파일을 열어 편집하면, 복호화된 평문이 자동 백업 스냅샷에 그대로 남는 문제였습니다. `getCleanTabs()`가 금고 탭 여부와 무관하게 모든 탭의 `content`를 세션에 썼기 때문입니다. 지금은 금고 탭의 `content`/`savedContent`를 세션 저장 시점에 원천적으로 제외하고, 세션 로드 시점에도 `vault: true`인 탭에 content가 남아있으면 강제로 비우는 이중 방어를 적용했습니다. 탭을 다시 열 때는 비밀번호를 입력해 디스크의 `.enc` 파일에서 복호화합니다.

## 알려진 아키텍처 한계 (의도적으로 미해결, 우선순위 근거 포함)

아래는 "패치로 막을 수 있는 버그"가 아니라 현재 아키텍처의 근본적 한계입니다. 각각 왜 지금 손대지 않았는지 이유를 남깁니다.

1. **Vault 파생 키가 프로세스 메모리에 평문으로 상주한다.** 메모리 덤프를 뜰 수 있는 공격자(디버거, 크래시 덤프, 스왑 분석)에게는 방어가 안 됩니다. 완전히 막으려면 Windows CNG의 비내보내기(non-exportable) 키나 TPM 바인딩을 써야 하는데, 이는 `cryptography` 라이브러리를 우회하고 AES-GCM 연산 자체를 CNG API로 옮기는 별도의 암호화 경로가 필요합니다. 개인 로컬 메모 앱이라는 위협 모델에서는 오버스펙이라 판단해 보류합니다. 기업/의료/금융처럼 더 강한 위협 모델이 필요해지면 재검토 대상입니다.

### 해결됨: pywebview RPC 표면이 XSS의 파급력을 키우는 문제

JS가 `window.pywebview.api.*`를 통해 파일 경로를 직접 넘기는 구조라, 코드베이스 어딘가에 XSS가 생기면 일반 웹앱보다 파급력이 컸습니다(파일 시스템 RPC 브릿지 전체 노출). 근본 해결책인 "JS는 탭 ID만 넘기고 Python이 경로를 전부 내부 상태로 관리"하는 전면 재설계는 `memo.py`의 거의 모든 메서드와 `ui_template.py`의 모든 호출부를 함께 바꿔야 해서 리스크가 컸습니다.

대신 **경로 화이트리스트(capability registry)**로 같은 보안 효과를 훨씬 작은 변경 범위로 얻었습니다. Python은 이 세션에서 "신뢰의 원천"을 거친 경로만 기억합니다:
1. OS 네이티브 파일/폴더 선택 대화상자의 결과 (사용자가 직접 클릭)
2. 시작 인자(Windows 파일 연결로 실행된 경로, OS가 넘겨준 값)
3. 세션 파일에서 복원된 경로 (Python 자신이 검증·저장한 값)

이 목록에 없는 경로는 UNC/순회/심볼릭 링크 검사를 모두 통과하더라도 읽기/쓰기가 거부됩니다. 즉 만약 코드 어딘가에 XSS가 생겨 공격자 JS가 임의 경로로 `save_file()`을 호출해도, 그 경로가 이 세션에서 한 번도 신뢰의 원천을 거친 적이 없다면 차단됩니다.

적용 지점: `open_file`, `open_path`, `save_file`, `save_file_as`, `rename_file`, `check_file_states`, `pick_folder_for_vault`, `vault_status`, `vault_create`, `vault_unlock`, `vault_lock`, `vault_rotate_password`, `vault_read_file`, `vault_write_file`.

금고(Vault)는 폴더를 한 번만 대화상자로 선택하고 그 안에 앱이 자동으로 여러 메모를 생성하는 흐름이라, 등록된 금고 폴더 "바로 안"의 파일은 개별 대화상자 없이도 허용됩니다(`_is_known_vault_folder` 예외). 일반 파일은 이 폴더 상속을 받지 않고 파일 자신의 등록 여부만 봅니다.

`tests/test_path_whitelist.py`에 16개 테스트로 검증했습니다 — 등록되지 않은 임의 경로로의 RPC 호출이 실제로 차단되는지, 세 가지 신뢰의 원천을 거친 경로는 정상 허용되는지, 금고 폴더 예외가 올바르게 동작하는지 모두 확인했습니다.

**이 방식의 한계**: 완전한 ID 기반 재설계보다는 방어 강도가 약간 낮습니다 — 예를 들어 이미 한 번 정당하게 연 파일 A의 경로를 화이트리스트가 기억하고 있으므로, 만약 XSS가 발생한 시점에 이미 그 경로가 등록되어 있었다면 그 특정 파일에 대한 재접근 자체는 막지 못합니다(다만 애초에 그 정보는 이미 화면에 노출되어 있었으므로 추가 손실은 제한적입니다). 완전한 ID 기반 격리는 여전히 "언젠가 여유가 있을 때" 검토할 개선 항목으로 남겨둡니다.



### 해결됨: 경로 검증과 파일 열기 사이의 경쟁 조건(TOCTOU, CWE-367)

`_is_safe_user_path`가 심볼릭 링크 여부를 검사하는 시점과 실제로 `open()`을 호출하는 시점 사이에 있던 시간차를 닫았습니다. "검사 후 사용"이 아니라 "사용 자체가 원자적으로 검사를 겸하도록" `_open_no_follow()`를 도입해, 실제 데이터 읽기/쓰기 지점(`_read_text_file`, `_write_text_file`, `vault_read_file`, `vault_write_file`) 전부에 적용했습니다.

- **POSIX(Linux/Mac, 개발 환경)**: `os.open()`에 `O_NOFOLLOW` 플래그를 사용해 커널이 경로 순회와 링크 감지를 한 syscall 안에서 원자적으로 수행합니다. 실제 심볼릭 링크로 재현한 공격 시나리오(사전 검사 통과 → 그 직후 링크로 바꿔치기)로 검증했으며, `tests/test_toctou.py`에 포함되어 있습니다.
- **Windows(배포 대상)**: `CreateFileW`를 `FILE_FLAG_OPEN_REPARSE_POINT`로 호출해 링크 자체에 대한 핸들을 얻고, 별도로 경로를 다시 조회하는 대신 그 핸들에 대해 `GetFileInformationByHandle`로 reparse point 여부를 확인합니다. **다만 이 코드는 아직 실제 Windows 환경에서 실행 검증을 거치지 않았습니다** — 개발이 Linux 샌드박스에서 이루어져 `ctypes`로 작성한 Win32 API 호출부(`CreateFileW`, `GetFileInformationByHandle`)를 실제로 실행해볼 수 없었습니다. Windows에서 처음 빌드·실행할 때 이 경로를 반드시 별도로 확인해야 합니다.



## 알려진 이슈와 수정 이력 (선택적으로 게시)

| 날짜 | 이슈 | 발견 경위 | 수정 |
|---|---|---|---|
| - | 경로 순회(`..\..\`)가 `_is_safe_user_path`를 통과 | Notepad++ CVE-2026-52886 보도를 계기로 자체 코드 재검토 | 정규화 이전 세그먼트 검사 추가 |
| - | 금고 탭의 복호화된 평문이 자동 백업(`session.json`)에 노출 | 위와 동일한 검토 과정에서 발견 | `getCleanTabs()`에서 금고 탭 content 제외 + 세션 로드 시 이중 스트리핑 |
| - | `session.json`(자동 백업 전체)이 평문 저장되어, 저장 안 한 탭의 비밀번호·API 키가 인포스틸러의 반출 대상이 될 수 있음 | Notepad++ 백업 폴더를 노린 인포스틸러 사례 검토 | Windows DPAPI로 세션 파일 전체를 계정 단위 암호화, 레거시 평문 세션 자동 마이그레이션 |
| - | 금고 비밀번호가 유출됐다고 의심되어도 교체할 방법이 없었음(기능 공백) | 셀프 코드 리뷰 | 트랜잭션 방식 `rotate_password` 추가. 실패 시 원본 무손상 보장 |
| - | 경로 검증(`_is_safe_user_path`)과 실제 파일 열기 사이에 시간차가 있어 이론상 심볼릭 링크로 바꿔치기 가능(TOCTOU, CWE-367) | 아키텍처 리뷰 | `_open_no_follow()` 도입 — 검사가 아니라 열기 자체가 원자적으로 링크를 거부. POSIX는 실제 심볼릭 링크로 검증 완료, Windows 경로는 실제 환경 검증 필요(아래 "해결됨" 항목 참고) |
| - | pywebview RPC 표면이 넓어, 가상의 XSS 발생 시 임의 경로 파일 접근으로 이어질 수 있음 | 아키텍처 리뷰 | 경로 화이트리스트(capability registry) 도입 — 대화상자·시작 인자·세션 복원을 거친 경로만 RPC로 접근 허용 |



## 방어선 요약

| 위협 | 방어 지점 | 파일:함수 |
|---|---|---|
| 조작된 UNC 경로로 원격 파일 자동 열기 | 경로 검증 | `memo.py:_is_safe_user_path` |
| 심볼릭 링크로 예상 밖 파일 접근 | 경로 검증 | `memo.py:_is_safe_user_path` |
| **경로 순회(`..\..\`)로 검증 범위 밖 파일 접근** | 정규화 이전 세그먼트 검사 | `memo.py:_is_safe_user_path` |
| 널 바이트 주입으로 하위 API 우회 | 경로 검증 | `memo.py:_is_safe_user_path` |
| 조작된 세션으로 앱 크래시 / 메모리 폭탄 | 스키마 + 크기 상한 | `memo.py:_validate_session_schema` |
| 파일명에 스크립트 삽입 (XSS) | HTML 이스케이프 | `ui_template.py:esc()` |
| 저장 중 크래시로 원본 손상 | 원자적 저장 (임시파일 + `os.replace`) | `memo.py:_write_text_file` |
| 외부 프로그램의 파일 변경과 저장 충돌 | mtime 비교 | `memo.py:_write_text_file` |
| 조작된 파일명으로 Windows 예약 이름 사용 | 파일명 정규화 | `memo.py:_normalize_filename` |
| 20MB 초과 파일로 UI 응답 정지 | 크기 상한 | `memo.py:MAX_OPEN_BYTES` |
| **금고 파일 내용 유출** | AES-256-GCM 암호화 | `vault.py:encrypt_bytes` |
| **금고 파일 변조** | GCM 인증 태그 검증 | `vault.py:decrypt_bytes` |
| **비밀번호 무차별 대입 완화** | PBKDF2 200k iterations | `vault.py:derive_key` |
| **조작된 config로 iteration 낮추기** | 하한 강제 (≥100k) | `vault.py:validate_vault_config` |
| **다운그레이드/포맷 변조** | 헤더를 AEAD associated_data로 바인딩 | `vault.py:encrypt_bytes` |
| **비밀번호 오류 vs 파일 변조 구분 유출** | 두 경우 동일 오류 반환 | `vault.py:VaultAuthFailed` |
| **금고 실수 재초기화로 인한 데이터 손실** | write API가 기존 config 위 덮어쓰기 거부 | `vault.py:write_vault_config` |
| **자동 백업(세션)이 금고 암호화를 우회해 평문 노출** | 세션 저장 시 금고 탭 content 제외 + 로드 시 이중 스트리핑 | `ui_template.py:getCleanTabs`, `memo.py:_validate_session_schema` |
| **인포스틸러가 세션 파일을 통째로 반출해 방치된 메모(비밀번호·API 키) 탈취** | Windows DPAPI로 세션 파일 전체를 계정 단위 암호화 | `memo.py:_dpapi_protect/_dpapi_unprotect`, `save_session/load_session` |
| **비밀번호 유출 의심 시 대응 수단 부재** | 트랜잭션 방식 비밀번호 변경(키 회전). 전부 성공해야 교체, 실패 시 원본 무손상 | `vault.py:rotate_password` |
| **경로 검증과 실제 파일 열기 사이의 경쟁 조건(TOCTOU, CWE-367)** | 검사가 아니라 열기 자체가 원자적으로 링크를 거부(POSIX `O_NOFOLLOW` / Windows `CreateFileW`+`GetFileInformationByHandle`) | `memo.py:_open_no_follow`, `_read_text_file`, `_write_text_file`, `vault_read_file`, `vault_write_file` |
| **XSS 등으로 공격자 JS가 임의 경로로 파일 RPC 호출 (pywebview 표면)** | 경로 화이트리스트(capability registry) — 대화상자·시작 인자·세션 복원을 거친 경로만 허용 | `memo.py:_known_paths`, `_require_known_path`, `_register_known_path` |

## 검증 방법

빌드 무결성 검증:

```powershell
# 배포된 NoteNest.exe와 함께 SHA256SUMS.txt가 GitHub Releases에 첨부됩니다.
Get-FileHash NoteNest.exe -Algorithm SHA256
# 출력값이 SHA256SUMS.txt의 값과 일치해야 합니다.
```

보안 테스트 실행 (설치 없이, 표준 라이브러리만으로):

```powershell
python -m unittest tests.test_security -v
python -m unittest tests.test_vault -v
python -m unittest tests.test_toctou -v
python -m unittest tests.test_session_crypto -v
```

또는 pytest를 선호하면(선택):

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest tests/test_security.py -v
```

정적 보안 분석 (개발자용):

```powershell
python -m pip install bandit pip-audit
bandit -r memo.py
pip-audit -r requirements.txt
```

## 알려진 제한 사항

- **파일 내용 격리**: pywebview 내부의 웹뷰가 파일 내용을 표시하지만, 파일 내용은 `<textarea value>`로만 렌더링되어 HTML로 해석되지 않습니다.
- **의존성 감사**: Dependabot이 활성화되어 있으며, `pip-audit`가 CI에서 실행됩니다.
