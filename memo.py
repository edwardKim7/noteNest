"""
NoteNest — 커스텀 타이틀바 + 찾기/바꾸기 + 실행 취소/다시 실행
- 네이티브 제목 표시줄을 없애고(frameless) 앱 톤에 맞는 다크 타이틀바로 교체
- 드래그 이동, 최소화/최대화/닫기, 모서리 리사이즈 손잡이
- Ctrl+F 찾기 / Ctrl+R 바꾸기 팝업
- Ctrl+Z 실행 취소 / Ctrl+Y 다시 실행
- 탭 더블클릭, 우클릭, F2로 파일/탭 이름 변경
- 다른 이름으로 저장 기능
- 줄 번호, 현재 줄 강조, 개선된 상태 표시줄
- 실행 인자 파일 열기, 외부 파일 변경/삭제 감지, 저장 충돌 방지
- 읽기 전용 파일 안내, 인코딩/줄끝 보존, 오류 로그 저장
실행: pip install pywebview  →  python memo.py
"""

import os
import json
import sys
import time
import traceback
import webview
import errno
from collections import OrderedDict

import vault

import ctypes


# ── Windows DPAPI (세션 파일 저장소 암호화) ─────────────────────
# 배경: 인포스틸러류 악성코드는 %APPDATA%\Notepad++\backup 같은 자동 백업
# 폴더를 통째로 긁어서 외부로 반출하는 방식으로 "저장하지 않고 방치한
# 메모"(제목 없음 탭에 적어둔 비밀번호·API 키 등)를 훔친다. NoteNest의
# session.json도 동일한 역할을 하므로 같은 위험에 노출된다.
#
# 방어: Windows DPAPI(CryptProtectData/CryptUnprotectData)로 세션 파일
# 전체를 암호화한다. 이 API는 현재 로그인한 Windows 계정에 암호화를 묶는다
# (내부적으로 사용자 자격 증명에서 파생된 마스터 키를 사용). 그 결과:
#   - 파일을 복사해 다른 PC/계정으로 반출해도 복호화 불가
#   - 사용자에게 비밀번호를 요구하지 않아 세션 복원 UX가 그대로 유지됨
#
# 한계(정직하게 명시): 악성코드가 "같은 로그인 세션 안에서 직접 실행"되면
# 그 프로세스도 동일한 Windows API(CryptUnprotectData)를 호출할 수 있어
# 복호화가 가능하다. 즉 DPAPI는 "파일을 빼돌려 다른 곳에서 여는" 공격은
# 막지만, "피해자 PC 안에서 능동적으로 복호화를 시도하는" 고급 공격까지는
#막지 못한다. 후자까지 방어하려면 사람만 아는 비밀번호가 필요하므로,
# 정말 민감한 내용(비밀번호, API 키 등)은 금고(Vault) 사용을 권장한다.
SESSION_MAGIC = b"NNSESSDP\x00"  # DPAPI로 보호된 세션 파일임을 표시하는 헤더


def _dpapi_available():
    """현재 플랫폼에서 DPAPI 사용 가능 여부. Windows 전용 API이므로 그 외
    플랫폼(개발/테스트 환경)에서는 항상 False를 반환하고 평문 저장으로
    자연스럽게 대체(fallback)된다."""
    return sys.platform == "win32"


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi_protect(data: bytes, description: str = "NoteNest session") -> bytes:
    """DPAPI로 bytes를 암호화. Windows 전용. 실패 시 예외를 던진다."""
    if not _dpapi_available():
        raise RuntimeError("DPAPI는 Windows에서만 사용할 수 있습니다.")
    CRYPTPROTECT_UI_FORBIDDEN = 0x1  # 암호화 중 UI 팝업 방지
    buf_in = ctypes.create_string_buffer(data, len(data))
    blob_in = _DATA_BLOB(len(data), ctypes.cast(buf_in, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in), description, None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)
    )
    if not ok:
        raise OSError("CryptProtectData failed: " + str(ctypes.get_last_error()))
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _dpapi_unprotect(blob: bytes) -> bytes:
    """DPAPI로 암호화된 bytes를 복호화. Windows 전용. 실패 시 예외를 던진다."""
    if not _dpapi_available():
        raise RuntimeError("DPAPI는 Windows에서만 사용할 수 있습니다.")
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    buf_in = ctypes.create_string_buffer(blob, len(blob))
    blob_in = _DATA_BLOB(len(blob), ctypes.cast(buf_in, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)
    )
    if not ok:
        raise OSError("CryptUnprotectData failed: " + str(ctypes.get_last_error()))
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


# ── 원자적 심볼릭 링크 차단 (TOCTOU 방어, CWE-367) ───────────────
# 배경: _is_safe_user_path()가 "심볼릭 링크인지 검사"하는 시점과 실제로
# open()을 호출해 파일을 읽는 시점 사이에는 시간차가 있다. 그 사이에
# 공격자가 파일을 심볼릭 링크로 바꿔치기하면(로컬 코드 실행 권한이 이미
# 있어야 하는 시나리오이긴 하지만), "검사는 통과했지만 실제로 열리는 건
# 링크"가 되는 경쟁 조건(race condition)이 이론적으로 존재한다.
#
# 해결: "검사 후 사용"이 아니라 "사용 자체가 검사를 겸하도록" 만든다.
#   - POSIX(Linux/Mac, 개발 환경): os.open()에 O_NOFOLLOW 플래그를 주면
#     커널이 경로 순회와 심볼릭 링크 감지를 한 syscall 안에서 원자적으로
#     수행한다. 심볼릭 링크면 ELOOP로 즉시 실패 — 이 사이에는 물리적으로
#     경쟁 조건이 끼어들 틈이 없다.
#   - Windows(배포 대상): O_NOFOLLOW가 없으므로 CreateFileW를
#     FILE_FLAG_OPEN_REPARSE_POINT로 호출해 "reparse point 자체"를 가리키는
#     핸들을 얻는다(자동으로 따라가지 않음). 그 다음 별도로 경로를 다시
#     조회하는 대신, 이미 열려 있는 그 핸들에 대해
#     GetFileInformationByHandle을 호출해 reparse point 여부를 확인한다.
#     "핸들이 이미 가리키고 있는 대상"을 검사하는 것이므로, 검사와 사용
#     사이에 별도의 경로 조회가 끼어들지 않아 경쟁 조건이 닫힌다.
class UnsafeSymlinkError(OSError):
    """경로가 심볼릭 링크/정션임을 열기 시도 자체에서 원자적으로 감지했을 때."""


class _WIN_BY_HANDLE_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.c_uint32),
        ("ftCreationTime", ctypes.c_uint64),
        ("ftLastAccessTime", ctypes.c_uint64),
        ("ftLastWriteTime", ctypes.c_uint64),
        ("dwVolumeSerialNumber", ctypes.c_uint32),
        ("nFileSizeHigh", ctypes.c_uint32),
        ("nFileSizeLow", ctypes.c_uint32),
        ("nNumberOfLinks", ctypes.c_uint32),
        ("nFileIndexHigh", ctypes.c_uint32),
        ("nFileIndexLow", ctypes.c_uint32),
    ]


def _win_open_no_follow_fd(path, writable=False):
    """Windows: reparse point(심볼릭 링크/정션)를 원자적으로 거부하며 파일을 여는
    저수준 파일 디스크립터를 반환. 실패 시 UnsafeSymlinkError 또는 OSError."""
    import msvcrt

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x1
    FILE_SHARE_WRITE = 0x2
    OPEN_EXISTING = 3
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    access = GENERIC_WRITE if writable else GENERIC_READ
    handle = ctypes.windll.kernel32.CreateFileW(
        ctypes.c_wchar_p(path), access, FILE_SHARE_READ | FILE_SHARE_WRITE, None,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, None
    )
    if handle in (None, INVALID_HANDLE_VALUE, 0):
        raise OSError(f"CreateFileW 실패: {path} (err={ctypes.get_last_error()})")

    # 이미 연 핸들 자체에 대해 검사 — 경로를 다시 조회하지 않으므로 그
    # 사이에 경쟁 조건이 끼어들 여지가 없다.
    info = _WIN_BY_HANDLE_FILE_INFO()
    ok = ctypes.windll.kernel32.GetFileInformationByHandle(handle, ctypes.byref(info))
    if not ok:
        ctypes.windll.kernel32.CloseHandle(handle)
        raise OSError(f"GetFileInformationByHandle 실패: {path}")

    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        ctypes.windll.kernel32.CloseHandle(handle)
        raise UnsafeSymlinkError(f"심볼릭 링크/정션은 열 수 없습니다: {path}")

    flags = os.O_WRONLY if writable else os.O_RDONLY
    return msvcrt.open_osfhandle(handle, flags)


def _open_no_follow_fd(path, writable=False):
    """플랫폼에 맞는 방식으로 심볼릭 링크를 원자적으로 거부하며 파일을 여는
    저수준 fd를 반환. 실패 시 UnsafeSymlinkError 또는 OSError."""
    if sys.platform == "win32":
        return _win_open_no_follow_fd(path, writable=writable)
    flags = os.O_WRONLY if writable else os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path, flags)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise UnsafeSymlinkError(f"심볼릭 링크는 열 수 없습니다: {path}") from e
        raise


def _open_no_follow(path, mode="rb"):
    """_open_no_follow_fd를 감싸 일반 Python 파일 객체(context manager)로 반환.
    기존 open(path, mode) 호출을 그대로 대체할 수 있는 형태."""
    writable = "w" in mode or "+" in mode or "a" in mode
    fd = _open_no_follow_fd(path, writable=writable)
    return os.fdopen(fd, mode)


def resource_path(relative_path):
    """PyInstaller EXE 내부/일반 Python 실행 모두에서 리소스 경로를 안전하게 찾습니다."""
    try:
        base_path = sys._MEIPASS  # type: ignore[attr-defined]
    except Exception:
        base_path = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base_path, relative_path)


def set_windows_app_id():
    """Windows 작업표시줄이 PyInstaller EXE 아이콘을 안정적으로 사용하도록 AppUserModelID를 지정합니다."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("NoteNest.CustomMemoApp")
    except Exception:
        pass

SESSION_DIR = os.path.join(os.path.expanduser("~"), ".simple_memo")
SESSION_FILE = os.path.join(SESSION_DIR, "session.json")
LOG_FILE = os.path.join(SESSION_DIR, "app.log")
MAX_OPEN_BYTES = 20 * 1024 * 1024  # textarea 기반 편집기 보호용: 20MB 초과 파일은 열기 차단
MAX_SESSION_BYTES = 8 * 1024 * 1024  # 세션 파일이 조작되어 과도하게 커지는 상황 방지

INVALID_FILENAME_CHARS = '<>:"/\\|?*'
RESERVED_WINDOWS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

# ── 보안 상수 ────────────────────────────────────────────────
# CVE-2026-48800(Notepad++)에서 배운 교훈:
# 설정 파일에 저장된 값을 "신뢰 가능한 입력"으로 간주하면 안 된다.
# 세션 파일은 사용자 홈 디렉터리에 있고, 다른 프로세스가 조작 가능하므로
# 로드 시점에 경로/타입/구조를 모두 검증한다.
PATH_REJECT_UNC = True          # \\server\share 형태 원격 경로 차단
PATH_REJECT_SYMLINK = True      # 심볼릭 링크/정션 경로 차단
PATH_MAX_LENGTH = 4096          # 극단적으로 긴 경로 차단
SESSION_MAX_TABS = 500          # 세션 조작으로 무한 탭 생성 차단
SESSION_MAX_TRASH = 5000        # 휴지통 무한 성장 차단
SESSION_MAX_FOLDERS = 200


def _is_safe_user_path(path):
    """사용자 데이터로 들어온 파일 경로가 앱이 열어도 되는 안전한 경로인지 검사.

    Notepad++ CVE-2026-48800 / CVE-2026-52886 계열 사고를 예방하기 위한 방어선:
      - 세션 파일에 조작된 UNC 경로(\\\\attacker\\share\\evil.txt)가 있어도 자동으로 열지 않는다.
      - 심볼릭 링크/정션을 통해 예상 밖의 파일이 열리는 것을 막는다.
      - 지나치게 긴 경로/제어문자가 섞인 경로를 조기에 거부한다.
      - "..' 경로 순회(traversal) 컴포넌트를 원본 문자열 단계에서 거부한다.
        CVE-2026-52886은 session.xml의 backupFilePath를 접두어(starts_with)만
        검사하고 정규화(normalize)하지 않아 '..\\..\\'로 검증을 우회당했다.
        같은 실수를 피하기 위해 여기서는 os.path.normpath로 정규화하기 *전에*
        원본 경로 문자열의 각 세그먼트를 검사해 '..'가 하나라도 있으면 거부한다.
        (normpath 이후에 검사하면 '..'가 이미 축약되어 사라지므로 무의미하다.)

    반환값: (ok: bool, reason: str|None)
    """
    try:
        if not path or not isinstance(path, str):
            return False, "empty"
        if len(path) > PATH_MAX_LENGTH:
            return False, "path_too_long"
        # 제어 문자(널 바이트 포함) 거부: 파일 시스템 API 우회 시도 차단
        if any(ord(ch) < 32 for ch in path):
            return False, "control_char"

        # UNC/네트워크 경로 차단: \\server\share, //server/share 모두
        if PATH_REJECT_UNC:
            normalized = path.replace("/", "\\")
            if normalized.startswith("\\\\"):
                return False, "unc_path"

        # 경로 순회 차단: 정규화 *이전*의 원본 문자열에서 '..' 세그먼트를 검사한다.
        # normpath()로 먼저 축약해버리면 '..'가 사라져 검사 자체가 무력화되므로
        # 반드시 이 순서를 지켜야 한다 (CVE-2026-52886이 겪은 실수).
        raw_segments = path.replace("/", "\\").split("\\")
        if any(seg == ".." for seg in raw_segments):
            return False, "path_traversal"

        # 심볼릭 링크/정션 차단: 실제 파일이 존재할 때만 검사
        # (아직 없는 경로는 저장 대상일 수 있어 통과)
        abs_path = os.path.abspath(path)
        if PATH_REJECT_SYMLINK and os.path.lexists(abs_path):
            try:
                if os.path.islink(abs_path):
                    return False, "symlink"
                # Windows 정션도 심볼릭 링크로 취급
                st = os.lstat(abs_path)
                if hasattr(st, "st_file_attributes"):
                    # FILE_ATTRIBUTE_REPARSE_POINT = 0x400
                    if st.st_file_attributes & 0x400:
                        return False, "reparse_point"
            except OSError:
                # 상태 확인 실패는 안전한 쪽으로 거부
                return False, "stat_failed"

        return True, None
    except Exception:
        return False, "check_failed"


def _validate_session_schema(data):
    """세션 파일에서 로드한 JSON이 예상 구조를 지키는지 검증하고 안전한 사본을 반환.

    누락된 필드는 기본값으로 채우고, 타입이 다르거나 검증 실패한 항목은 조용히 버린다.
    이를 통해 세션 파일이 손상되거나 조작되어도 앱이 오작동/충돌하지 않도록 한다.
    """
    if not isinstance(data, dict):
        return None

    safe = {}

    # tabs: list of dict, 각 탭은 dict이며 path가 있으면 안전한 경로여야 함
    raw_tabs = data.get("tabs")
    if isinstance(raw_tabs, list):
        safe_tabs = []
        for tab in raw_tabs[:SESSION_MAX_TABS]:
            if not isinstance(tab, dict):
                continue
            path = tab.get("path")
            if path is not None:
                ok, _reason = _is_safe_user_path(str(path))
                if not ok:
                    # 위험 경로는 탭 자체를 폐기 (조용히 무시)
                    continue
            # 보안: 금고 탭은 세션 파일에 평문 content가 있으면 안 된다.
            # JS 쪽(getCleanTabs)이 이미 비우지만, 세션 파일이 수동 편집되거나
            # 이전 버전/조작된 파일이 로드될 가능성에 대비해 여기서도 강제로 비운다.
            # Notepad++ CVE-2026-52886처럼 "보조 저장 경로가 주 경로의 보호를
            # 우회한다"는 실수를 이중으로 차단하는 지점.
            if tab.get("vault") is True:
                tab = dict(tab)
                tab["content"] = ""
                tab["savedContent"] = ""
            # content 크기 제한: 조작된 세션으로 메모리 폭탄 방지
            content = tab.get("content")
            if isinstance(content, str) and len(content.encode("utf-8", errors="ignore")) > MAX_OPEN_BYTES:
                continue
            safe_tabs.append(tab)
        safe["tabs"] = safe_tabs

    # folders, trash: 개수 상한만 강제
    raw_folders = data.get("folders")
    if isinstance(raw_folders, list):
        safe["folders"] = [f for f in raw_folders[:SESSION_MAX_FOLDERS] if isinstance(f, dict)]

    raw_trash = data.get("trash")
    if isinstance(raw_trash, list):
        safe_trash = []
        for item in raw_trash[:SESSION_MAX_TRASH]:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            if path is not None:
                ok, _reason = _is_safe_user_path(str(path))
                if not ok:
                    continue
            safe_trash.append(item)
        safe["trash"] = safe_trash

    # settings, window, activeId, activeFolderId 등은 dict/원시타입만 통과시킴
    for key in ("settings", "window"):
        val = data.get(key)
        if isinstance(val, dict):
            safe[key] = val

    for key in ("activeId", "activeFolderId"):
        if key not in data:
            continue
        val = data.get(key)
        if isinstance(val, (str, int, type(None))):
            safe[key] = val

    return safe


class Api:
    """JS에서 호출하는 Python 기능 (파일 입출력 · 세션 백업 · 창 제어)."""

    def __init__(self, startup_paths=None):
        self._window = None
        self._maximized = False     # 최대화 토글 상태 추적
        self._last_session_json = None  # 같은 세션을 반복 저장하지 않기 위한 캐시

        # 경로 화이트리스트를 startup_paths 처리보다 먼저 초기화해야
        # 아래에서 바로 등록할 수 있다. 자세한 설명은 클래스 뒷부분의
        # "경로 화이트리스트 헬퍼" 섹션 주석 참고.
        # ── 경로 화이트리스트(capability registry) ──────────────────
        # 배경: pywebview는 JS가 window.pywebview.api.* 를 통해 Python
        # 메서드를 거의 다 직접 호출할 수 있는 구조라, 코드베이스 어딘가에
        # XSS가 생기면 일반 웹앱보다 파급력이 크다(파일 시스템 RPC 브릿지
        # 전체 노출). 모든 API 시그니처를 "탭 ID만 주고받기"로 바꾸는 전면
        # 재설계는 4,900줄 UI 전체와 세션/탭/휴지통/폴더 이동 로직을 함께
        # 재작성해야 해서 리스크가 크므로, 대신 같은 보안 효과를 훨씬 작은
        # 변경 범위로 얻을 수 있는 화이트리스트 방식을 택한다.
        #
        # 이 세션에서 앱이 "신뢰의 원천"을 거쳐 실제로 마주친 경로만 다음
        # 목록에 등록된다. 신뢰의 원천은 셋뿐이다:
        #   1. OS 네이티브 파일/폴더 선택 대화상자의 결과 (사용자가 직접 클릭)
        #   2. 시작 인자(Windows 파일 연결로 실행된 경로, OS가 넘겨준 값)
        #   3. 세션 파일에서 복원된 경로 (Python 자신이 검증·저장한 값)
        # 이 목록에 없는 경로는, 설령 UNC/순회/심볼릭 링크 검사를 모두
        # 통과하더라도 읽기/쓰기가 거부된다. 즉 만약 코드 어딘가에 XSS가
        # 생겨 공격자 JS가 임의 경로로 save_file()을 호출해도, 그 경로가
        # 이 세션에서 한 번도 신뢰의 원천을 거친 적이 없다면 차단된다.
        self._known_paths = OrderedDict()

        self._startup_paths = []
        for path in startup_paths or []:
            try:
                if path and not str(path).startswith("-"):
                    abs_path = os.path.abspath(path)
                    self._startup_paths.append(abs_path)
                    self._register_known_path(abs_path)  # 신뢰의 원천 ②: OS 시작 인자
            except Exception:
                pass

        # ── Vault 상태 ────────────────────────────────────
        # 잠금 해제된 금고의 파생 키를 담는 dict. 파일 시스템에 절대 저장하지 않는다.
        # 키: 정규화된 금고 폴더 절대 경로, 값: 32바이트 AES 키
        self._vault_keys = {}
        # 자동 잠금(idle timeout)을 위한 마지막 사용 시각
        self._vault_last_use = {}
        # 자동 잠금 기본 5분. 세션 설정에서 override 가능.
        self._vault_idle_seconds = 5 * 60


    def _log(self, message):
        try:
            os.makedirs(SESSION_DIR, exist_ok=True)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S") + " | " + str(message) + "\n")
        except Exception:
            pass

    # ── 경로 화이트리스트 헬퍼 ────────────────────────────────
    KNOWN_PATH_CAP = 2000  # 장시간 세션에서 무한정 커지지 않도록 상한

    def _path_key(self, path):
        try:
            return os.path.normcase(os.path.abspath(path))
        except Exception:
            return None

    def _register_known_path(self, path):
        """path와 그 상위 폴더를 신뢰 목록에 등록한다.

        상위 폴더까지 함께 등록하는 이유: 금고(Vault)는 사용자가 폴더를
        한 번만 대화상자로 선택하고, 그 안에 새 메모를 앱이 자동으로
        여러 개 만드는 흐름이라(개별 파일마다 대화상자를 또 띄우지 않음).
        폴더가 신뢰 목록에 있으면 그 폴더 '바로 안'의 파일은 금고 관련
        메서드에서 허용된다(_is_known_vault_folder 참고). 일반 파일 읽기/
        쓰기는 폴더 신뢰를 상속하지 않고 파일 자신의 등록 여부만 본다.
        """
        key = self._path_key(path)
        if not key:
            return
        for target in (key, os.path.dirname(key)):
            if target in self._known_paths:
                self._known_paths.move_to_end(target)
            else:
                self._known_paths[target] = None
        while len(self._known_paths) > self.KNOWN_PATH_CAP:
            self._known_paths.popitem(last=False)

    def _is_known_path(self, path):
        key = self._path_key(path)
        return bool(key) and key in self._known_paths

    def _is_known_vault_folder(self, folder_path):
        """폴더가 신뢰 목록에 있고 실제로 금고 폴더인지 확인.
        vault_read_file/vault_write_file이 개별 파일 대화상자 없이 새 메모를
        만들 때 이 검사로 허용 여부를 판단한다."""
        return self._is_known_path(folder_path) and vault.is_vault_folder(folder_path)

    def _require_known_path(self, path, allow_vault_folder_fallback=False):
        """일반적인 경로 접근 진입점에서 공통으로 쓰는 검증.
        (ok, error_response_or_None) 튜플을 반환한다."""
        ok, reason = _is_safe_user_path(path or "")
        if not ok:
            return False, {"ok": False, "error": "unsafe_path", "reason": reason,
                            "path": str(path) if path else ""}
        if self._is_known_path(path):
            return True, None
        if allow_vault_folder_fallback and self._is_known_vault_folder(os.path.dirname(os.path.abspath(path))):
            return True, None
        self._log(f"path not in known-path registry, rejected: {path!r}")
        return False, {"ok": False, "error": "unsafe_path", "reason": "not_registered",
                        "path": str(path) if path else ""}

    def _register_session_paths(self, session_data):
        """load_session이 검증된 세션을 반환하기 직전에 호출.
        세션에 담긴(=Python 자신이 검증·저장한) 경로들을 신뢰 목록에 등록한다."""
        if not isinstance(session_data, dict):
            return
        for key in ("tabs", "trash"):
            items = session_data.get(key)
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict):
                    p = item.get("path")
                    if p:
                        self._register_known_path(p)

    # 세션 ─────────────────────────────────────────
    def load_session(self):
        """세션 파일 로드. 크기 상한과 스키마 검증을 거쳐 위험한 값은 자동 폐기.

        보안 배경: CVE-2026-48800(Notepad++)은 설정 파일 값을 그대로 신뢰해서
        발생했다. NoteNest는 세션 로드 지점에서 (1) 파일 크기 (2) JSON 스키마
        (3) 저장된 파일 경로의 안전성을 모두 검증한다.

        DPAPI 지원: 파일이 SESSION_MAGIC 헤더로 시작하면 DPAPI로 보호된
        형식이므로 복호화 후 파싱한다. 헤더가 없으면 과거 버전이 만든
        평문 세션으로 간주해 그대로 파싱한다(하위 호환). 평문으로 읽힌
        세션은 다음 save_session 호출 시 자동으로 DPAPI 보호 형식으로
        마이그레이션된다.
        """
        if not os.path.exists(SESSION_FILE):
            return None
        try:
            size = os.path.getsize(SESSION_FILE)
            if size > MAX_SESSION_BYTES:
                self._log(f"session too large: {size} bytes, ignored")
                return None
            with open(SESSION_FILE, "rb") as f:
                raw_bytes = f.read()

            if raw_bytes.startswith(SESSION_MAGIC):
                if not _dpapi_available():
                    # 다른 플랫폼(개발 환경 등)에서는 DPAPI로 보호된 세션을
                    # 복호화할 방법이 없다. 세션을 잃는 것이 잘못된 복호화
                    # 시도보다 안전하므로 조용히 포기한다.
                    self._log("DPAPI-protected session found but unavailable on this platform")
                    return None
                try:
                    plain_bytes = _dpapi_unprotect(raw_bytes[len(SESSION_MAGIC):])
                except Exception as e:
                    self._log("DPAPI unprotect failed: " + repr(e))
                    return None
                text = plain_bytes.decode("utf-8")
            else:
                # 레거시 평문 세션 (v1 또는 비Windows 환경에서 저장된 파일)
                text = raw_bytes.decode("utf-8")

            raw = json.loads(text)
            validated = _validate_session_schema(raw)
            self._register_session_paths(validated)  # 신뢰의 원천 ③: 세션 복원
            return validated
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            self._log("load_session failed: " + repr(e))
            return None

    def save_session(self, data):
        """세션 저장. EXE 환경에서 반복 저장/부분 저장으로 UI가 멎는 것을 줄이기 위해
        동일 데이터는 건너뛰고, 임시 파일에 쓴 뒤 원자적으로 교체합니다.

        DPAPI 지원: Windows에서는 세션 파일 전체를 DPAPI로 암호화해 저장한다.
        파일이 통째로 복사되어 외부로 반출되어도 다른 계정/기기에서는
        복호화할 수 없다. DPAPI를 쓸 수 없는 플랫폼에서는 평문으로 저장한다
        (이 앱은 배포 대상이 Windows이므로 실제 사용자 환경에서는 이 경로를
        타지 않는다).
        """
        try:
            payload_str = json.dumps(data, ensure_ascii=False)
            if payload_str == self._last_session_json:
                return True

            os.makedirs(SESSION_DIR, exist_ok=True)
            tmp_file = SESSION_FILE + ".tmp"
            payload_bytes = payload_str.encode("utf-8")

            if _dpapi_available():
                try:
                    protected = _dpapi_protect(payload_bytes)
                    with open(tmp_file, "wb") as f:
                        f.write(SESSION_MAGIC + protected)
                    os.replace(tmp_file, SESSION_FILE)
                    self._last_session_json = payload_str
                    return True
                except Exception as e:
                    self._log("DPAPI protect failed, falling back to plaintext: " + repr(e))
                    # 아래로 흘러 평문 저장을 시도 (세션을 아예 잃는 것보다 낫다)

            with open(tmp_file, "w", encoding="utf-8") as f:
                f.write(payload_str)
            os.replace(tmp_file, SESSION_FILE)
            self._last_session_json = payload_str
            return True
        except (OSError, TypeError, ValueError):
            return False

    # 파일 ─────────────────────────────────────────
    def _file_stat(self, path):
        st = os.stat(path)
        # Windows 읽기 전용 속성과 일반 쓰기 권한을 같이 확인합니다.
        attrs = getattr(st, "st_file_attributes", 0)
        readonly_attr = False
        try:
            readonly_attr = bool(attrs & 0x01)  # FILE_ATTRIBUTE_READONLY
        except Exception:
            readonly_attr = False
        readonly_access = not os.access(path, os.W_OK)
        return {
            "mtime": st.st_mtime,
            "ctime": getattr(st, "st_birthtime", st.st_ctime),
            "size": st.st_size,
            "readonly": bool(readonly_attr or readonly_access),
        }

    def _detect_eol(self, content):
        if "\r\n" in content:
            return "CRLF"
        if "\r" in content and "\n" not in content:
            return "CR"
        return "LF"

    def _decode_bytes(self, data):
        candidates = []
        if data.startswith(b"\xef\xbb\xbf"):
            candidates.append(("UTF-8-BOM", "utf-8-sig"))
        elif data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
            candidates.append(("UTF-16", "utf-16"))
        candidates.extend([
            ("UTF-8", "utf-8"),
            ("CP949", "cp949"),
        ])

        seen = set()
        for label, enc in candidates:
            if enc in seen:
                continue
            seen.add(enc)
            try:
                return data.decode(enc), label
            except UnicodeDecodeError:
                continue
        return None, None

    def _read_text_file(self, path):
        try:
            # 보안: 세션 복원·시작 인자·자동 열기 경로가 모두 이 함수를 지나가므로
            # 여기서 UNC/심볼릭 링크/과도한 길이 경로를 일괄 차단한다.
            ok, reason = _is_safe_user_path(path or "")
            if not ok:
                self._log(f"unsafe path rejected: {reason} | {path!r}")
                return {"ok": False, "error": "unsafe_path", "reason": reason,
                        "path": str(path) if path else ""}

            path = os.path.abspath(path)
            if not os.path.exists(path):
                return {"ok": False, "error": "missing", "path": path}
            if os.path.isdir(path):
                return {"ok": False, "error": "directory", "path": path}

            stat_info = self._file_stat(path)
            if stat_info["size"] > MAX_OPEN_BYTES:
                return {"ok": False, "error": "too_large", "path": path, "size": stat_info["size"]}

            # 보안(TOCTOU 방어): _is_safe_user_path의 심볼릭 링크 검사는 여기
            # 도달하기 전 시점의 스냅샷일 뿐이다. 실제 데이터를 읽는 이 지점의
            # open() 자체가 심볼릭 링크를 원자적으로 거부하도록 해, 검사와
            # 사용 사이에 파일이 바꿔치기되는 경쟁 조건을 닫는다.
            try:
                with _open_no_follow(path, "rb") as f:
                    data = f.read()
            except UnsafeSymlinkError:
                self._log(f"TOCTOU: symlink detected at open-time for {path}")
                return {"ok": False, "error": "unsafe_path", "reason": "symlink_toctou", "path": path}

            content, encoding = self._decode_bytes(data)
            if content is None:
                return {"ok": False, "error": "decode", "path": path}

            return {
                "ok": True,
                "path": path,
                "name": os.path.basename(path),
                "content": content,
                "encoding": encoding,
                "eol": self._detect_eol(content),
                "stat": stat_info,
            }
        except OSError as e:
            self._log("read failed: " + repr(e))
            return {"ok": False, "error": "access", "path": os.path.abspath(path) if path else ""}
        except Exception:
            self._log(traceback.format_exc())
            return {"ok": False, "error": "read_failed", "path": os.path.abspath(path) if path else ""}

    def _normalize_content_for_eol(self, content, eol):
        text = str(content or "")
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if eol == "CRLF":
            return text.replace("\n", "\r\n")
        if eol == "CR":
            return text.replace("\n", "\r")
        return text

    def _encoding_to_python(self, encoding):
        label = (encoding or "UTF-8").upper()
        if label in {"UTF-8-BOM", "UTF8-BOM"}:
            return "utf-8-sig", "UTF-8-BOM"
        if label.startswith("UTF-16"):
            return "utf-16", "UTF-16"
        if label in {"CP949", "MS949", "ANSI"}:
            return "cp949", "CP949"
        return "utf-8", "UTF-8"

    def _write_text_file(self, path, content, encoding="UTF-8", eol="LF", expected_mtime=None, force=False):
        try:
            # 보안: 저장 대상 경로도 UNC/심볼릭 링크로 위조될 수 있으므로 검증한다.
            ok, reason = _is_safe_user_path(path or "")
            if not ok:
                self._log(f"unsafe write path rejected: {reason} | {path!r}")
                return {"ok": False, "error": "unsafe_path", "reason": reason,
                        "path": str(path) if path else ""}

            path = os.path.abspath(path)
            folder = os.path.dirname(path)
            if folder and not os.path.exists(folder):
                return {"ok": False, "error": "folder_missing", "path": path}

            # 보안(TOCTOU 방어): _file_stat()의 os.stat()은 심볼릭 링크를
            # 투명하게 따라가므로, 대상이 링크라는 사실을 모른 채 링크가
            # 가리키는 엉뚱한 파일의 mtime/readonly 정보를 검사에 쓸 위험이
            # 있다. 실제로 저장 로직에 들어가기 전에 명시적으로 링크 여부를
            # 원자적으로 확인해 거부한다. (최종 교체는 os.replace()가
            # 목적지 심볼릭 링크 자체를 갈아치우는 방식이라 이 단계 자체가
            # 없어도 대상 파일이 오염되지는 않지만, "링크를 조용히 실제
            # 파일로 바꿔버리는" 놀람 동작을 막기 위해 명시적으로 거부한다.)
            if os.path.lexists(path):
                try:
                    probe_fd = _open_no_follow_fd(path, writable=False)
                    os.close(probe_fd)
                except UnsafeSymlinkError:
                    self._log(f"TOCTOU: symlink detected at write-time for {path}")
                    return {"ok": False, "error": "unsafe_path", "reason": "symlink_toctou", "path": path}
                except OSError:
                    pass  # 열기 자체가 실패하는 다른 사유는 아래 로직에서 자연스럽게 처리됨

            if os.path.exists(path):
                stat_info = self._file_stat(path)
                if stat_info.get("readonly"):
                    return {"ok": False, "error": "readonly", "path": path, "stat": stat_info}
                if expected_mtime is not None and not force:
                    try:
                        if abs(float(stat_info["mtime"]) - float(expected_mtime)) > 0.001:
                            return {"ok": False, "error": "external_changed", "path": path, "stat": stat_info}
                    except Exception:
                        pass
            else:
                # 기존 경로 저장인데 파일이 사라졌으면 같은 이름으로 새로 만드는 대신 사용자에게 다른 이름 저장을 유도합니다.
                if expected_mtime is not None:
                    return {"ok": False, "error": "missing", "path": path}

            py_encoding, encoding_label = self._encoding_to_python(encoding)
            normalized = self._normalize_content_for_eol(content, eol)

            tmp_path = os.path.join(folder or ".", f".__memo_tmp_{os.getpid()}_{int(time.time() * 1000)}__")
            try:
                with open(tmp_path, "w", encoding=py_encoding, newline="") as f:
                    f.write(normalized)
                os.replace(tmp_path, path)
            except UnicodeEncodeError:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
                return {"ok": False, "error": "encoding_failed", "path": path, "encoding": encoding_label}
            except OSError as e:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
                self._log("write failed: " + repr(e))
                return {"ok": False, "error": "write_failed", "path": path}

            stat_info = self._file_stat(path)
            return {
                "ok": True,
                "path": path,
                "name": os.path.basename(path),
                "encoding": encoding_label,
                "eol": eol or "LF",
                "stat": stat_info,
            }
        except Exception:
            self._log(traceback.format_exc())
            return {"ok": False, "error": "write_failed", "path": os.path.abspath(path) if path else ""}

    def open_file(self):
        result = self._window.create_file_dialog(
            webview.OPEN_DIALOG, allow_multiple=False,
            file_types=("텍스트 파일 (*.txt)", "모든 파일 (*.*)"),
        )
        if not result:
            return None
        path = result[0] if isinstance(result, (list, tuple)) else result
        self._register_known_path(path)  # 신뢰의 원천 ①: 네이티브 열기 대화상자
        return self._read_text_file(path)

    def open_path(self, path):
        ok, err = self._require_known_path(path)
        if not ok:
            return err
        return self._read_text_file(path)

    def get_startup_files(self):
        # Windows 연결 프로그램 / 드래그 실행으로 넘어온 인자 파일을 pywebview 준비 후 한 번만 전달합니다.
        paths = list(self._startup_paths)
        self._startup_paths = []
        return [self._read_text_file(path) for path in paths]

    def check_file_states(self, items):
        results = []
        try:
            for item in items or []:
                try:
                    path = item.get("path") if isinstance(item, dict) else None
                    tab_id = item.get("id") if isinstance(item, dict) else None
                    if not path:
                        continue
                    # 보안: 상태 확인 요청 경로도 안전성 + 화이트리스트 검증 후 사용
                    ok, _reason = _is_safe_user_path(str(path))
                    if not ok:
                        results.append({"id": tab_id, "path": str(path), "exists": False,
                                        "error": "unsafe_path"})
                        continue
                    if not self._is_known_path(path):
                        self._log(f"check_file_states: path not registered, skipped: {path!r}")
                        results.append({"id": tab_id, "path": str(path), "exists": False,
                                        "error": "unsafe_path"})
                        continue
                    abs_path = os.path.abspath(path)
                    if not os.path.exists(abs_path):
                        results.append({"id": tab_id, "path": abs_path, "exists": False})
                    elif os.path.isdir(abs_path):
                        results.append({"id": tab_id, "path": abs_path, "exists": False, "error": "directory"})
                    else:
                        results.append({
                            "id": tab_id,
                            "path": abs_path,
                            "name": os.path.basename(abs_path),
                            "exists": True,
                            "stat": self._file_stat(abs_path),
                        })
                except Exception:
                    self._log(traceback.format_exc())
        except Exception:
            self._log(traceback.format_exc())
        return results

    def _normalize_filename(self, new_name, default_ext=""):
        """Windows에서 안전한 파일 이름으로 정리하고 검증합니다."""
        try:
            name = str(new_name or "").strip().strip('"').strip("'")
        except Exception:
            return None, "empty"

        # 경로가 들어와도 파일명만 사용합니다.
        name = os.path.basename(name).strip()
        # Windows는 파일명 끝의 공백/마침표를 허용하지 않습니다.
        name = name.rstrip(" .")

        if not name:
            return None, "empty"
        if any(ch in INVALID_FILENAME_CHARS for ch in name) or any(ord(ch) < 32 for ch in name):
            return None, "invalid"

        stem, ext = os.path.splitext(name)
        if stem.upper() in RESERVED_WINDOWS_NAMES:
            return None, "reserved"
        if not ext and default_ext:
            name += default_ext

        return name, None

    def save_file(self, current_path, content, suggested_name=None, expected_mtime=None, force=False, encoding="UTF-8", eol="LF"):
        path = current_path
        if not path:
            # 새 메모를 처음 저장할 때 저장창 기본 이름을 Memo1.txt, Memo2.txt처럼 보여줍니다.
            default_name, error = self._normalize_filename(suggested_name or "Memo", default_ext=".txt")
            if error:
                default_name = "Memo.txt"

            chosen = self._window.create_file_dialog(
                webview.SAVE_DIALOG, save_filename=default_name,
                file_types=("텍스트 파일 (*.txt)", "모든 파일 (*.*)"),
            )
            if not chosen:
                return None
            path = chosen[0] if isinstance(chosen, (list, tuple)) else chosen
            expected_mtime = None
            self._register_known_path(path)  # 신뢰의 원천 ①: 네이티브 저장 대화상자
        else:
            # 이미 열려 있던 탭의 저장(Ctrl+S)이므로 경로가 화이트리스트에 있어야 한다.
            ok, err = self._require_known_path(path)
            if not ok:
                return err
        if not os.path.splitext(path)[1]:
            path += ".txt"
        return self._write_text_file(path, content, encoding=encoding, eol=eol, expected_mtime=expected_mtime, force=force)

    def _unique_copy_path(self, path, force_copy=False):
        """다른 이름 저장이 기존 파일을 덮어쓰지 않도록 같은 폴더 안의 빈 파일명을 만듭니다."""
        path = os.path.abspath(path)
        if not force_copy and not os.path.exists(path):
            return path

        folder = os.path.dirname(path)
        name = os.path.basename(path)
        stem, ext = os.path.splitext(name)
        if not stem:
            stem = "Memo"

        base = f"{stem} - 복사본"
        candidate = os.path.join(folder, base + ext)
        index = 2
        while os.path.exists(candidate):
            candidate = os.path.join(folder, f"{base} {index}{ext}")
            index += 1
            if index > 10000:
                raise OSError("unique filename generation failed")
        return candidate

    def save_file_as(self, content, suggested_name=None, encoding="UTF-8", eol="LF", source_path=None):
        """현재 탭 내용을 저장 대화상자로 고른 이름의 새 파일로 저장합니다.
        이미 있는 파일을 고른 경우에도 덮어쓰지 않고 자동으로 복사본 파일명을 사용합니다.
        """
        default_name, error = self._normalize_filename(suggested_name or "Memo", default_ext=".txt")
        if error:
            default_name = "Memo.txt"

        chosen = self._window.create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=default_name,
            file_types=("텍스트 파일 (*.txt)", "모든 파일 (*.*)"),
        )
        if not chosen:
            return None

        path = chosen[0] if isinstance(chosen, (list, tuple)) else chosen
        if not os.path.splitext(path)[1]:
            path += ".txt"

        same_as_source = False
        if source_path:
            try:
                same_as_source = os.path.normcase(os.path.abspath(source_path)) == os.path.normcase(os.path.abspath(path))
            except Exception:
                same_as_source = False
        path = self._unique_copy_path(path, force_copy=same_as_source)
        self._register_known_path(path)  # 신뢰의 원천 ①: 네이티브 다른 이름으로 저장 대화상자

        return self._write_text_file(path, content, encoding=encoding, eol=eol, expected_mtime=None, force=True)

    def rename_file(self, current_path, new_name):
        """탭 이름 변경. 저장된 파일이면 실제 파일명도 변경합니다.
        저장되지 않은 메모는 탭 이름만 변경합니다.
        """
        try:
            default_ext = os.path.splitext(current_path or "")[1]
            safe_name, error = self._normalize_filename(new_name, default_ext=default_ext)
            if error:
                return {"ok": False, "error": error}

            if not current_path:
                return {"ok": True, "path": None, "name": safe_name}

            # 보안: 이미 열려 있던 탭의 경로여야 하므로 화이트리스트를 거친다.
            ok, err = self._require_known_path(current_path)
            if not ok:
                return err

            old_path = os.path.abspath(current_path)
            if not os.path.exists(old_path):
                return {"ok": False, "error": "missing"}

            folder = os.path.dirname(old_path)
            new_path_abs = os.path.abspath(os.path.join(folder, safe_name))

            # 이름이 완전히 같으면 그대로 성공 처리합니다.
            if old_path == new_path_abs:
                return {"ok": True, "path": old_path, "name": os.path.basename(old_path), "stat": self._file_stat(old_path)}

            # Windows에서 대소문자만 바꾸는 경우를 위해 임시 이름을 거쳐 변경합니다.
            if os.path.normcase(old_path) == os.path.normcase(new_path_abs):
                tmp_path = os.path.join(folder, f".__memo_rename_tmp_{os.getpid()}__")
                while os.path.exists(tmp_path):
                    tmp_path += "_"
                os.rename(old_path, tmp_path)
                os.rename(tmp_path, new_path_abs)
            else:
                if os.path.exists(new_path_abs):
                    return {"ok": False, "error": "exists"}
                os.rename(old_path, new_path_abs)

            self._register_known_path(new_path_abs)  # 신뢰의 원천: 앱 자신이 방금 수행한 rename의 결과
            return {"ok": True, "path": new_path_abs, "name": os.path.basename(new_path_abs), "stat": self._file_stat(new_path_abs)}
        except OSError as e:
            self._log("rename failed: " + repr(e))
            return {"ok": False, "error": "rename_failed"}
        except Exception:
            self._log(traceback.format_exc())
            return {"ok": False, "error": "rename_failed"}

    # 금고 ─────────────────────────────────────────
    # 설계 노트:
    # - 파생 키는 self._vault_keys에만 상주. 파일/세션에 절대 저장되지 않음.
    # - 각 메서드는 idle timeout을 검사하고, 만료 시 잠금 해제된 상태를 자동 폐기.
    # - JS는 폴더 절대 경로로 금고를 식별한다.
    # - 잘못된 비밀번호와 파일 변조는 동일한 오류로 응답 (오라클 회피).

    def _vault_key_id(self, folder_path):
        """금고를 식별하는 정규화된 키."""
        try:
            return os.path.normcase(os.path.abspath(folder_path))
        except Exception:
            return None

    def _vault_check_idle(self, key_id):
        """마지막 사용에서 idle_seconds 이상 지났으면 자동 잠금."""
        if key_id in self._vault_keys:
            last = self._vault_last_use.get(key_id, 0)
            if time.time() - last > self._vault_idle_seconds:
                self._vault_forget(key_id)

    def _vault_touch(self, key_id):
        self._vault_last_use[key_id] = time.time()

    def _vault_forget(self, key_id):
        """메모리에서 키를 지운다. bytes는 immutable이라 완전 소거는 어려우나
        참조를 끊고 GC 대상으로 만든다."""
        self._vault_keys.pop(key_id, None)
        self._vault_last_use.pop(key_id, None)

    def vault_status(self, folder_path):
        """폴더의 금고 상태 반환. UI가 잠금/열림/일반 폴더를 구분하는 데 사용."""
        try:
            ok, err = self._require_known_path(folder_path)
            if not ok:
                return {"is_vault": False, "unlocked": False, "error": "unsafe_path"}
            if not vault.is_vault_folder(folder_path):
                return {"is_vault": False, "unlocked": False}
            key_id = self._vault_key_id(folder_path)
            self._vault_check_idle(key_id)
            return {"is_vault": True, "unlocked": key_id in self._vault_keys}
        except Exception:
            self._log(traceback.format_exc())
            return {"is_vault": False, "unlocked": False, "error": "status_failed"}

    def vault_create(self, folder_path, password):
        """폴더를 새 금고로 초기화한다.

        보안 원칙: 이미 금고인 폴더는 절대 재초기화하지 않는다 — 안의 메모가
        영구히 잠기기 때문. (write_vault_config가 자체적으로 거부하지만
        여기서도 방어적으로 확인)
        """
        try:
            ok, err = self._require_known_path(folder_path)
            if not ok:
                return {"ok": False, "error": "unsafe_path"}
            if not password or not isinstance(password, str) or len(password) < 8:
                return {"ok": False, "error": "weak_password"}
            if not os.path.isdir(folder_path):
                return {"ok": False, "error": "folder_missing"}
            if vault.is_vault_folder(folder_path):
                return {"ok": False, "error": "already_vault"}

            config = vault.create_vault_config(password)
            if not vault.write_vault_config(folder_path, config):
                return {"ok": False, "error": "write_failed"}

            # 생성 후 자동 잠금 해제 상태로 시작
            key = vault.unlock_with_password(config, password)
            if key is None:
                # 이론적으로 발생 불가지만 방어적으로 처리
                return {"ok": False, "error": "post_verify_failed"}
            key_id = self._vault_key_id(folder_path)
            self._vault_keys[key_id] = key
            self._vault_touch(key_id)
            return {"ok": True, "folder": folder_path}
        except Exception:
            self._log(traceback.format_exc())
            return {"ok": False, "error": "create_failed"}

    def vault_unlock(self, folder_path, password):
        """비밀번호로 금고 잠금 해제. 성공 시 세션 동안 열린 상태 유지."""
        try:
            ok, err = self._require_known_path(folder_path)
            if not ok:
                return {"ok": False, "error": "unsafe_path"}
            if not isinstance(password, str) or not password:
                return {"ok": False, "error": "auth_failed"}
            config = vault.load_vault_config(folder_path)
            if config is None:
                return {"ok": False, "error": "not_a_vault"}

            # validate 결과는 디코딩된 bytes 형태이므로, unlock_with_password가
            # 기대하는 base64 문자열 형태로 다시 감싸 전달할 수도 있으나,
            # 여기서는 vault 내부 함수와 상호운용을 위해 원본 config를 다시 로드.
            with open(os.path.join(folder_path, vault.VAULT_CONFIG_NAME),
                      "r", encoding="utf-8") as f:
                raw_config = json.load(f)
            key = vault.unlock_with_password(raw_config, password)
            if key is None:
                # 비밀번호 오류든 파일 변조든 동일 메시지 (오라클 회피)
                return {"ok": False, "error": "auth_failed"}
            key_id = self._vault_key_id(folder_path)
            self._vault_keys[key_id] = key
            self._vault_touch(key_id)
            return {"ok": True}
        except Exception:
            self._log(traceback.format_exc())
            return {"ok": False, "error": "auth_failed"}

    def vault_lock(self, folder_path):
        """수동 잠금. 메모리에서 키 즉시 제거."""
        try:
            ok, _err = self._require_known_path(folder_path)
            if not ok:
                return {"ok": False, "error": "unsafe_path"}
            key_id = self._vault_key_id(folder_path)
            self._vault_forget(key_id)
            return {"ok": True}
        except Exception:
            return {"ok": False, "error": "lock_failed"}

    def vault_lock_all(self):
        """앱 잠금(모든 금고 잠금). 창 최소화 시 등에 호출."""
        try:
            self._vault_keys.clear()
            self._vault_last_use.clear()
            return {"ok": True}
        except Exception:
            return {"ok": False, "error": "lock_failed"}

    def vault_rotate_password(self, folder_path, old_password, new_password):
        """금고 비밀번호를 변경한다. 성공 시 새 비밀번호로 즉시 잠금 해제된 상태로 전환.

        vault.rotate_password는 트랜잭션 방식이라 실패해도 원본이 손상되지
        않는다(모듈 docstring 참고). 여기서는 그 결과를 UI가 다루기 쉬운
        {ok, error} 형태로 감싸고, 성공 시 메모리 키를 새 키로 교체한다.
        """
        try:
            ok, err = self._require_known_path(folder_path)
            if not ok:
                return {"ok": False, "error": "unsafe_path"}
            if not isinstance(old_password, str) or not old_password:
                return {"ok": False, "error": "auth_failed"}
            if not isinstance(new_password, str) or len(new_password) < 8:
                return {"ok": False, "error": "weak_password"}

            try:
                vault.rotate_password(folder_path, old_password, new_password)
            except vault.VaultRotationError as e:
                self._log("vault_rotate_password failed: " + repr(e))
                # 원인별로 구분해 알려주되, 파일 손상/비번오류는 사용자에게
                # 유용한 정보이므로 오라클 회피 원칙(잠금해제 실패와 달리)을
                # 여기서는 적용하지 않는다 — 이미 old_password를 알고 있는
                # 사용자 본인의 요청이므로 정보 비대칭이 없다.
                msg = str(e)
                return {"ok": False, "error": "rotation_failed", "message": msg}

            # 회전 성공: 메모리에 있던 옛 키를 새 키로 교체해 즉시 사용 가능하게 함
            key_id = self._vault_key_id(folder_path)
            config = vault.load_vault_config(folder_path)
            if config is not None:
                with open(os.path.join(folder_path, vault.VAULT_CONFIG_NAME),
                          "r", encoding="utf-8") as f:
                    raw_config = json.load(f)
                new_key = vault.unlock_with_password(raw_config, new_password)
                if new_key is not None:
                    self._vault_keys[key_id] = new_key
                    self._vault_touch(key_id)
            return {"ok": True}
        except Exception:
            self._log(traceback.format_exc())
            return {"ok": False, "error": "rotation_failed"}

    def pick_folder_for_vault(self):
        """폴더 선택 대화상자를 띄워 사용자가 고른 절대 경로를 반환.

        None을 반환하면 사용자가 취소한 것.
        """
        try:
            result = self._window.create_file_dialog(webview.FOLDER_DIALOG)
            if not result:
                return None
            path = result[0] if isinstance(result, (list, tuple)) else result
            abs_path = os.path.abspath(path)
            self._register_known_path(abs_path)  # 신뢰의 원천 ①: 네이티브 폴더 선택 대화상자
            return abs_path
        except Exception:
            self._log(traceback.format_exc())
            return None

    def _find_vault_key_for_file(self, file_path):
        """파일이 잠금 해제된 금고 안에 있으면 그 파생 키를 반환."""
        if not file_path:
            return None, None
        try:
            abs_path = os.path.abspath(file_path)
            folder = os.path.dirname(abs_path)
            if not vault.is_vault_folder(folder):
                return None, None
            key_id = self._vault_key_id(folder)
            self._vault_check_idle(key_id)
            key = self._vault_keys.get(key_id)
            return key, key_id
        except Exception:
            return None, None

    def vault_read_file(self, file_path):
        """금고 안의 .enc 파일을 복호화해서 평문 텍스트로 반환."""
        try:
            ok, err = self._require_known_path(file_path, allow_vault_folder_fallback=True)
            if not ok:
                return {"ok": False, "error": "unsafe_path"}
            key, key_id = self._find_vault_key_for_file(file_path)
            if key is None:
                return {"ok": False, "error": "locked"}

            abs_path = os.path.abspath(file_path)
            if not os.path.isfile(abs_path):
                return {"ok": False, "error": "missing"}
            size = os.path.getsize(abs_path)
            if size > vault.MAX_VAULT_FILE_BYTES:
                return {"ok": False, "error": "too_large"}

            # 보안(TOCTOU 방어): 금고 파일도 일반 파일과 동일한 경쟁 조건에
            # 노출될 수 있으므로 동일한 원자적 open을 적용한다.
            try:
                with _open_no_follow(abs_path, "rb") as f:
                    blob = f.read()
            except UnsafeSymlinkError:
                self._log(f"TOCTOU: symlink detected at vault open-time for {abs_path}")
                return {"ok": False, "error": "unsafe_path", "reason": "symlink_toctou"}
            try:
                plaintext_bytes = vault.decrypt_bytes(blob, key)
            except vault.VaultAuthFailed:
                return {"ok": False, "error": "auth_failed"}

            content = plaintext_bytes.decode("utf-8", errors="replace")
            self._register_known_path(abs_path)  # 처음 읽은 금고 파일도 이 세션에서 신뢰 대상이 됨
            self._vault_touch(key_id)
            return {
                "ok": True,
                "path": abs_path,
                "name": os.path.basename(abs_path),
                "content": content,
                "encoding": "UTF-8",
                "eol": self._detect_eol(content),
                "stat": self._file_stat(abs_path),
                "vault": True,
            }
        except Exception:
            self._log(traceback.format_exc())
            return {"ok": False, "error": "read_failed"}

    def vault_write_file(self, file_path, content, expected_mtime=None, force=False):
        """평문을 암호화해 .enc 파일로 원자적 저장."""
        try:
            ok, err = self._require_known_path(file_path, allow_vault_folder_fallback=True)
            if not ok:
                return {"ok": False, "error": "unsafe_path"}
            key, key_id = self._find_vault_key_for_file(file_path)
            if key is None:
                return {"ok": False, "error": "locked"}

            abs_path = os.path.abspath(file_path)
            folder = os.path.dirname(abs_path)
            if not os.path.isdir(folder):
                return {"ok": False, "error": "folder_missing"}

            # 보안(TOCTOU 방어): 일반 파일 쓰기와 동일한 이유로 명시적 링크 탐지.
            if os.path.lexists(abs_path):
                try:
                    probe_fd = _open_no_follow_fd(abs_path, writable=False)
                    os.close(probe_fd)
                except UnsafeSymlinkError:
                    self._log(f"TOCTOU: symlink detected at vault write-time for {abs_path}")
                    return {"ok": False, "error": "unsafe_path", "reason": "symlink_toctou"}
                except OSError:
                    pass

            # 외부 변경 감지 (일반 파일과 동일한 규칙 적용)
            if os.path.exists(abs_path):
                stat_info = self._file_stat(abs_path)
                if stat_info.get("readonly"):
                    return {"ok": False, "error": "readonly"}
                if expected_mtime is not None and not force:
                    try:
                        if abs(float(stat_info["mtime"]) - float(expected_mtime)) > 0.001:
                            return {"ok": False, "error": "external_changed", "stat": stat_info}
                    except Exception:
                        pass

            plaintext = str(content or "").encode("utf-8")
            blob = vault.encrypt_bytes(plaintext, key)

            # 원자적 저장 (일반 파일과 동일한 패턴)
            tmp_path = os.path.join(folder, f".__vault_tmp_{os.getpid()}_{int(time.time()*1000)}__")
            try:
                with open(tmp_path, "wb") as f:
                    f.write(blob)
                os.replace(tmp_path, abs_path)
            except OSError as e:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
                self._log("vault write failed: " + repr(e))
                return {"ok": False, "error": "write_failed"}

            self._register_known_path(abs_path)  # 새로 생성된 금고 파일도 이후 세션에서 신뢰 대상이 됨
            self._vault_touch(key_id)
            stat_info = self._file_stat(abs_path)
            return {
                "ok": True,
                "path": abs_path,
                "name": os.path.basename(abs_path),
                "encoding": "UTF-8",
                "eol": "LF",
                "stat": stat_info,
                "vault": True,
            }
        except Exception:
            self._log(traceback.format_exc())
            return {"ok": False, "error": "write_failed"}

    # 창 제어 (커스텀 타이틀바 버튼이 호출) ─────────────
    def minimize_window(self):
        try:
            self._window.minimize()
        except Exception:
            pass

    # 💡 문법 오류가 났던 부분을 안전하게 여러 줄로 분리했습니다.
    def toggle_maximize(self):
        try:
            if self._maximized:
                self._window.restore()
                self._maximized = False
            else:
                self._window.maximize()
                self._maximized = True
        except Exception:
            try:
                self._window.toggle_fullscreen()   # maximize 미지원 환경 대비
            except Exception:
                pass

    def close_window(self):
        try:
            self._window.destroy()
        except Exception:
            pass

    def resize_window(self, w, h):
        try:
            self._window.resize(int(w), int(h))
        except Exception:
            pass


from ui_template import HTML



def load_saved_window_size():
    """이전 종료 시 저장한 창 크기를 읽습니다. 값이 없거나 이상하면 기본 크기를 사용합니다."""
    default = (1040, 720)
    try:
        if not os.path.exists(SESSION_FILE):
            return default
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        settings = data.get("settings") if isinstance(data, dict) else None
        if isinstance(settings, dict) and settings.get("rememberWindowSize") is False:
            return default
        state = data.get("window") if isinstance(data, dict) else None
        width = int((state or {}).get("width") or default[0])
        height = int((state or {}).get("height") or default[1])
        width = max(560, min(width, 3840))
        height = max(360, min(height, 2160))
        return width, height
    except Exception:
        return default


def main():
    set_windows_app_id()
    start_width, start_height = load_saved_window_size()
    api = Api(sys.argv[1:])
    window = webview.create_window(
        "NoteNest", html=HTML, js_api=api,
        width=start_width, height=start_height, min_size=(560, 360),
        background_color="#0e0e13",
        frameless=True, easy_drag=False,        # 네이티브 테두리 제거 + 드래그영역 직접 지정
    )
    api._window = window

    # 중요: closing 이벤트에서 window.evaluate_js("dumpState()")를 호출하지 않습니다.
    # JS → Python close_window 호출 중 다시 Python → JS 동기 호출을 걸면 EXE에서 멈춤이 발생할 수 있습니다.
    # 종료 직전 저장은 JS closeWindow()의 await persist()와 주기적 autosave에 맡깁니다.
    webview.start()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        try:
            os.makedirs(SESSION_DIR, exist_ok=True)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S") + " | fatal\n")
                f.write(traceback.format_exc() + "\n")
        except Exception:
            pass
        raise
