"""보안 관련 단위 테스트.

배경: Notepad++ CVE-2026-48800처럼 "설정 파일 값은 신뢰 가능하다"고 가정한 코드가
공격 표면이 된다. NoteNest는 세션 로드 시점과 파일 입출력 지점에서 경로/스키마를
검증하는데, 이 방어선이 실제로 동작하는지 확인한다.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

from tests import _bootstrap  # noqa: F401  (side-effect import: sys.path + webview mock)

from memo import (
    _is_safe_user_path,
    _validate_session_schema,
    MAX_OPEN_BYTES,
    SESSION_MAX_TABS,
    SESSION_MAX_TRASH,
)


class TestPathSafety(unittest.TestCase):
    """_is_safe_user_path: 앱이 열어도 되는 안전한 경로인지 검증한다."""

    def test_normal_path_ok(self) -> None:
        ok, reason = _is_safe_user_path(r"C:\Users\me\Documents\memo.txt")
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_empty_path_rejected(self) -> None:
        ok, reason = _is_safe_user_path("")
        self.assertFalse(ok)
        self.assertEqual(reason, "empty")

    def test_none_path_rejected(self) -> None:
        ok, reason = _is_safe_user_path(None)  # type: ignore[arg-type]
        self.assertFalse(ok)

    def test_unc_path_rejected(self) -> None:
        ok, reason = _is_safe_user_path(r"\\attacker\share\evil.txt")
        self.assertFalse(ok)
        self.assertEqual(reason, "unc_path")

    def test_unc_forward_slash_rejected(self) -> None:
        ok, reason = _is_safe_user_path("//attacker/share/evil.txt")
        self.assertFalse(ok)
        self.assertEqual(reason, "unc_path")

    def test_traversal_forward_slash_rejected(self) -> None:
        ok, reason = _is_safe_user_path("../../etc/passwd")
        self.assertFalse(ok)
        self.assertEqual(reason, "path_traversal")

    def test_traversal_backslash_rejected(self) -> None:
        ok, reason = _is_safe_user_path(r"..\..\Windows\System32\config\SAM")
        self.assertFalse(ok)
        self.assertEqual(reason, "path_traversal")

    def test_traversal_embedded_in_absolute_path_rejected(self) -> None:
        ok, reason = _is_safe_user_path(r"C:\Users\me\notes\..\..\..\Windows\win.ini")
        self.assertFalse(ok)
        self.assertEqual(reason, "path_traversal")

    def test_traversal_mixed_slash_rejected(self) -> None:
        ok, reason = _is_safe_user_path("notes/../../../secret.txt")
        self.assertFalse(ok)
        self.assertEqual(reason, "path_traversal")

    def test_dotdot_as_filename_substring_not_rejected(self) -> None:
        ok, reason = _is_safe_user_path(r"C:\Users\me\notes\my..file.txt")
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_dot_prefixed_folder_not_rejected(self) -> None:
        ok, reason = _is_safe_user_path(r"C:\Users\me\..hidden\ok.txt")
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_control_char_rejected(self) -> None:
        ok, reason = _is_safe_user_path("normal.txt\x00.exe")
        self.assertFalse(ok)
        self.assertEqual(reason, "control_char")

    def test_extremely_long_path_rejected(self) -> None:
        ok, reason = _is_safe_user_path("a" * 5000)
        self.assertFalse(ok)
        self.assertEqual(reason, "path_too_long")

    @unittest.skipIf(sys.platform == "win32", "Windows 심볼릭 링크 생성은 관리자 권한 필요할 수 있음")
    def test_symlink_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "real.txt")
            link = os.path.join(tmp, "link.txt")
            with open(target, "w", encoding="utf-8") as f:
                f.write("real")
            os.symlink(target, link)
            ok, reason = _is_safe_user_path(link)
            self.assertFalse(ok)
            self.assertEqual(reason, "symlink")


class TestSessionSchema(unittest.TestCase):
    """_validate_session_schema: 조작·손상된 세션 파일이 앱을 오작동시키지 않는다."""

    def test_none_input_returns_none(self) -> None:
        self.assertIsNone(_validate_session_schema(None))

    def test_non_dict_returns_none(self) -> None:
        self.assertIsNone(_validate_session_schema([1, 2, 3]))
        self.assertIsNone(_validate_session_schema("session"))

    def test_empty_dict_ok(self) -> None:
        self.assertEqual(_validate_session_schema({}), {})

    def test_unc_path_tab_dropped(self) -> None:
        raw = {
            "tabs": [
                {"id": "t1", "path": r"C:\Users\me\ok.txt", "content": "hi"},
                {"id": "t2", "path": r"\\attacker\share\evil.txt", "content": "bad"},
            ]
        }
        result = _validate_session_schema(raw)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["tabs"]), 1)
        self.assertEqual(result["tabs"][0]["id"], "t1")

    def test_null_path_tab_kept(self) -> None:
        raw = {"tabs": [{"id": "new", "path": None, "content": "draft"}]}
        result = _validate_session_schema(raw)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["tabs"]), 1)

    def test_huge_content_tab_dropped(self) -> None:
        raw = {"tabs": [{"id": "big", "path": None, "content": "x" * (MAX_OPEN_BYTES + 1)}]}
        result = _validate_session_schema(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["tabs"], [])

    def test_tab_count_capped(self) -> None:
        raw = {"tabs": [{"id": f"t{i}", "path": None} for i in range(SESSION_MAX_TABS + 100)]}
        result = _validate_session_schema(raw)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["tabs"]), SESSION_MAX_TABS)

    def test_trash_count_capped(self) -> None:
        raw = {"trash": [{"trashId": f"r{i}", "path": None} for i in range(SESSION_MAX_TRASH + 50)]}
        result = _validate_session_schema(raw)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["trash"]), SESSION_MAX_TRASH)

    def test_non_list_tabs_dropped(self) -> None:
        raw = {"tabs": "not a list"}
        result = _validate_session_schema(raw)
        self.assertIsNotNone(result)
        self.assertNotIn("tabs", result)

    def test_non_dict_tab_entries_filtered(self) -> None:
        raw = {"tabs": [{"id": "ok", "path": None}, "junk", 42, None]}
        result = _validate_session_schema(raw)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["tabs"]), 1)

    def test_settings_preserved(self) -> None:
        raw = {"settings": {"theme": "liquid-white-blue", "autoBackupMs": 3000}}
        result = _validate_session_schema(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["settings"]["theme"], "liquid-white-blue")

    def test_active_id_preserved(self) -> None:
        raw = {"activeId": "t1", "activeFolderId": "all"}
        result = _validate_session_schema(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["activeId"], "t1")
        self.assertEqual(result["activeFolderId"], "all")

    def test_vault_tab_content_stripped_on_load(self) -> None:
        raw = {
            "tabs": [
                {"id": "v1", "path": r"C:\vault\note.txt.enc", "vault": True,
                 "content": "SECRET PLAINTEXT LEAK", "savedContent": "SECRET"},
            ]
        }
        result = _validate_session_schema(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["tabs"][0]["content"], "")
        self.assertEqual(result["tabs"][0]["savedContent"], "")

    def test_non_vault_tab_content_preserved(self) -> None:
        raw = {"tabs": [{"id": "n1", "path": None, "vault": False, "content": "일반 메모"}]}
        result = _validate_session_schema(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["tabs"][0]["content"], "일반 메모")


if __name__ == "__main__":
    unittest.main()
