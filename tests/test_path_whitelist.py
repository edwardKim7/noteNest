"""경로 화이트리스트(capability registry) 테스트.

배경: pywebview는 JS가 window.pywebview.api.* 를 통해 Python 메서드를
거의 다 직접 호출할 수 있는 구조라, 코드베이스 어딘가에 XSS가 생기면
일반 웹앱보다 파급력이 크다(파일 시스템 RPC 브릿지 전체 노출).

방어: 이 세션에서 앱이 "신뢰의 원천"(OS 네이티브 대화상자, 시작 인자,
세션 파일 복원)을 거쳐 실제로 마주친 경로만 화이트리스트에 등록되고,
등록되지 않은 경로는 UNC/순회/심볼릭 링크 검사를 모두 통과하더라도
읽기/쓰기가 거부된다.

이 테스트는 등록되지 않은 임의 경로로 RPC를 직접 호출하는 시나리오
(가상의 XSS가 공격자 JS를 통해 임의 경로로 API를 호출하는 상황과 동일)를
재현해, 실제로 차단되는지 확인한다.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from tests import _bootstrap  # noqa: F401  (side-effect import: sys.path + webview mock)

from memo import Api


class TestKnownPathRegistryBasics(unittest.TestCase):
    """레지스트리 자체의 등록/조회/용량 제한 동작."""

    def test_fresh_session_has_no_known_paths_by_default(self) -> None:
        api = Api()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "never_registered.txt")
            self.assertFalse(api._is_known_path(path))

    def test_register_then_known(self) -> None:
        api = Api()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "note.txt")
            api._register_known_path(path)
            self.assertTrue(api._is_known_path(path))

    def test_register_also_trusts_parent_folder_for_vault_fallback(self) -> None:
        """파일 등록 시 상위 폴더도 함께 등록되어야, 금고 폴더 안에 새로
        생성되는 파일(대화상자 없이 앱이 자동 생성)을 허용할 수 있다."""
        api = Api()
        with tempfile.TemporaryDirectory() as tmp:
            file_path = os.path.join(tmp, "note.txt.enc")
            api._register_known_path(file_path)
            self.assertTrue(api._is_known_path(tmp))

    def test_cap_evicts_oldest(self) -> None:
        api = Api()
        api.KNOWN_PATH_CAP = 5  # 테스트 편의를 위해 낮춤
        with tempfile.TemporaryDirectory() as tmp:
            paths = [os.path.join(tmp, f"f{i}.txt") for i in range(10)]
            for p in paths:
                api._register_known_path(p)
            # 상한 초과분은 앞쪽(가장 오래된 것)부터 제거됨
            self.assertFalse(api._is_known_path(paths[0]))
            self.assertTrue(api._is_known_path(paths[-1]))


class TestWhitelistBlocksUnregisteredPaths(unittest.TestCase):
    """등록되지 않은 임의 경로로의 RPC 호출이 실제로 차단되는지 확인.

    이 클래스의 각 테스트는 "만약 XSS가 발생해 공격자 JS가 이 세션에서
    한 번도 마주친 적 없는 경로로 API를 직접 호출한다면" 시나리오를
    재현한다.
    """

    def setUp(self) -> None:
        self.api = Api()  # 신선한 세션: 화이트리스트가 비어 있음
        self.tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = self.tmp_ctx.name
        self.victim_file = os.path.join(self.tmp, "victim.txt")
        with open(self.victim_file, "w", encoding="utf-8") as f:
            f.write("이 세션에서 대화상자로 연 적 없는 파일")

    def tearDown(self) -> None:
        self.tmp_ctx.cleanup()

    def test_open_path_rejects_unregistered(self) -> None:
        result = self.api.open_path(self.victim_file)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "unsafe_path")
        self.assertEqual(result.get("reason"), "not_registered")

    def test_save_file_existing_path_rejects_unregistered(self) -> None:
        result = self.api.save_file(self.victim_file, "공격자 내용", force=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "unsafe_path")

    def test_check_file_states_rejects_unregistered(self) -> None:
        states = self.api.check_file_states([{"id": "x", "path": self.victim_file}])
        self.assertFalse(states[0]["exists"])
        self.assertEqual(states[0].get("error"), "unsafe_path")

    def test_rename_file_rejects_unregistered(self) -> None:
        result = self.api.rename_file(self.victim_file, "renamed.txt")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "unsafe_path")

    def test_vault_status_rejects_unregistered_folder(self) -> None:
        result = self.api.vault_status(self.tmp)
        self.assertFalse(result["is_vault"])
        self.assertEqual(result.get("error"), "unsafe_path")

    def test_vault_create_rejects_unregistered_folder(self) -> None:
        result = self.api.vault_create(self.tmp, "SomePassword123")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "unsafe_path")

    def test_vault_unlock_rejects_unregistered_folder(self) -> None:
        result = self.api.vault_unlock(self.tmp, "SomePassword123")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "unsafe_path")

    def test_vault_read_file_rejects_unregistered_and_non_vault_folder(self) -> None:
        result = self.api.vault_read_file(self.victim_file)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "unsafe_path")


class TestWhitelistAllowsTrustedOrigins(unittest.TestCase):
    """세 가지 신뢰의 원천을 거친 경로는 정상적으로 허용되는지 회귀 확인."""

    def test_startup_path_is_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "startup.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("시작 인자로 열린 파일")
            api = Api(startup_paths=[path])
            self.assertTrue(api._is_known_path(path))
            result = api.open_path(path)
            self.assertTrue(result["ok"])

    def test_dialog_result_is_trusted_open_file_pattern(self) -> None:
        """open_file()의 대화상자 결과를 직접 흉내내어 등록 후 open_path 확인."""
        api = Api()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "dialog_chosen.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("대화상자로 고른 파일")
            api._register_known_path(path)  # open_file 내부에서 하는 것과 동일한 등록
            result = api.open_path(path)
            self.assertTrue(result["ok"])

    def test_session_restored_path_is_trusted(self) -> None:
        import memo

        with tempfile.TemporaryDirectory() as tmp:
            orig_dir, orig_file = memo.SESSION_DIR, memo.SESSION_FILE
            memo.SESSION_DIR = tmp
            memo.SESSION_FILE = os.path.join(tmp, "session.json")
            try:
                note_path = os.path.join(tmp, "restored.txt")
                with open(note_path, "w", encoding="utf-8") as f:
                    f.write("세션에서 복원된 메모")

                writer_api = Api()
                writer_api.save_session({
                    "tabs": [{"id": "t1", "path": note_path, "content": "세션에서 복원된 메모", "vault": False}]
                })

                reader_api = Api()  # 재시작 시뮬레이션(새 인스턴스)
                loaded = reader_api.load_session()
                self.assertIsNotNone(loaded)
                self.assertTrue(reader_api._is_known_path(note_path))
                result = reader_api.open_path(note_path)
                self.assertTrue(result["ok"])
            finally:
                memo.SESSION_DIR, memo.SESSION_FILE = orig_dir, orig_file

    def test_new_file_inside_known_vault_folder_is_allowed_without_own_dialog(self) -> None:
        """금고는 폴더를 한 번만 대화상자로 선택하고, 그 안에 앱이 자동으로
        여러 메모를 만든다(개별 파일마다 대화상자를 또 띄우지 않음). 이
        흐름이 화이트리스트 때문에 막히면 안 된다."""
        api = Api()
        with tempfile.TemporaryDirectory() as tmp:
            api._register_known_path(tmp)  # pick_folder_for_vault 대화상자 결과를 흉내
            create_result = api.vault_create(tmp, "VaultPassword123")
            self.assertTrue(create_result["ok"])

            # 개별 .enc 파일 경로는 등록된 적 없지만, 등록된 금고 폴더
            # 안이므로 vault_read_file/vault_write_file은 허용되어야 한다.
            new_note = os.path.join(tmp, "auto_created_note.txt.enc")
            write_result = api.vault_write_file(new_note, "자동 생성된 메모")
            self.assertTrue(write_result["ok"])

            read_result = api.vault_read_file(new_note)
            self.assertTrue(read_result["ok"])
            self.assertEqual(read_result["content"], "자동 생성된 메모")


if __name__ == "__main__":
    unittest.main()
