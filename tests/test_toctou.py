"""TOCTOU(Check-Then-Use, CWE-367) 방어 테스트.

배경: _is_safe_user_path()가 심볼릭 링크 여부를 "검사하는 시점"과 실제로
open()으로 파일을 "읽는 시점" 사이에는 시간차가 있다. 그 사이에 파일이
심볼릭 링크로 바꿔치기되면, 사전 검사를 통과했더라도 실제로는 의도치 않은
파일이 열릴 수 있다.

방어: "검사 후 사용"이 아니라 "사용 자체가 검사를 겸하도록" 만든다.
POSIX에서는 os.open(O_NOFOLLOW)가 커널 수준에서 원자적으로 이를 보장한다.
Windows 저수준 코드(CreateFileW + GetFileInformationByHandle)는 이 샌드박스
(Linux)에서 실행할 수 없으므로 이 테스트의 범위 밖이며, 실제 Windows
환경에서 별도 검증이 필요하다.

이 테스트는 실제 심볼릭 링크를 생성해 진짜 공격 시나리오를 재현한다 —
모킹이 아니라 실제 파일시스템 동작을 검증한다.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

from tests import _bootstrap  # noqa: F401  (side-effect import: sys.path + webview mock)

from memo import (
    Api,
    UnsafeSymlinkError,
    _is_safe_user_path,
    _open_no_follow,
)

_SKIP_REASON = (
    "이 테스트는 POSIX O_NOFOLLOW 경로를 검증한다. "
    "Windows 저수준 경로(CreateFileW)는 실제 Windows 환경에서 별도 검증 필요."
)


@unittest.skipIf(sys.platform == "win32", _SKIP_REASON)
class TestOpenNoFollowBasics(unittest.TestCase):
    """_open_no_follow / _open_no_follow_fd의 기본 동작."""

    def test_normal_file_reads_correctly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "normal.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("정상 내용")
            with _open_no_follow(path, "r") as f:
                self.assertEqual(f.read(), "정상 내용")

    def test_symlink_raises_unsafe_symlink_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "target.txt")
            with open(target, "w", encoding="utf-8") as f:
                f.write("타겟 내용")
            link = os.path.join(tmp, "link.txt")
            os.symlink(target, link)

            with self.assertRaises(UnsafeSymlinkError):
                with _open_no_follow(link, "r"):
                    pass

    def test_write_mode_also_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "target.txt")
            with open(target, "w", encoding="utf-8") as f:
                f.write("원본")
            link = os.path.join(tmp, "link.txt")
            os.symlink(target, link)

            with self.assertRaises(UnsafeSymlinkError):
                with _open_no_follow(link, "w") as f:
                    f.write("공격자 내용")

            with open(target, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "원본")  # 실제로 안전한지 확인

    def test_nonexistent_file_raises_oserror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(OSError):
                with _open_no_follow(os.path.join(tmp, "missing.txt"), "r"):
                    pass


@unittest.skipIf(sys.platform == "win32", _SKIP_REASON)
class TestRaceConditionWindow(unittest.TestCase):
    """진짜 TOCTOU 경쟁 조건(사전 검사 통과 → 그 직후 바꿔치기)을 재현."""

    def test_precheck_passes_but_atomic_open_still_blocks_after_swap(self) -> None:
        """이 테스트가 핵심이다: 사전 검사(_is_safe_user_path)가 '정상'이라고
        판단한 *이후*에 파일이 심볼릭 링크로 바뀌어도, 실제 사용 시점의
        원자적 open이 이를 차단하는지 확인한다. 이게 실패하면 사전 검사만
        있고 원자적 방어가 없다는 뜻이라, 바로 이 시나리오가 뚫린다."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "race_target.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("원래는 평범한 파일")

            # 1. 사전 검사 시점: 아직 평범한 파일이므로 통과해야 정상
            ok, _reason = _is_safe_user_path(path)
            self.assertTrue(ok)

            # 2. 경쟁 조건 시뮬레이션: 검사와 실제 사용 사이에 파일이 바뀜
            os.remove(path)
            sensitive = os.path.join(tmp, "sensitive.txt")
            with open(sensitive, "w", encoding="utf-8") as f:
                f.write("경쟁 조건으로 새어나가면 안 되는 내용")
            os.symlink(sensitive, path)

            # 3. 사전 검사는 이미 "통과"를 반환했지만(위 1번), 실제 사용
            #    시점의 원자적 open은 그 시점의 실제 상태를 다시 검사하므로
            #    막혀야 한다.
            with self.assertRaises(UnsafeSymlinkError):
                with _open_no_follow(path, "r"):
                    pass


@unittest.skipIf(sys.platform == "win32", _SKIP_REASON)
class TestApiIntegration(unittest.TestCase):
    """Api 메서드 수준에서 실제 심볼릭 링크 공격이 차단되는지 통합 검증."""

    def setUp(self) -> None:
        self.api = Api()

    def _create_vault_for_test(self, folder, password):
        """실제 앱에서는 pick_folder_for_vault() 대화상자 결과가 자동으로
        화이트리스트에 등록된 뒤 vault_create가 호출된다. 단위 테스트는
        대화상자를 띄울 수 없으므로, 같은 신뢰 단계를 명시적으로 재현한다."""
        self.api._register_known_path(folder)
        return self.api.vault_create(folder, password)

    def test_read_text_file_rejects_disguised_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sensitive = os.path.join(tmp, "sensitive_credentials.txt")
            with open(sensitive, "w", encoding="utf-8") as f:
                f.write("SECRET_DB_PASSWORD=hunter2")
            disguised = os.path.join(tmp, "my_memo.txt")
            os.symlink(sensitive, disguised)

            result = self.api._read_text_file(disguised)
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"], "unsafe_path")
            self.assertNotIn("SECRET_DB_PASSWORD", str(result))

    def test_read_text_file_normal_case_unaffected(self) -> None:
        """TOCTOU 방어 추가로 일반 파일 읽기가 영향받지 않는지 회귀 확인."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "normal.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("평범한 메모")
            result = self.api._read_text_file(path)
            self.assertTrue(result["ok"])
            self.assertEqual(result["content"], "평범한 메모")

    def test_write_text_file_rejects_symlink_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real_target = os.path.join(tmp, "important_config.txt")
            with open(real_target, "w", encoding="utf-8") as f:
                f.write("원본 설정값")
            fake_memo = os.path.join(tmp, "looks_like_memo.txt")
            os.symlink(real_target, fake_memo)

            result = self.api._write_text_file(fake_memo, "공격자가 덮어쓰려는 내용", force=True)
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"], "unsafe_path")

            with open(real_target, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "원본 설정값")  # 실제로 안전한지 확인

    def test_write_text_file_normal_case_unaffected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "new_memo.txt")
            result = self.api._write_text_file(path, "정상 저장 내용")
            self.assertTrue(result["ok"])
            with open(path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "정상 저장 내용")

    def test_vault_read_file_rejects_disguised_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r = self._create_vault_for_test(tmp, "ToctouTest123")
            self.assertTrue(r["ok"])

            outside_secret = os.path.abspath(os.path.join(tmp, os.pardir, "outside_vault_secret.txt"))
            with open(outside_secret, "w", encoding="utf-8") as f:
                f.write("금고 밖 진짜 민감한 파일")
            try:
                fake_enc = os.path.join(tmp, "disguised.txt.enc")
                os.symlink(outside_secret, fake_enc)

                result = self.api.vault_read_file(fake_enc)
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], "unsafe_path")
                self.assertNotIn("금고 밖", str(result))
            finally:
                os.remove(outside_secret)

    def test_vault_write_file_rejects_symlink_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r = self._create_vault_for_test(tmp, "ToctouTest456")
            self.assertTrue(r["ok"])

            outside_target = os.path.abspath(os.path.join(tmp, os.pardir, "outside_target.txt"))
            with open(outside_target, "w", encoding="utf-8") as f:
                f.write("건드리면 안 되는 내용")
            try:
                fake_enc = os.path.join(tmp, "write_disguised.txt.enc")
                os.symlink(outside_target, fake_enc)

                result = self.api.vault_write_file(fake_enc, "공격자 내용 주입 시도")
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], "unsafe_path")

                with open(outside_target, "r", encoding="utf-8") as f:
                    self.assertEqual(f.read(), "건드리면 안 되는 내용")
            finally:
                os.remove(outside_target)

    def test_vault_normal_roundtrip_unaffected(self) -> None:
        """TOCTOU 방어 추가로 정상 Vault 흐름이 영향받지 않는지 회귀 확인."""
        with tempfile.TemporaryDirectory() as tmp:
            self._create_vault_for_test(tmp, "RegressionTest123")
            fp = os.path.join(tmp, "note.txt.enc")
            w = self.api.vault_write_file(fp, "정상 금고 메모")
            self.assertTrue(w["ok"])
            rd = self.api.vault_read_file(fp)
            self.assertTrue(rd["ok"])
            self.assertEqual(rd["content"], "정상 금고 메모")


if __name__ == "__main__":
    unittest.main()
