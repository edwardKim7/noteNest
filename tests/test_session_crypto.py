"""세션 파일 저장소 암호화(DPAPI) 테스트.

배경: 인포스틸러류 악성코드는 Notepad++의 자동 백업 폴더
(%APPDATA%\\Notepad++\\backup)처럼 "저장 안 하고 방치한 메모"가 담긴
평문 백업 파일을 통째로 긁어 외부로 반출한다. NoteNest의
~/.simple_memo/session.json도 동일한 노출 지점이다.

방어: Windows DPAPI로 세션 파일 전체를 암호화해, 파일이 그대로 복사되어
반출되어도 다른 계정/기기에서는 열 수 없게 한다.

이 테스트는 실제 Windows API(crypt32.dll)에 의존하지 않는다. 대신
memo._dpapi_protect / memo._dpapi_unprotect를 가역적인 가짜 암호화 함수로
patch해서, "봉투(envelope) 형식과 흐름"이 올바른지 검증한다: 매직 헤더
부착, 평문 미노출, round-trip, 레거시 평문 세션과의 하위 호환, DPAPI 실패
시 평문 저장으로의 안전한 폴백. 실제 crypt32 호출 자체의 정확성은 Windows
환경에서만 검증 가능하므로 이 테스트의 범위 밖이다.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

from tests import _bootstrap  # noqa: F401  (side-effect import: sys.path + webview mock)

import memo
from memo import Api, SESSION_MAGIC


def _fake_protect(data: bytes, description: str = "x") -> bytes:
    """XOR 기반 가역 변환. 암호학적으로 안전하지 않지만, 여기서 검증하려는
    것은 "저장/로드가 이 함수들을 올바른 순서로 호출하는가"이지 암호 강도가
    아니므로 충분하다. 실제 강도는 Windows CryptProtectData가 보장한다."""
    key = 0xAB
    return bytes(b ^ key for b in data)


def _fake_unprotect(blob: bytes) -> bytes:
    key = 0xAB
    return bytes(b ^ key for b in blob)


class _IsolatedSessionTestCase(unittest.TestCase):
    """각 테스트마다 독립된 임시 세션 디렉터리를 사용하도록 격리하는 베이스 클래스."""

    def setUp(self) -> None:
        self._tmpdir_ctx = tempfile.TemporaryDirectory()
        self.tmp = self._tmpdir_ctx.name
        self._orig_session_dir = memo.SESSION_DIR
        self._orig_session_file = memo.SESSION_FILE
        memo.SESSION_DIR = self.tmp
        memo.SESSION_FILE = os.path.join(self.tmp, "session.json")

    def tearDown(self) -> None:
        memo.SESSION_DIR = self._orig_session_dir
        memo.SESSION_FILE = self._orig_session_file
        self._tmpdir_ctx.cleanup()


class TestNonWindowsFallback(_IsolatedSessionTestCase):
    """DPAPI가 없는 플랫폼(현재 테스트 실행 환경 포함)에서의 실제 동작."""

    def test_dpapi_unavailable_on_non_windows(self) -> None:
        if sys.platform != "win32":
            self.assertFalse(memo._dpapi_available())

    def test_save_falls_back_to_plaintext(self) -> None:
        api = Api()
        payload = {"tabs": [{"id": "t1", "path": None, "content": "일반 메모", "vault": False}]}
        self.assertTrue(api.save_session(payload))
        with open(memo.SESSION_FILE, "rb") as f:
            raw = f.read()
        self.assertFalse(raw.startswith(SESSION_MAGIC))

    def test_save_load_roundtrip_plaintext(self) -> None:
        api = Api()
        payload = {"tabs": [{"id": "t1", "path": None, "content": "왕복 테스트", "vault": False}]}
        api.save_session(payload)
        loaded = api.load_session()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["tabs"][0]["content"], "왕복 테스트")


class TestDpapiEnvelope(_IsolatedSessionTestCase):
    """DPAPI가 있는 것처럼 patch한 상태에서의 봉투 형식 검증."""

    def setUp(self) -> None:
        super().setUp()
        self._patches = [
            mock.patch.object(memo, "_dpapi_available", lambda: True),
            mock.patch.object(memo, "_dpapi_protect", _fake_protect),
            mock.patch.object(memo, "_dpapi_unprotect", _fake_unprotect),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self) -> None:
        for p in self._patches:
            p.stop()
        super().tearDown()

    def test_magic_header_attached(self) -> None:
        api = Api()
        payload = {"tabs": [{"id": "t1", "path": None, "content": "secret", "vault": False}]}
        api.save_session(payload)
        with open(memo.SESSION_FILE, "rb") as f:
            raw = f.read()
        self.assertTrue(raw.startswith(SESSION_MAGIC))

    def test_plaintext_not_exposed_on_disk(self) -> None:
        api = Api()
        secret = "API_KEY=sk-should-not-appear-raw"
        payload = {"tabs": [{"id": "t1", "path": None, "content": secret, "vault": False}]}
        api.save_session(payload)
        with open(memo.SESSION_FILE, "rb") as f:
            raw = f.read()
        self.assertNotIn(secret.encode("utf-8"), raw)

    def test_roundtrip_recovers_content(self) -> None:
        api = Api()
        secret = "API_KEY=sk-roundtrip-test"
        payload = {"tabs": [{"id": "t1", "path": None, "content": secret, "vault": False}]}
        api.save_session(payload)
        loaded = api.load_session()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["tabs"][0]["content"], secret)

    def test_legacy_plaintext_session_still_loads(self) -> None:
        legacy = {"tabs": [{"id": "legacy", "path": None, "content": "구버전 메모", "vault": False}]}
        with open(memo.SESSION_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(legacy, ensure_ascii=False))
        api = Api()
        loaded = api.load_session()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["tabs"][0]["content"], "구버전 메모")

    def test_legacy_session_migrates_on_next_save(self) -> None:
        legacy = {"tabs": [{"id": "legacy", "path": None, "content": "마이그레이션 대상", "vault": False}]}
        with open(memo.SESSION_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(legacy, ensure_ascii=False))
        api = Api()
        api.load_session()
        api.save_session(legacy)
        with open(memo.SESSION_FILE, "rb") as f:
            raw = f.read()
        self.assertTrue(raw.startswith(SESSION_MAGIC))

    def test_dpapi_failure_falls_back_to_plaintext_without_losing_session(self) -> None:
        def broken_protect(data: bytes, description: str = "x") -> bytes:
            raise OSError("시뮬레이션된 DPAPI 실패")

        with mock.patch.object(memo, "_dpapi_protect", broken_protect):
            api = Api()
            payload = {"tabs": [{"id": "t1", "path": None, "content": "fallback 확인", "vault": False}]}
            self.assertTrue(api.save_session(payload))
            with open(memo.SESSION_FILE, "rb") as f:
                raw = f.read()
            self.assertFalse(raw.startswith(SESSION_MAGIC))
            loaded = api.load_session()
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["tabs"][0]["content"], "fallback 확인")

    def test_dpapi_protected_session_unreadable_without_dpapi(self) -> None:
        api = Api()
        payload = {"tabs": [{"id": "t1", "path": None, "content": "보호된 내용", "vault": False}]}
        api.save_session(payload)

        with mock.patch.object(memo, "_dpapi_available", lambda: False):
            api2 = Api()
            loaded = api2.load_session()
            self.assertIsNone(loaded)


if __name__ == "__main__":
    unittest.main()
