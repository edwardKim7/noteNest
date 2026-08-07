from __future__ import annotations

import unittest

from tests import _bootstrap  # noqa: F401  (side-effect import: sys.path + webview mock)

from memo import Api


class TestFileHelpers(unittest.TestCase):
    def setUp(self) -> None:
        self.api = Api()

    def test_detect_eol(self) -> None:
        self.assertEqual(self.api._detect_eol("a\r\nb"), "CRLF")
        self.assertEqual(self.api._detect_eol("a\rb"), "CR")
        self.assertEqual(self.api._detect_eol("a\nb"), "LF")

    def test_decode_utf8_bom(self) -> None:
        text, encoding = self.api._decode_bytes(b"\xef\xbb\xbfhello")
        self.assertEqual(text, "hello")
        self.assertEqual(encoding, "UTF-8-BOM")

    def test_decode_cp949(self) -> None:
        text, encoding = self.api._decode_bytes("메모".encode("cp949"))
        self.assertEqual(text, "메모")
        self.assertEqual(encoding, "CP949")

    def test_normalize_eol(self) -> None:
        self.assertEqual(self.api._normalize_content_for_eol("a\r\nb\rc", "LF"), "a\nb\nc")
        self.assertEqual(self.api._normalize_content_for_eol("a\nb", "CRLF"), "a\r\nb")

    def test_encoding_mapping(self) -> None:
        self.assertEqual(self.api._encoding_to_python("UTF-8-BOM"), ("utf-8-sig", "UTF-8-BOM"))
        self.assertEqual(self.api._encoding_to_python("CP949"), ("cp949", "CP949"))
        self.assertEqual(self.api._encoding_to_python("UNKNOWN"), ("utf-8", "UTF-8"))

    def test_filename_normalization(self) -> None:
        self.assertEqual(self.api._normalize_filename(" report ", ".txt"), ("report.txt", None))
        self.assertEqual(self.api._normalize_filename("CON", ".txt"), (None, "reserved"))
        self.assertEqual(self.api._normalize_filename("bad:name.txt"), (None, "invalid"))


if __name__ == "__main__":
    unittest.main()
