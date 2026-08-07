"""vault 모듈 테스트.

암호화 코드는 조용히 잘못될 수 있으므로 다음을 명시적으로 확인한다.
1. 정상 케이스: encrypt→decrypt 왕복이 원본을 복구
2. 인증 실패: 비밀번호 오류·헤더 변조·본문 변조·nonce 변조를 모두 감지
3. 스키마 방어: 조작된 config에 취약하지 않음
4. 파라미터 검증: 잘못된 크기/타입을 조기 거부
5. 비결정성: 같은 평문+키가 매번 다른 ciphertext (nonce 재사용 방지)
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
import unittest

from tests import _bootstrap  # noqa: F401  (side-effect import: sys.path + webview mock)

from vault import (
    FORMAT_VERSION,
    KDF_NAME,
    KEY_BYTES,
    MAGIC,
    NONCE_BYTES,
    PBKDF2_ITERATIONS,
    SALT_BYTES,
    VERIFIER_PLAINTEXT,
    VaultAuthFailed,
    VaultError,
    VaultRotationError,
    create_vault_config,
    decrypt_bytes,
    derive_key,
    encrypt_bytes,
    is_vault_folder,
    load_vault_config,
    rotate_password,
    unlock_with_password,
    validate_vault_config,
    write_vault_config,
)


# ── 저수준 암호화 ────────────────────────────────────────────
class TestDeriveKey(unittest.TestCase):
    def test_produces_32_bytes(self) -> None:
        key = derive_key("hunter2", b"\x00" * SALT_BYTES)
        self.assertEqual(len(key), KEY_BYTES)
        self.assertIsInstance(key, bytes)

    def test_deterministic_with_same_input(self) -> None:
        salt = b"\x11" * SALT_BYTES
        self.assertEqual(derive_key("same", salt), derive_key("same", salt))

    def test_different_password_different_key(self) -> None:
        salt = b"\x22" * SALT_BYTES
        self.assertNotEqual(derive_key("a", salt), derive_key("b", salt))

    def test_different_salt_different_key(self) -> None:
        self.assertNotEqual(
            derive_key("pw", b"\x01" * SALT_BYTES), derive_key("pw", b"\x02" * SALT_BYTES)
        )

    def test_empty_password_rejected(self) -> None:
        with self.assertRaises(VaultError):
            derive_key("", b"\x00" * SALT_BYTES)

    def test_short_salt_rejected(self) -> None:
        with self.assertRaises(VaultError):
            derive_key("pw", b"\x00" * 8)

    def test_low_iterations_rejected(self) -> None:
        # 조작된 config로 iterations를 낮추는 공격 차단
        with self.assertRaises(VaultError):
            derive_key("pw", b"\x00" * SALT_BYTES, iterations=1000)


class TestEncryptDecrypt(unittest.TestCase):
    def _fresh_key(self) -> bytes:
        return secrets.token_bytes(KEY_BYTES)

    def test_roundtrip_ascii(self) -> None:
        key = self._fresh_key()
        plaintext = b"hello world"
        self.assertEqual(decrypt_bytes(encrypt_bytes(plaintext, key), key), plaintext)

    def test_roundtrip_utf8(self) -> None:
        key = self._fresh_key()
        plaintext = "안녕하세요 🔐 メモ".encode("utf-8")
        self.assertEqual(decrypt_bytes(encrypt_bytes(plaintext, key), key), plaintext)

    def test_roundtrip_empty(self) -> None:
        key = self._fresh_key()
        self.assertEqual(decrypt_bytes(encrypt_bytes(b"", key), key), b"")

    def test_roundtrip_large(self) -> None:
        key = self._fresh_key()
        plaintext = b"A" * (5 * 1024 * 1024)  # 5MB
        self.assertEqual(decrypt_bytes(encrypt_bytes(plaintext, key), key), plaintext)

    def test_nondeterministic_ciphertext(self) -> None:
        """같은 평문+키를 여러 번 암호화해도 결과가 다름 (nonce 재사용 방지)."""
        key = self._fresh_key()
        pt = b"same input"
        self.assertNotEqual(encrypt_bytes(pt, key), encrypt_bytes(pt, key))

    def test_wrong_key_fails(self) -> None:
        blob = encrypt_bytes(b"secret", self._fresh_key())
        with self.assertRaises(VaultAuthFailed):
            decrypt_bytes(blob, self._fresh_key())

    def test_tampered_ciphertext_fails(self) -> None:
        key = self._fresh_key()
        blob = bytearray(encrypt_bytes(b"secret data", key))
        pos = len(MAGIC) + 1 + NONCE_BYTES + 2
        blob[pos] ^= 0x01
        with self.assertRaises(VaultAuthFailed):
            decrypt_bytes(bytes(blob), key)

    def test_tampered_nonce_fails(self) -> None:
        key = self._fresh_key()
        blob = bytearray(encrypt_bytes(b"secret", key))
        blob[len(MAGIC) + 1] ^= 0x01
        with self.assertRaises(VaultAuthFailed):
            decrypt_bytes(bytes(blob), key)

    def test_tampered_magic_fails(self) -> None:
        key = self._fresh_key()
        blob = bytearray(encrypt_bytes(b"secret", key))
        blob[0] ^= 0x01
        with self.assertRaises(VaultAuthFailed):
            decrypt_bytes(bytes(blob), key)

    def test_downgrade_version_fails(self) -> None:
        """미래의 v2 공격자가 v1으로 다운그레이드해도 associated_data 불일치로 실패."""
        key = self._fresh_key()
        blob = bytearray(encrypt_bytes(b"secret", key))
        blob[len(MAGIC)] = 99
        with self.assertRaises(VaultAuthFailed):
            decrypt_bytes(bytes(blob), key)

    def test_truncated_blob_fails(self) -> None:
        key = self._fresh_key()
        blob = encrypt_bytes(b"secret", key)
        with self.assertRaises(VaultAuthFailed):
            decrypt_bytes(blob[:-5], key)

    def test_empty_blob_fails(self) -> None:
        with self.assertRaises(VaultAuthFailed):
            decrypt_bytes(b"", self._fresh_key())

    def test_wrong_key_size_rejected(self) -> None:
        with self.assertRaises(VaultError):
            encrypt_bytes(b"x", b"\x00" * 16)
        with self.assertRaises(VaultError):
            decrypt_bytes(b"\x00" * 50, b"\x00" * 16)


# ── 금고 설정 및 잠금 해제 ────────────────────────────────────
class TestVaultConfig(unittest.TestCase):
    def test_create_and_unlock_roundtrip(self) -> None:
        config = create_vault_config("MyStrongPassphrase!")
        key = unlock_with_password(config, "MyStrongPassphrase!")
        self.assertIsNotNone(key)
        self.assertEqual(len(key), KEY_BYTES)

    def test_wrong_password_returns_none(self) -> None:
        config = create_vault_config("correct-horse-battery-staple")
        self.assertIsNone(unlock_with_password(config, "wrong-password"))

    def test_two_vaults_have_different_salts(self) -> None:
        """같은 비밀번호로 만든 두 금고가 서로 다른 키를 파생 (salt 격리)."""
        c1 = create_vault_config("password")
        c2 = create_vault_config("password")
        self.assertNotEqual(c1["salt"], c2["salt"])
        k1 = unlock_with_password(c1, "password")
        k2 = unlock_with_password(c2, "password")
        self.assertNotEqual(k1, k2)

    def test_config_has_expected_shape(self) -> None:
        config = create_vault_config("pw")
        self.assertEqual(config["version"], FORMAT_VERSION)
        self.assertEqual(config["kdf"], KDF_NAME)
        self.assertEqual(config["iterations"], PBKDF2_ITERATIONS)
        self.assertEqual(len(base64.b64decode(config["salt"])), SALT_BYTES)

    def test_validate_rejects_low_iterations(self) -> None:
        """조작된 config로 iterations를 낮추는 공격을 차단."""
        config = create_vault_config("pw")
        config["iterations"] = 1000
        self.assertIsNone(validate_vault_config(config))

    def test_validate_rejects_wrong_kdf(self) -> None:
        config = create_vault_config("pw")
        config["kdf"] = "md5_lol"
        self.assertIsNone(validate_vault_config(config))

    def test_validate_rejects_wrong_version(self) -> None:
        config = create_vault_config("pw")
        config["version"] = 999
        self.assertIsNone(validate_vault_config(config))

    def test_validate_rejects_bad_salt_length(self) -> None:
        config = create_vault_config("pw")
        config["salt"] = base64.b64encode(b"\x00" * 8).decode("ascii")
        self.assertIsNone(validate_vault_config(config))

    def test_validate_rejects_non_dict(self) -> None:
        self.assertIsNone(validate_vault_config(None))
        self.assertIsNone(validate_vault_config([1, 2, 3]))
        self.assertIsNone(validate_vault_config("string"))

    def test_validate_rejects_missing_fields(self) -> None:
        self.assertIsNone(validate_vault_config({}))
        self.assertIsNone(validate_vault_config({"version": 1}))

    def test_unlock_with_tampered_verifier_fails(self) -> None:
        """verifier가 변조되면 AES-GCM 인증 실패로 잠금 해제 거부."""
        config = create_vault_config("pw")
        v = bytearray(base64.b64decode(config["verifier"]))
        v[-3] ^= 0x01
        config["verifier"] = base64.b64encode(bytes(v)).decode("ascii")
        self.assertIsNone(unlock_with_password(config, "pw"))


# ── 파일 시스템 통합 ─────────────────────────────────────────
class TestVaultFolder(unittest.TestCase):
    def test_is_vault_folder_true(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".vault-config.json"), "w", encoding="utf-8") as f:
                f.write("{}")
            self.assertTrue(is_vault_folder(tmp))

    def test_is_vault_folder_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(is_vault_folder(tmp))

    def test_is_vault_folder_empty_input(self) -> None:
        self.assertFalse(is_vault_folder(""))
        self.assertFalse(is_vault_folder(None))  # type: ignore[arg-type]

    def test_write_vault_config_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = create_vault_config("pw")
            self.assertTrue(write_vault_config(tmp, config))
            self.assertTrue(is_vault_folder(tmp))

    def test_write_vault_config_refuses_overwrite(self) -> None:
        """기존 금고를 실수로 재초기화하면 안의 메모가 영구 손실되므로 덮어쓰기 거부."""
        with tempfile.TemporaryDirectory() as tmp:
            write_vault_config(tmp, create_vault_config("first"))
            result = write_vault_config(tmp, create_vault_config("second"))
            self.assertFalse(result)

    def test_load_vault_config_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            original = create_vault_config("pw")
            write_vault_config(tmp, original)
            loaded = load_vault_config(tmp)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["version"], original["version"])
            self.assertEqual(loaded["iterations"], original["iterations"])
            self.assertEqual(len(loaded["salt"]), SALT_BYTES)

    def test_load_vault_config_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(load_vault_config(tmp))

    def test_load_vault_config_corrupted_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".vault-config.json"), "w", encoding="utf-8") as f:
                f.write("not-json {{")
            self.assertIsNone(load_vault_config(tmp))

    def test_end_to_end_folder_flow(self) -> None:
        """폴더 초기화 → 로드 → 잠금해제 → 파일 암복호화까지 통합 검증."""
        with tempfile.TemporaryDirectory() as tmp:
            config = create_vault_config("MySecret")
            self.assertTrue(write_vault_config(tmp, config))

            loaded = load_vault_config(tmp)
            self.assertIsNotNone(loaded)

            key = unlock_with_password(config, "MySecret")
            self.assertIsNotNone(key)

            secret_note = "회의록: 오후 3시, 참석자 3명".encode("utf-8")
            enc = encrypt_bytes(secret_note, key)

            note_path = os.path.join(tmp, "meeting.txt.enc")
            with open(note_path, "wb") as f:
                f.write(enc)

            with open(note_path, "rb") as f:
                loaded_enc = f.read()

            self.assertEqual(decrypt_bytes(loaded_enc, key), secret_note)

            wrong_key = unlock_with_password(config, "MySecrer")  # 오타
            self.assertIsNone(wrong_key)


class TestRotatePassword(unittest.TestCase):
    """rotate_password: 트랜잭션 방식 비밀번호 변경.

    핵심 검증 포인트: 성공 시 모든 파일이 새 키로 일관되게 바뀌고, 실패 시
    (비밀번호 오류, 손상 파일, 짧은 새 비밀번호 등) 원본이 바이트 단위로
    전혀 손상되지 않아야 한다.
    """

    def _make_vault(self, tmp, password, files):
        """files: {filename: plaintext_str} 딕셔너리로 금고를 채운다."""
        config = create_vault_config(password)
        write_vault_config(tmp, config)
        key = unlock_with_password(config, password)
        blobs = {}
        for name, text in files.items():
            blob = encrypt_bytes(text.encode("utf-8"), key)
            path = os.path.join(tmp, name)
            with open(path, "wb") as f:
                f.write(blob)
            blobs[name] = blob
        return key, blobs

    def _current_key(self, tmp, password):
        with open(os.path.join(tmp, ".vault-config.json"), "r", encoding="utf-8") as f:
            raw = json.load(f)
        return unlock_with_password(raw, password)

    def test_rotation_success_all_files_reencrypted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            files = {"a.txt.enc": "메모 A", "b.txt.enc": "메모 B 🔐", "c.txt.enc": ""}
            self._make_vault(tmp, "OldPass123", files)

            rotate_password(tmp, "OldPass123", "NewPass456")

            new_key = self._current_key(tmp, "NewPass456")
            self.assertIsNotNone(new_key)
            for name, expected in files.items():
                with open(os.path.join(tmp, name), "rb") as f:
                    blob = f.read()
                self.assertEqual(decrypt_bytes(blob, new_key).decode("utf-8"), expected)

    def test_rotation_old_password_no_longer_works(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._make_vault(tmp, "OldPass123", {"x.txt.enc": "hi"})
            rotate_password(tmp, "OldPass123", "NewPass456")
            self.assertIsNone(self._current_key(tmp, "OldPass123"))

    def test_rotation_no_leftover_temp_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._make_vault(tmp, "OldPass123", {"a.txt.enc": "x", "b.txt.enc": "y"})
            rotate_password(tmp, "OldPass123", "NewPass456")
            leftovers = [n for n in os.listdir(tmp) if "rotate_tmp" in n]
            self.assertEqual(leftovers, [])

    def test_wrong_old_password_raises_and_preserves_original(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _key, blobs = self._make_vault(tmp, "Correct123", {"x.txt.enc": "secret"})

            with self.assertRaises(VaultRotationError):
                rotate_password(tmp, "WrongPassword", "NewPass456")

            self.assertIsNotNone(self._current_key(tmp, "Correct123"))
            with open(os.path.join(tmp, "x.txt.enc"), "rb") as f:
                self.assertEqual(f.read(), blobs["x.txt.enc"])  # 바이트 단위 동일

    def test_weak_new_password_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._make_vault(tmp, "Correct123", {})
            with self.assertRaises(VaultRotationError):
                rotate_password(tmp, "Correct123", "short")

    def test_corrupted_file_aborts_entire_rotation(self) -> None:
        """손상된 파일이 하나라도 있으면 전체 회전을 중단하고, 정상 파일도 그대로 둔다
        (부분 회전은 어떤 파일이 새/옛 비밀번호인지 혼란을 야기하므로 허용하지 않음)."""
        with tempfile.TemporaryDirectory() as tmp:
            key, blobs = self._make_vault(tmp, "Correct123", {"good.txt.enc": "fine"})
            corrupted = bytearray(encrypt_bytes(b"will be corrupted", key))
            corrupted[20] ^= 0xFF
            with open(os.path.join(tmp, "bad.txt.enc"), "wb") as f:
                f.write(bytes(corrupted))

            with self.assertRaises(VaultRotationError):
                rotate_password(tmp, "Correct123", "NewPass789")

            self.assertIsNotNone(self._current_key(tmp, "Correct123"))
            with open(os.path.join(tmp, "good.txt.enc"), "rb") as f:
                self.assertEqual(f.read(), blobs["good.txt.enc"])

    def test_nonexistent_folder_raises(self) -> None:
        with self.assertRaises(VaultRotationError):
            rotate_password("/nonexistent/vault/path/xyz", "a", "NewPass123")

    def test_empty_vault_rotation_succeeds(self) -> None:
        """파일이 하나도 없는 빈 금고도 비밀번호 변경이 가능해야 한다."""
        with tempfile.TemporaryDirectory() as tmp:
            self._make_vault(tmp, "OldPass123", {})
            rotate_password(tmp, "OldPass123", "NewPass456")
            self.assertIsNotNone(self._current_key(tmp, "NewPass456"))


if __name__ == "__main__":
    unittest.main()
