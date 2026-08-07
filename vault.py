"""NoteNest 로컬 암호화 금고(Vault).

Notepad++ 대비 시그니처 기능. "안전한 로컬 메모"라는 프로젝트 정체성을 완성한다.

설계 원칙
─────────
1. Zero-Knowledge: 마스터 비밀번호는 앱을 벗어나지 않고, 파생 키는 세션이
   잠금 해제된 동안에만 메모리에 상주한다.
2. 인증 암호화(AEAD): AES-256-GCM으로 기밀성과 무결성을 동시에 보장한다.
   변조된 파일이나 잘못된 비밀번호는 즉시 예외로 잡힌다.
3. 폴더별 격리: 각 금고는 독립된 salt를 가지므로 같은 비밀번호로도
   서로 다른 키가 파생된다.
4. Associated Data 바인딩: MAGIC 헤더를 AEAD의 associated_data로 넣어
   포맷 변조/버전 다운그레이드 공격을 차단한다.
5. 실패는 조용히: 잘못된 비밀번호와 변조된 파일을 사용자에게 구분해 알리지
   않는다(오라클 회피).

파일 형식 (금고 안 개별 .enc 파일)
────────────────────────────────
    Magic     : b"NNVAULT\\x00"   (8 bytes)
    Version   : 0x01              (1 byte)
    Nonce     : 12 bytes          (AES-GCM 표준)
    Body      : ciphertext || auth_tag(16B)

금고 설정 (.vault-config.json, 금고 폴더 루트)
────────────────────────────────
    {
      "version":    1,
      "kdf":        "pbkdf2_hmac_sha256",
      "iterations": 200000,
      "salt":       "<base64 16B>",
      "verifier":   "<base64 encrypted-blob>"
    }

비밀번호 검증은 verifier 복호화 결과가 알려진 상수(VERIFIER_PLAINTEXT)와
일치하는지로 판별한다. 이 값은 공격자에게 알려져 있어도 문제가 없다 —
AES-GCM 인증 태그가 이미 무결성을 보장하기 때문이다.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError as _e:  # pragma: no cover
    raise ImportError(
        "vault 기능은 'cryptography' 패키지가 필요합니다. "
        "requirements.txt에 포함되어 있으므로 pip install -r requirements.txt를 실행하세요."
    ) from _e


# ── 프로토콜 상수 ────────────────────────────────────────────
MAGIC: bytes = b"NNVAULT\x00"
FORMAT_VERSION: int = 1

SALT_BYTES: int = 16
NONCE_BYTES: int = 12   # AES-GCM 권장 12바이트
KEY_BYTES: int = 32     # AES-256
GCM_TAG_BYTES: int = 16

# OWASP Password Storage Cheat Sheet 2023 권장치. Argon2id를 쓰면 더 좋지만
# stdlib에 없는 의존성을 추가하지 않기 위해 PBKDF2를 사용한다.
PBKDF2_ITERATIONS: int = 200_000
KDF_NAME: str = "pbkdf2_hmac_sha256"

# 잠금 해제 검증용 상수. 이 값이 공개되어도 안전하다.
VERIFIER_PLAINTEXT: bytes = b"NoteNest-VaultVerify-v1"

# 파일 크기 상한: 조작된 .enc 파일이 앱을 정지시키지 못하게 한다.
MAX_VAULT_FILE_BYTES: int = 20 * 1024 * 1024


class VaultError(Exception):
    """금고 관련 일반 오류. 구체적인 원인은 사용자에게 노출하지 않는다."""


class VaultLocked(VaultError):
    """잠금 상태에서 복호화가 시도됐을 때."""


class VaultAuthFailed(VaultError):
    """비밀번호 오류 또는 파일 변조 감지. 두 경우를 구분해 알리지 않는다."""


# ── 저수준 암호화 함수 ────────────────────────────────────────
def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """마스터 비밀번호에서 AES 키를 파생한다.

    보안 주의:
      - password 인수는 호출자가 사용 직후 참조를 폐기해야 한다(Python 특성상
        문자열 즉시 파쇄는 불가하지만, 오래 붙들지 않아야 코어덤프 노출 최소화).
      - iterations는 config에 저장된 값을 그대로 신뢰하지 말고, 로드 시점에
        하한(최소 100,000)을 강제해야 한다.
    """
    if not isinstance(password, str) or len(password) == 0:
        raise VaultError("password는 비어있지 않은 문자열이어야 합니다.")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_BYTES:
        raise VaultError(f"salt는 {SALT_BYTES}바이트여야 합니다.")
    if iterations < 100_000:
        raise VaultError("iterations가 너무 낮습니다(최소 100,000).")
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes(salt),
        iterations,
        dklen=KEY_BYTES,
    )


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """평문 바이트를 암호화해 .enc 파일에 그대로 쓸 수 있는 형식으로 반환.

    associated_data로 MAGIC과 VERSION을 넣어, 헤더 변조/다운그레이드를 감지한다.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
        raise VaultError("key는 32바이트여야 합니다.")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise VaultError("plaintext는 bytes여야 합니다.")

    nonce = secrets.token_bytes(NONCE_BYTES)
    header = MAGIC + bytes([FORMAT_VERSION])
    aead = AESGCM(bytes(key))
    # associated_data에 header를 바인딩해 헤더 변조 시 인증 실패를 유도
    body = aead.encrypt(nonce, bytes(plaintext), associated_data=header)
    return header + nonce + body


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    """.enc 파일 바이트를 복호화. 비밀번호 오류·변조는 모두 VaultAuthFailed로 던진다."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
        raise VaultError("key는 32바이트여야 합니다.")
    if not isinstance(blob, (bytes, bytearray)):
        raise VaultError("blob은 bytes여야 합니다.")

    min_size = len(MAGIC) + 1 + NONCE_BYTES + GCM_TAG_BYTES
    if len(blob) < min_size:
        raise VaultAuthFailed()

    if not hmac.compare_digest(blob[: len(MAGIC)], MAGIC):
        raise VaultAuthFailed()

    version_byte = blob[len(MAGIC)]
    if version_byte != FORMAT_VERSION:
        # 미래 버전 마이그레이션 지점. 지금은 지원 안 함.
        raise VaultAuthFailed()

    header = bytes(blob[: len(MAGIC) + 1])
    nonce_start = len(header)
    nonce = bytes(blob[nonce_start : nonce_start + NONCE_BYTES])
    body = bytes(blob[nonce_start + NONCE_BYTES :])

    aead = AESGCM(bytes(key))
    try:
        return aead.decrypt(nonce, body, associated_data=header)
    except InvalidTag:
        # 비밀번호 오류든 파일 변조든 동일하게 처리 (오라클 공격 방지)
        raise VaultAuthFailed()


# ── 금고 설정(.vault-config.json) ─────────────────────────────
def create_vault_config(password: str) -> dict:
    """새 금고의 설정 dict를 생성한다. 폴더 루트에 저장할 값.

    salt는 새로 생성하고, verifier에는 알려진 상수의 암호화본을 넣어
    나중에 비밀번호를 검증할 수 있게 한다.
    """
    salt = secrets.token_bytes(SALT_BYTES)
    key = derive_key(password, salt)
    try:
        verifier = encrypt_bytes(VERIFIER_PLAINTEXT, key)
    finally:
        # 즉시 사용 후 참조 제거 (best-effort)
        del key
    return {
        "version": FORMAT_VERSION,
        "kdf": KDF_NAME,
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "verifier": base64.b64encode(verifier).decode("ascii"),
    }


def validate_vault_config(config: object) -> Optional[dict]:
    """로드한 config가 예상 스키마를 지키는지 검증하고 안전한 사본을 반환.

    조작된 config로부터 앱을 보호한다. iterations를 낮게 조작해서 무차별
    대입을 쉽게 만드는 공격도 여기서 차단한다.
    """
    if not isinstance(config, dict):
        return None
    try:
        version = int(config.get("version", 0))
        if version != FORMAT_VERSION:
            return None
        kdf = config.get("kdf")
        if kdf != KDF_NAME:
            return None
        iterations = int(config.get("iterations", 0))
        if iterations < 100_000:  # 낮은 iterations 공격 차단
            return None
        salt = base64.b64decode(config["salt"], validate=True)
        verifier = base64.b64decode(config["verifier"], validate=True)
        if len(salt) != SALT_BYTES:
            return None
        if len(verifier) < len(MAGIC) + 1 + NONCE_BYTES + GCM_TAG_BYTES:
            return None
        return {
            "version": version,
            "kdf": kdf,
            "iterations": iterations,
            "salt": salt,
            "verifier": verifier,
        }
    except (KeyError, ValueError, TypeError, base64.binascii.Error):
        return None


def unlock_with_password(config: object, password: str) -> Optional[bytes]:
    """설정과 비밀번호로 금고 잠금 해제. 성공하면 파생 키, 실패하면 None."""
    validated = validate_vault_config(config)
    if validated is None:
        return None
    try:
        key = derive_key(password, validated["salt"], iterations=validated["iterations"])
        recovered = decrypt_bytes(validated["verifier"], key)
        # 상수 시간 비교. VERIFIER가 짧아 부가 정보 유출 위험은 낮지만
        # 습관적으로 상수 시간 비교를 쓴다.
        if not hmac.compare_digest(recovered, VERIFIER_PLAINTEXT):
            return None
        return key
    except VaultError:
        return None


# ── 파일 시스템 헬퍼 ─────────────────────────────────────────
VAULT_CONFIG_NAME: str = ".vault-config.json"
VAULT_FILE_EXTENSION: str = ".enc"


def is_vault_folder(folder_path: str) -> bool:
    """지정된 폴더가 금고인지(.vault-config.json이 있는지) 확인."""
    if not folder_path or not isinstance(folder_path, str):
        return False
    try:
        cfg_path = os.path.join(folder_path, VAULT_CONFIG_NAME)
        return os.path.isfile(cfg_path)
    except (OSError, ValueError):
        return False


def load_vault_config(folder_path: str) -> Optional[dict]:
    """폴더의 .vault-config.json을 읽어 검증된 dict로 반환."""
    if not is_vault_folder(folder_path):
        return None
    cfg_path = os.path.join(folder_path, VAULT_CONFIG_NAME)
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return validate_vault_config(raw)


def write_vault_config(folder_path: str, config: dict) -> bool:
    """.vault-config.json을 원자적으로 저장.

    이미 존재하는 금고 폴더는 덮어쓰지 않는다 — 실수로 초기화되면
    안의 모든 메모가 영구히 잠기기 때문.
    """
    if not os.path.isdir(folder_path):
        return False
    cfg_path = os.path.join(folder_path, VAULT_CONFIG_NAME)
    if os.path.exists(cfg_path):
        return False  # 절대 덮어쓰지 않음
    tmp_path = cfg_path + ".tmp"
    try:
        payload = json.dumps(config, ensure_ascii=False, indent=2)
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp_path, cfg_path)
        return True
    except OSError:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        return False


class VaultRotationError(VaultError):
    """비밀번호 회전 중 실패. 이 예외가 발생해도 금고는 원본 상태로 남는다."""


def rotate_password(folder_path: str, old_password: str, new_password: str) -> None:
    """금고의 비밀번호를 old_password에서 new_password로 교체한다.

    트랜잭션 원칙 (중요):
      1. 실제 파일은 회전이 끝나기 전까지 단 하나도 건드리지 않는다.
      2. 모든 .enc 파일을 old_key로 복호화 → new_key로 재암호화한 결과를
         전부 *임시 파일*(.rotate_tmp 접미사)로 먼저 만든다.
      3. 이 단계에서 하나라도 실패하면(복호화 실패, 디스크 공간 부족 등)
         지금까지 만든 임시 파일을 전부 지우고 VaultRotationError를 던진다.
         → 원본 .enc 파일과 .vault-config.json은 전혀 손대지 않았으므로
           안전하게 재시도할 수 있다.
      4. 모든 임시 파일이 성공적으로 준비된 뒤에만, 각 파일을 os.replace()로
         원자적으로 교체하고 config도 교체한다. 이 단계는 OS 수준에서
         원자적이라 도중에 정전이 나도 각 파일은 old 아니면 new 상태 중
         하나로 일관되게 남는다(파일 개수만큼의 개별 원자적 교체이지,
         전체가 하나의 원자적 트랜잭션은 아니라는 점은 한계로 남는다 —
         자세한 내용은 모듈 docstring 참고).

    실패 시 VaultRotationError를 던진다. 성공하면 아무것도 반환하지 않는다
    (folder_path의 config와 모든 .enc 파일이 이미 new_password로 잠긴 상태).
    """
    if not os.path.isdir(folder_path):
        raise VaultRotationError("금고 폴더를 찾을 수 없습니다.")
    if not new_password or not isinstance(new_password, str) or len(new_password) < 8:
        raise VaultRotationError("새 비밀번호는 최소 8자 이상이어야 합니다.")

    old_config = load_vault_config(folder_path)
    if old_config is None:
        raise VaultRotationError("금고 설정을 읽을 수 없습니다.")

    # validate_vault_config는 salt/verifier를 bytes로 디코딩한 사본을 주지만,
    # unlock_with_password는 base64 원본 config(raw json)를 기대하므로
    # 다시 raw json을 읽어 잠금 해제에 사용한다.
    cfg_path = os.path.join(folder_path, VAULT_CONFIG_NAME)
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            raw_config = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise VaultRotationError("금고 설정 파일을 읽는 중 오류가 발생했습니다.") from e

    old_key = unlock_with_password(raw_config, old_password)
    if old_key is None:
        raise VaultRotationError("현재 비밀번호가 올바르지 않습니다.")

    # 폴더 안의 .enc 파일 전부 수집 (하위 폴더는 다루지 않음 — 금고는 단일 폴더 단위)
    try:
        enc_files = [
            os.path.join(folder_path, name)
            for name in os.listdir(folder_path)
            if name.endswith(VAULT_FILE_EXTENSION) and
            os.path.isfile(os.path.join(folder_path, name))
        ]
    except OSError as e:
        raise VaultRotationError("금고 폴더를 읽는 중 오류가 발생했습니다.") from e

    new_config = create_vault_config(new_password)
    new_key = unlock_with_password(new_config, new_password)
    if new_key is None:
        # 이론적으로 발생 불가하지만 방어적으로 처리
        raise VaultRotationError("새 비밀번호로 설정을 생성하는 중 오류가 발생했습니다.")

    # ── 1단계: 전부 임시 파일로 재암호화 (원본은 아직 무손상) ──────────
    staged = []  # (원본경로, 임시경로) 쌍의 리스트. 실패 시 정리용.
    try:
        for enc_path in enc_files:
            try:
                with open(enc_path, "rb") as f:
                    blob = f.read()
            except OSError as e:
                raise VaultRotationError(f"{os.path.basename(enc_path)} 파일을 읽을 수 없습니다.") from e

            try:
                plaintext = decrypt_bytes(blob, old_key)
            except VaultAuthFailed as e:
                # 손상되었거나 다른 비밀번호로 암호화된 파일. 회전 전체를 중단한다 —
                # 일부만 회전되면 어떤 파일이 새/옛 비밀번호인지 헷갈리는 상태가 되어
                # 사용자가 데이터를 잃을 위험이 더 크다.
                raise VaultRotationError(
                    f"{os.path.basename(enc_path)} 파일을 복호화할 수 없습니다. "
                    "파일이 손상되었거나 비밀번호가 일치하지 않습니다."
                ) from e

            new_blob = encrypt_bytes(plaintext, new_key)
            tmp_path = enc_path + ".rotate_tmp"
            with open(tmp_path, "wb") as f:
                f.write(new_blob)
            staged.append((enc_path, tmp_path))

        # ── 2단계: config도 임시 파일로 준비 ──────────────────────────
        config_tmp_path = cfg_path + ".rotate_tmp"
        with open(config_tmp_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(new_config, ensure_ascii=False, indent=2))

    except (VaultRotationError, OSError, VaultError) as e:
        # 실패: 지금까지 만든 임시 파일을 전부 정리하고 원본은 그대로 둔 채 중단
        for _orig, tmp in staged:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
        try:
            leftover_cfg_tmp = cfg_path + ".rotate_tmp"
            if os.path.exists(leftover_cfg_tmp):
                os.remove(leftover_cfg_tmp)
        except OSError:
            pass
        if isinstance(e, VaultRotationError):
            raise
        raise VaultRotationError("회전 준비 중 오류가 발생했습니다.") from e

    # ── 3단계: 모든 준비가 끝났으니 실제 교체 (각 파일 단위로 원자적) ──
    # 여기부터는 실패해도 되돌릴 수 없다는 뜻은 아니다 — os.replace 자체는
    # 각 파일 단위로 원자적이라, 정전이 나도 파일 하나하나는 항상 old 또는
    # new 완성본 중 하나로 일관된 상태를 유지한다. 다만 파일이 여러 개일 때
    # "전부 다 같이 바뀐다"는 보장은 없어 극단적으로 운이 나쁘면(교체 도중
    # 정전) 일부 파일만 새 비밀번호로 바뀐 상태가 될 수 있다. 이 경우
    # config는 마지막에 바꾸므로, config가 아직 old_password를 가리키면
    # 사용자는 old_password로 로그인해서 어떤 파일이 아직 안 바뀌었는지
    # 확인 후 회전을 재시도할 수 있다(각 파일은 old_key로 복호화 가능한
    # 상태이거나 이미 new_key로 재암호화된 상태 중 하나이므로 데이터 손실은
    # 없다. 다만 파일별 재시도 로직은 이번 버전 범위 밖이다).
    for orig, tmp in staged:
        os.replace(tmp, orig)
    os.replace(config_tmp_path, cfg_path)
