#!/usr/bin/env python3
"""
Public Encryptor Toolkit

This file intentionally contains only standard encryption profiles that are safe
to publish. It is the public counterpart to the local full-featured encryptor.

Goals:
  - Keep the old "PASSPHRASE|CIPHERTEXT" flow working for simple sharing.
  - Offer stronger public formats that remain easy to inspect and decrypt.
  - Support both interactive and scripted usage.
  - Handle text and file inputs.
  - Include built-in validation, passphrase tooling, self-tests, and benchmarks.

Supported profiles:
  - legacy-cbc
      OpenSSL / CryptoJS compatible AES-256-CBC using EVP_BytesToKey (MD5).
      Output remains compatible with the legacy PASSPHRASE|BASE64 style.

  - gcm-pbkdf2
      AES-256-GCM with PBKDF2-SHA256 derived key material.

  - gcm-scrypt
      AES-256-GCM with scrypt derived key material.

  - cbc-hmac-pbkdf2
      AES-256-CBC with PKCS7 padding and HMAC-SHA256 authentication.

  - cbc-hmac-scrypt
      AES-256-CBC with PKCS7 padding and HMAC-SHA256 authentication using
      scrypt derived keys.

Envelope format:
  - Compact envelope: PUBENC1:<base64url(json)>
  - Armored envelope:
      -----BEGIN PUBLIC ENCRYPTED MESSAGE-----
      ...wrapped compact payload...
      -----END PUBLIC ENCRYPTED MESSAGE-----

Default behavior:
  - Encrypt interactive hidden text using gcm-pbkdf2.
  - Auto-generate a strong passphrase.
  - Embed the passphrase in the output unless disabled.

Examples:
  python encrypt_public.py
    python encrypt_public.py encrypt --message "sample text" --profile gcm-pbkdf2
  python encrypt_public.py encrypt --message-file note.txt --format armored
  python encrypt_public.py encrypt --binary-file archive.bin --profile cbc-hmac-scrypt
  python encrypt_public.py generate-passphrase --length 24 --symbols
  python encrypt_public.py inspect "PASSPHRASE|PUBENC1:..."
  python encrypt_public.py profiles
  python encrypt_public.py self-test
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import json
import os
import random
import string
import sys
import textwrap
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


COMPACT_PREFIX = "PUBENC1:"
ARMOR_HEADER = "-----BEGIN PUBLIC ENCRYPTED MESSAGE-----"
ARMOR_FOOTER = "-----END PUBLIC ENCRYPTED MESSAGE-----"
DEFAULT_PROFILE = "gcm-pbkdf2"
DEFAULT_PASSPHRASE_LENGTH = 24
DEFAULT_WRAP = 88
DEFAULT_PBKDF2_ROUNDS = 220_000
DEFAULT_SCRYPT_N = 2 ** 14
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
MAX_PREVIEW_BYTES = 64
PROGRAM_NAME = "encrypt_public.py"

TEXT_PASSPHRASE_BLACKLIST = {
    "123456",
    "12345678",
    "123456789",
    "000000",
    "111111",
    "112233",
    "121212",
    "123123",
    "12341234",
    "12344321",
    "654321",
    "666666",
    "7777777",
    "888888",
    "999999",
    "147258369",
    "159753",
    "987654321",
    "1q2w3e",
    "1q2w3e4r",
    "123qwe",
    "qwe123",
    "qwerty",
    "qwerty123",
    "asdfgh",
    "zxcvbn",
    "qazwsx",
    "qazwsxedc",
    "zaq12wsx",
    "abcd1234",
}

LOWERCASE_SET = string.ascii_lowercase
UPPERCASE_SET = string.ascii_uppercase
DIGIT_SET = string.digits
SYMBOL_SET = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS_CHARS = set("0O1lI|`")

PROFILE_HELP = {
    "legacy-cbc": "OpenSSL/CryptoJS compatible AES-256-CBC with EVP_BytesToKey (MD5).",
    "gcm-pbkdf2": "AES-256-GCM with PBKDF2-SHA256 and authenticated encryption.",
    "gcm-scrypt": "AES-256-GCM with scrypt KDF and authenticated encryption.",
    "cbc-hmac-pbkdf2": "AES-256-CBC with HMAC-SHA256 using PBKDF2-derived key material.",
    "cbc-hmac-scrypt": "AES-256-CBC with HMAC-SHA256 using scrypt-derived key material.",
}


class EncryptorError(RuntimeError):
    """Base error for public encryptor failures."""


class InputResolutionError(EncryptorError):
    """Raised when the input source cannot be resolved safely."""


class EnvelopeError(EncryptorError):
    """Raised when a compact or armored envelope is malformed."""


class CryptoDependencyError(EncryptorError):
    """Raised when pycryptodome is not available."""


class ValidationError(EncryptorError):
    """Raised when user-supplied options are invalid."""


@dataclass(frozen=True)
class PassphrasePolicy:
    length: int = DEFAULT_PASSPHRASE_LENGTH
    include_lower: bool = True
    include_upper: bool = True
    include_digits: bool = True
    include_symbols: bool = False
    avoid_ambiguous: bool = False
    reject_common: bool = True


@dataclass(frozen=True)
class PayloadSource:
    payload: bytes
    kind: str
    source_name: str
    encoding: str
    original_path: Optional[str] = None


@dataclass(frozen=True)
class KdfSettings:
    name: str
    salt: bytes
    rounds: Optional[int] = None
    n: Optional[int] = None
    r: Optional[int] = None
    p: Optional[int] = None


@dataclass(frozen=True)
class CipherSettings:
    profile: str
    algorithm: str
    mode: str
    iv_or_nonce: bytes
    tag: Optional[bytes] = None
    mac: Optional[bytes] = None


@dataclass(frozen=True)
class Envelope:
    version: int
    profile: str
    created_at: str
    payload_kind: str
    source_name: str
    encoding: str
    compression: str
    original_size: int
    compressed_size: int
    kdf: Dict[str, Any]
    cipher: Dict[str, Any]
    ciphertext_b64: str
    embedded_passphrase: bool
    note: str = ""
    original_path: Optional[str] = None


@dataclass(frozen=True)
class EncryptionResult:
    profile: str
    passphrase: str
    payload_source: PayloadSource
    envelope: Optional[Envelope]
    compact_payload: str
    display_payload: str
    embedded_output: str
    preview: str


@dataclass(frozen=True)
class InspectReport:
    embedded_passphrase: bool
    passphrase_length: Optional[int]
    payload_type: str
    summary_lines: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class BenchmarkResult:
    profile: str
    iterations: int
    bytes_processed: int
    elapsed_seconds: float
    throughput_mib_per_second: float


def require_crypto() -> None:
    try:
        from Crypto.Cipher import AES  # noqa: F401
    except ImportError as exc:
        raise CryptoDependencyError(
            "Missing dependency: run  pip install pycryptodome"
        ) from exc


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def bytes_preview(data: bytes, max_bytes: int = MAX_PREVIEW_BYTES) -> str:
    if not data:
        return "<empty>"
    preview = data[:max_bytes]
    try:
        text = preview.decode("utf-8")
        safe = "".join(ch if ch.isprintable() else "." for ch in text)
    except UnicodeDecodeError:
        safe = preview.hex()
    suffix = "..." if len(data) > max_bytes else ""
    return safe + suffix


def wrap_lines(text: str, width: int = DEFAULT_WRAP) -> str:
    if not text:
        return ""
    return "\n".join(textwrap.wrap(text, width=width, break_long_words=True))


def normalize_whitespace(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").split("\n"))


def safe_json_dumps(data: Dict[str, Any], pretty: bool = False) -> str:
    if pretty:
        return json.dumps(data, indent=2, sort_keys=True)
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EnvelopeError("Invalid base64 payload in envelope") from exc


def b64url_e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_d(text: str) -> bytes:
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise EnvelopeError("Invalid base64url compact payload") from exc


def human_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024.0 or unit == "GiB":
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{num_bytes} B"


def file_basename(path: Optional[str]) -> str:
    if not path:
        return "stdin"
    return Path(path).name


def is_probably_text(data: bytes) -> bool:
    if not data:
        return True
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    bad = sum(1 for ch in decoded if not ch.isprintable() and ch not in "\n\r\t")
    return bad <= max(2, len(decoded) // 100)


def classify_bytes_kind(data: bytes) -> str:
    return "text" if is_probably_text(data) else "binary"


def read_text_file(path: str) -> bytes:
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        raise InputResolutionError(f"Input file not found: {path}")
    return file_path.read_bytes()


def read_payload_source(args: argparse.Namespace) -> PayloadSource:
    candidates = []
    if args.message is not None:
        candidates.append("message")
    if args.message_file is not None:
        candidates.append("message_file")
    if args.binary_file is not None:
        candidates.append("binary_file")
    if args.stdin:
        candidates.append("stdin")
    if args.hex_input is not None:
        candidates.append("hex_input")
    if args.base64_input is not None:
        candidates.append("base64_input")

    if len(candidates) > 1:
        raise InputResolutionError(
            "Choose only one input source: --message, --message-file, --binary-file, --stdin, --hex-input, or --base64-input"
        )

    if args.message is not None:
        payload = args.message.encode("utf-8")
        return PayloadSource(payload, "text", "literal", "utf-8")

    if args.message_file is not None:
        payload = read_text_file(args.message_file)
        return PayloadSource(
            payload=payload,
            kind=classify_bytes_kind(payload),
            source_name=file_basename(args.message_file),
            encoding="file-bytes",
            original_path=str(Path(args.message_file).resolve()),
        )

    if args.binary_file is not None:
        payload = read_text_file(args.binary_file)
        return PayloadSource(
            payload=payload,
            kind="binary",
            source_name=file_basename(args.binary_file),
            encoding="binary-file",
            original_path=str(Path(args.binary_file).resolve()),
        )

    if args.stdin:
        payload = sys.stdin.buffer.read()
        if not payload:
            raise InputResolutionError("No stdin input received.")
        return PayloadSource(payload, classify_bytes_kind(payload), "stdin", "stdin")

    if args.hex_input is not None:
        compact = "".join(args.hex_input.split())
        try:
            payload = bytes.fromhex(compact)
        except ValueError as exc:
            raise InputResolutionError("Invalid hex payload.") from exc
        return PayloadSource(payload, classify_bytes_kind(payload), "hex-literal", "hex")

    if args.base64_input is not None:
        try:
            payload = base64.b64decode(args.base64_input, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise InputResolutionError("Invalid base64 payload.") from exc
        return PayloadSource(payload, classify_bytes_kind(payload), "base64-literal", "base64")

    print("Enter the message to encrypt (input will be hidden):")
    plaintext = getpass.getpass("Message: ", stream=None)
    if not plaintext:
        raise InputResolutionError("No message provided.")
    return PayloadSource(plaintext.encode("utf-8"), "text", "interactive", "utf-8")


def maybe_clear_screen(enabled: bool) -> None:
    if not enabled:
        return
    for _ in range(60):
        print()
    os.system("clear" if sys.platform != "win32" else "cls")


def build_charset(policy: PassphrasePolicy) -> str:
    charset = ""
    if policy.include_lower:
        charset += LOWERCASE_SET
    if policy.include_upper:
        charset += UPPERCASE_SET
    if policy.include_digits:
        charset += DIGIT_SET
    if policy.include_symbols:
        charset += SYMBOL_SET
    if policy.avoid_ambiguous:
        charset = "".join(ch for ch in charset if ch not in AMBIGUOUS_CHARS)
    ensure(bool(charset), "Passphrase policy produced an empty character set.")
    return charset


def estimate_passphrase_entropy(passphrase: str) -> float:
    if not passphrase:
        return 0.0
    pool = 0
    if any(ch in LOWERCASE_SET for ch in passphrase):
        pool += len(LOWERCASE_SET)
    if any(ch in UPPERCASE_SET for ch in passphrase):
        pool += len(UPPERCASE_SET)
    if any(ch in DIGIT_SET for ch in passphrase):
        pool += len(DIGIT_SET)
    if any(ch in SYMBOL_SET for ch in passphrase):
        pool += len(SYMBOL_SET)
    if pool == 0:
        return 0.0
    return round(len(passphrase) * (pool.bit_length()), 2)


def audit_passphrase(passphrase: str) -> List[str]:
    findings: List[str] = []
    lowered = passphrase.lower()
    if len(passphrase) < 14:
        findings.append("Passphrase is shorter than 14 characters.")
    if lowered in TEXT_PASSPHRASE_BLACKLIST:
        findings.append("Passphrase is in the built-in common-passphrase blacklist.")
    if passphrase.isalpha() or passphrase.isdigit():
        findings.append("Passphrase uses only one character class.")
    if len(set(passphrase)) <= max(3, len(passphrase) // 4):
        findings.append("Passphrase has low character variety.")
    if any(passphrase.count(ch * 3) for ch in set(passphrase)):
        findings.append("Passphrase contains repeated triple-character runs.")
    if passphrase == passphrase.lower() and any(ch.isalpha() for ch in passphrase):
        findings.append("Passphrase has no uppercase letters.")
    if passphrase == passphrase.upper() and any(ch.isalpha() for ch in passphrase):
        findings.append("Passphrase has no lowercase letters.")
    if not any(ch in DIGIT_SET for ch in passphrase):
        findings.append("Passphrase has no digits.")
    return findings


def strength_label(passphrase: str) -> str:
    entropy = estimate_passphrase_entropy(passphrase)
    findings = audit_passphrase(passphrase)
    if entropy >= 110 and not findings:
        return "excellent"
    if entropy >= 85 and len(findings) <= 1:
        return "strong"
    if entropy >= 60:
        return "good"
    if entropy >= 40:
        return "fair"
    return "weak"


def generate_passphrase(policy: PassphrasePolicy) -> str:
    charset = build_charset(policy)
    rng = random.SystemRandom()
    required_sets: List[str] = []
    if policy.include_lower:
        required_sets.append("".join(ch for ch in LOWERCASE_SET if ch in charset))
    if policy.include_upper:
        required_sets.append("".join(ch for ch in UPPERCASE_SET if ch in charset))
    if policy.include_digits:
        required_sets.append("".join(ch for ch in DIGIT_SET if ch in charset))
    if policy.include_symbols:
        required_sets.append("".join(ch for ch in SYMBOL_SET if ch in charset))

    for _ in range(256):
        chars = [rng.choice(charset) for _ in range(policy.length)]
        if required_sets:
            for index, required in enumerate(required_sets):
                chars[index % len(chars)] = rng.choice(required)
        rng.shuffle(chars)
        candidate = "".join(chars)
        if policy.reject_common and candidate.lower() in TEXT_PASSPHRASE_BLACKLIST:
            continue
        if policy.avoid_ambiguous and any(ch in AMBIGUOUS_CHARS for ch in candidate):
            continue
        if strength_label(candidate) in {"excellent", "strong", "good"}:
            return candidate
    raise EncryptorError("Unable to generate a passphrase satisfying the requested policy.")


def compress_payload(data: bytes, mode: str) -> Tuple[bytes, str]:
    if mode == "none":
        return data, "none"
    if mode == "zlib":
        compressed = zlib.compress(data, level=9)
        if len(compressed) < len(data):
            return compressed, "zlib"
        return data, "none"
    raise ValidationError(f"Unsupported compression mode: {mode}")


def decompress_payload(data: bytes, mode: str) -> bytes:
    if mode == "none":
        return data
    if mode == "zlib":
        try:
            return zlib.decompress(data)
        except zlib.error as exc:
            raise EnvelopeError("Envelope compression metadata is invalid.") from exc
    raise EnvelopeError(f"Unsupported compression marker: {mode}")


def evp_bytes_to_key(passphrase: bytes, salt: bytes, key_len: int, iv_len: int) -> Tuple[bytes, bytes]:
    digest = b""
    block = b""
    while len(digest) < key_len + iv_len:
        block = hashlib.md5(block + passphrase + salt).digest()
        digest += block
    return digest[:key_len], digest[key_len:key_len + iv_len]


def derive_pbkdf2(passphrase: str, salt: bytes, length: int, rounds: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, rounds, dklen=length)


def derive_scrypt(passphrase: str, salt: bytes, length: int, n: int, r: int, p: int) -> bytes:
    if hasattr(hashlib, "scrypt"):
        return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=length)
    try:
        from Crypto.Protocol.KDF import scrypt as crypto_scrypt  # type: ignore
    except ImportError as exc:
        raise CryptoDependencyError("scrypt support is unavailable in this Python environment.") from exc
    return crypto_scrypt(passphrase.encode("utf-8"), salt, key_len=length, N=n, r=r, p=p)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise EnvelopeError("CBC plaintext is empty after decryption.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise EnvelopeError("Invalid PKCS7 padding.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise EnvelopeError("Invalid PKCS7 padding bytes.")
    return data[:-pad_len]


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7_pad(plaintext))


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return pkcs7_unpad(cipher.decrypt(ciphertext))


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise EnvelopeError("GCM authentication failed.") from exc


def compute_hmac(key: bytes, *parts: bytes) -> bytes:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        digest.update(part)
    return digest.digest()


def make_aad(profile: str, payload_kind: str, compression: str, source_name: str) -> bytes:
    metadata = {
        "profile": profile,
        "payload_kind": payload_kind,
        "compression": compression,
        "source_name": source_name,
    }
    return safe_json_dumps(metadata).encode("utf-8")


def encode_compact_envelope(envelope: Envelope) -> str:
    raw = safe_json_dumps(envelope.__dict__).encode("utf-8")
    return COMPACT_PREFIX + b64url_e(raw)


def decode_compact_envelope(payload: str) -> Envelope:
    if not payload.startswith(COMPACT_PREFIX):
        raise EnvelopeError("Compact public envelope prefix not found.")
    raw = b64url_d(payload[len(COMPACT_PREFIX):])
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError("Compact public envelope JSON is invalid.") from exc
    try:
        return Envelope(**data)
    except TypeError as exc:
        raise EnvelopeError("Compact public envelope is missing required fields.") from exc


def armor_payload(compact: str, width: int = DEFAULT_WRAP) -> str:
    return "\n".join([
        ARMOR_HEADER,
        wrap_lines(compact, width=width),
        ARMOR_FOOTER,
    ])


def dearmor_payload(payload: str) -> str:
    text = normalize_whitespace(payload.strip())
    if ARMOR_HEADER not in text or ARMOR_FOOTER not in text:
        return payload.strip()
    lines = [line.strip() for line in text.splitlines()]
    in_body = False
    body: List[str] = []
    for line in lines:
        if line == ARMOR_HEADER:
            in_body = True
            continue
        if line == ARMOR_FOOTER:
            break
        if in_body and line:
            body.append(line)
    if not body:
        raise EnvelopeError("Armored public message body is empty.")
    return "".join(body)


def split_embedded_passphrase(text: str) -> Tuple[Optional[str], str]:
    if "|" not in text:
        return None, text.strip()
    left, right = text.split("|", 1)
    if left and right:
        return left, right.strip()
    return None, text.strip()


def build_kdf_settings(profile: str) -> KdfSettings:
    salt = os.urandom(16)
    if profile == "legacy-cbc":
        return KdfSettings(name="evp-md5", salt=salt[:8])
    if profile in {"gcm-pbkdf2", "cbc-hmac-pbkdf2"}:
        return KdfSettings(name="pbkdf2-sha256", salt=salt, rounds=DEFAULT_PBKDF2_ROUNDS)
    if profile in {"gcm-scrypt", "cbc-hmac-scrypt"}:
        return KdfSettings(
            name="scrypt",
            salt=salt,
            n=DEFAULT_SCRYPT_N,
            r=DEFAULT_SCRYPT_R,
            p=DEFAULT_SCRYPT_P,
        )
    raise ValidationError(f"Unsupported profile: {profile}")


def derive_profile_key_material(profile: str, passphrase: str, settings: KdfSettings) -> bytes:
    if profile == "legacy-cbc":
        raise ValidationError("legacy-cbc uses EVP key derivation directly.")
    if profile.startswith("gcm-"):
        length = 32
    elif profile.startswith("cbc-hmac-"):
        length = 64
    else:
        raise ValidationError(f"Unsupported profile: {profile}")

    if settings.name == "pbkdf2-sha256":
        assert settings.rounds is not None
        return derive_pbkdf2(passphrase, settings.salt, length, settings.rounds)
    if settings.name == "scrypt":
        assert settings.n is not None and settings.r is not None and settings.p is not None
        return derive_scrypt(passphrase, settings.salt, length, settings.n, settings.r, settings.p)
    raise ValidationError(f"Unsupported KDF: {settings.name}")


def build_envelope_dict(
    profile: str,
    payload_source: PayloadSource,
    compression_mode: str,
    kdf_settings: KdfSettings,
    cipher_settings: CipherSettings,
    ciphertext: bytes,
    embedded_passphrase: bool,
    original_size: int,
    compressed_size: int,
    note: str,
) -> Envelope:
    kdf_data: Dict[str, Any] = {
        "name": kdf_settings.name,
        "salt_b64": b64e(kdf_settings.salt),
    }
    if kdf_settings.rounds is not None:
        kdf_data["rounds"] = kdf_settings.rounds
    if kdf_settings.n is not None:
        kdf_data["n"] = kdf_settings.n
    if kdf_settings.r is not None:
        kdf_data["r"] = kdf_settings.r
    if kdf_settings.p is not None:
        kdf_data["p"] = kdf_settings.p

    cipher_data: Dict[str, Any] = {
        "algorithm": cipher_settings.algorithm,
        "mode": cipher_settings.mode,
        "iv_or_nonce_b64": b64e(cipher_settings.iv_or_nonce),
    }
    if cipher_settings.tag is not None:
        cipher_data["tag_b64"] = b64e(cipher_settings.tag)
    if cipher_settings.mac is not None:
        cipher_data["mac_b64"] = b64e(cipher_settings.mac)

    return Envelope(
        version=1,
        profile=profile,
        created_at=utc_now_iso(),
        payload_kind=payload_source.kind,
        source_name=payload_source.source_name,
        encoding=payload_source.encoding,
        compression=compression_mode,
        original_size=original_size,
        compressed_size=compressed_size,
        kdf=kdf_data,
        cipher=cipher_data,
        ciphertext_b64=b64e(ciphertext),
        embedded_passphrase=embedded_passphrase,
        note=note,
        original_path=payload_source.original_path,
    )


def encrypt_legacy_cbc(payload: PayloadSource, passphrase: str) -> EncryptionResult:
    salt = os.urandom(8)
    key, iv = evp_bytes_to_key(passphrase.encode("utf-8"), salt, 32, 16)
    ciphertext = aes_cbc_encrypt(key, iv, payload.payload)
    raw = b"Salted__" + salt + ciphertext
    compact = b64e(raw)
    embedded = f"{passphrase}|{compact}"
    return EncryptionResult(
        profile="legacy-cbc",
        passphrase=passphrase,
        payload_source=payload,
        envelope=None,
        compact_payload=compact,
        display_payload=compact,
        embedded_output=embedded,
        preview=bytes_preview(payload.payload),
    )


def encrypt_gcm_envelope(
    payload: PayloadSource,
    passphrase: str,
    profile: str,
    compression_mode: str,
    embedded_passphrase: bool,
    note: str,
) -> EncryptionResult:
    compressed, actual_compression = compress_payload(payload.payload, compression_mode)
    settings = build_kdf_settings(profile)
    key = derive_profile_key_material(profile, passphrase, settings)
    nonce = os.urandom(12)
    aad = make_aad(profile, payload.kind, actual_compression, payload.source_name)
    ciphertext, tag = aes_gcm_encrypt(key, nonce, compressed, aad)
    envelope = build_envelope_dict(
        profile=profile,
        payload_source=payload,
        compression_mode=actual_compression,
        kdf_settings=settings,
        cipher_settings=CipherSettings(profile, "AES-256", "GCM", nonce, tag=tag),
        ciphertext=ciphertext,
        embedded_passphrase=embedded_passphrase,
        original_size=len(payload.payload),
        compressed_size=len(compressed),
        note=note,
    )
    compact = encode_compact_envelope(envelope)
    embedded = f"{passphrase}|{compact}" if embedded_passphrase else compact
    return EncryptionResult(
        profile=profile,
        passphrase=passphrase,
        payload_source=payload,
        envelope=envelope,
        compact_payload=compact,
        display_payload=compact,
        embedded_output=embedded,
        preview=bytes_preview(payload.payload),
    )


def encrypt_cbc_hmac_envelope(
    payload: PayloadSource,
    passphrase: str,
    profile: str,
    compression_mode: str,
    embedded_passphrase: bool,
    note: str,
) -> EncryptionResult:
    compressed, actual_compression = compress_payload(payload.payload, compression_mode)
    settings = build_kdf_settings(profile)
    material = derive_profile_key_material(profile, passphrase, settings)
    enc_key = material[:32]
    mac_key = material[32:]
    iv = os.urandom(16)
    aad = make_aad(profile, payload.kind, actual_compression, payload.source_name)
    ciphertext = aes_cbc_encrypt(enc_key, iv, compressed)
    mac = compute_hmac(mac_key, aad, iv, ciphertext)
    envelope = build_envelope_dict(
        profile=profile,
        payload_source=payload,
        compression_mode=actual_compression,
        kdf_settings=settings,
        cipher_settings=CipherSettings(profile, "AES-256", "CBC+HMAC-SHA256", iv, mac=mac),
        ciphertext=ciphertext,
        embedded_passphrase=embedded_passphrase,
        original_size=len(payload.payload),
        compressed_size=len(compressed),
        note=note,
    )
    compact = encode_compact_envelope(envelope)
    embedded = f"{passphrase}|{compact}" if embedded_passphrase else compact
    return EncryptionResult(
        profile=profile,
        passphrase=passphrase,
        payload_source=payload,
        envelope=envelope,
        compact_payload=compact,
        display_payload=compact,
        embedded_output=embedded,
        preview=bytes_preview(payload.payload),
    )


def decrypt_legacy_cbc(payload: str, passphrase: str) -> bytes:
    raw = b64d(payload)
    if raw[:8] != b"Salted__":
        raise EnvelopeError("Legacy CBC payload does not begin with Salted__.")
    salt = raw[8:16]
    ciphertext = raw[16:]
    key, iv = evp_bytes_to_key(passphrase.encode("utf-8"), salt, 32, 16)
    return aes_cbc_decrypt(key, iv, ciphertext)


def derive_material_from_envelope(passphrase: str, envelope: Envelope) -> bytes:
    kdf_name = envelope.kdf["name"]
    salt = b64d(envelope.kdf["salt_b64"])
    if envelope.profile.startswith("gcm-"):
        length = 32
    elif envelope.profile.startswith("cbc-hmac-"):
        length = 64
    else:
        raise EnvelopeError(f"Unsupported envelope profile: {envelope.profile}")
    if kdf_name == "pbkdf2-sha256":
        rounds = int(envelope.kdf["rounds"])
        return derive_pbkdf2(passphrase, salt, length, rounds)
    if kdf_name == "scrypt":
        return derive_scrypt(
            passphrase,
            salt,
            length,
            int(envelope.kdf["n"]),
            int(envelope.kdf["r"]),
            int(envelope.kdf["p"]),
        )
    raise EnvelopeError(f"Unsupported envelope KDF: {kdf_name}")


def decrypt_public_envelope(envelope: Envelope, passphrase: str) -> bytes:
    ciphertext = b64d(envelope.ciphertext_b64)
    iv_or_nonce = b64d(envelope.cipher["iv_or_nonce_b64"])
    aad = make_aad(envelope.profile, envelope.payload_kind, envelope.compression, envelope.source_name)
    if envelope.profile.startswith("gcm-"):
        key = derive_material_from_envelope(passphrase, envelope)
        tag = b64d(envelope.cipher["tag_b64"])
        plaintext = aes_gcm_decrypt(key, iv_or_nonce, ciphertext, tag, aad)
        return decompress_payload(plaintext, envelope.compression)
    if envelope.profile.startswith("cbc-hmac-"):
        material = derive_material_from_envelope(passphrase, envelope)
        enc_key = material[:32]
        mac_key = material[32:]
        expected_mac = b64d(envelope.cipher["mac_b64"])
        actual_mac = compute_hmac(mac_key, aad, iv_or_nonce, ciphertext)
        if not hmac.compare_digest(expected_mac, actual_mac):
            raise EnvelopeError("CBC-HMAC authentication failed.")
        plaintext = aes_cbc_decrypt(enc_key, iv_or_nonce, ciphertext)
        return decompress_payload(plaintext, envelope.compression)
    raise EnvelopeError(f"Unsupported envelope profile: {envelope.profile}")


def render_result(result: EncryptionResult, output_format: str, embed_passphrase: bool) -> str:
    payload = result.compact_payload
    if result.profile == "legacy-cbc":
        payload = result.compact_payload
    elif output_format == "armored":
        payload = armor_payload(result.compact_payload)
    elif output_format == "json":
        assert result.envelope is not None
        payload = safe_json_dumps(result.envelope.__dict__, pretty=True)

    if embed_passphrase:
        if output_format == "json":
            wrapper = {
                "embedded_passphrase": True,
                "passphrase": result.passphrase,
                "payload": payload,
            }
            return safe_json_dumps(wrapper, pretty=True)
        return f"{result.passphrase}|{payload}"

    return payload


def choose_passphrase(args: argparse.Namespace) -> str:
    if args.passphrase:
        return args.passphrase
    if args.passphrase_file:
        content = Path(args.passphrase_file).read_text(encoding="utf-8").strip()
        if not content:
            raise ValidationError("Passphrase file is empty.")
        return content
    if args.prompt_passphrase:
        first = getpass.getpass("Passphrase: ", stream=None)
        second = getpass.getpass("Confirm passphrase: ", stream=None)
        if first != second:
            raise ValidationError("Passphrases do not match.")
        if not first:
            raise ValidationError("Empty passphrase is not allowed.")
        return first
    policy = PassphrasePolicy(
        length=args.length,
        include_lower=not args.no_lower,
        include_upper=not args.no_upper,
        include_digits=not args.no_digits,
        include_symbols=args.symbols,
        avoid_ambiguous=args.avoid_ambiguous,
        reject_common=not args.allow_common_passphrase,
    )
    return generate_passphrase(policy)


def make_encryption_result(args: argparse.Namespace) -> EncryptionResult:
    require_crypto()
    payload = read_payload_source(args)
    maybe_clear_screen(args.clear_screen and payload.source_name == "interactive")
    passphrase = choose_passphrase(args)
    if args.audit_passphrase:
        findings = audit_passphrase(passphrase)
        if findings and not args.allow_weak_passphrase:
            joined = "\n  - ".join([""] + findings)
            raise ValidationError(
                "Passphrase audit failed. Use --allow-weak-passphrase to override:" + joined
            )

    if args.profile == "legacy-cbc":
        return encrypt_legacy_cbc(payload, passphrase)
    if args.profile in {"gcm-pbkdf2", "gcm-scrypt"}:
        return encrypt_gcm_envelope(
            payload=payload,
            passphrase=passphrase,
            profile=args.profile,
            compression_mode=args.compression,
            embedded_passphrase=not args.no_embed_passphrase,
            note=args.note or "",
        )
    if args.profile in {"cbc-hmac-pbkdf2", "cbc-hmac-scrypt"}:
        return encrypt_cbc_hmac_envelope(
            payload=payload,
            passphrase=passphrase,
            profile=args.profile,
            compression_mode=args.compression,
            embedded_passphrase=not args.no_embed_passphrase,
            note=args.note or "",
        )
    raise ValidationError(f"Unsupported profile: {args.profile}")


def inspect_payload(text: str) -> InspectReport:
    embedded_passphrase, raw_payload = split_embedded_passphrase(text.strip())
    summary_lines: List[str] = []
    if raw_payload.startswith(COMPACT_PREFIX):
        envelope = decode_compact_envelope(raw_payload)
        summary_lines.extend([
            f"Payload type       : public compact envelope",
            f"Profile            : {envelope.profile}",
            f"Created at         : {envelope.created_at}",
            f"Kind               : {envelope.payload_kind}",
            f"Source name        : {envelope.source_name}",
            f"Compression        : {envelope.compression}",
            f"Original size      : {human_size(envelope.original_size)}",
            f"Stored size        : {human_size(envelope.compressed_size)}",
            f"KDF                : {envelope.kdf['name']}",
            f"Cipher mode        : {envelope.cipher['mode']}",
            f"Embedded passphrase? : {'yes' if envelope.embedded_passphrase else 'no'}",
        ])
        if envelope.note:
            summary_lines.append(f"Note               : {envelope.note}")
        return InspectReport(
            embedded_passphrase=embedded_passphrase is not None,
            passphrase_length=len(embedded_passphrase) if embedded_passphrase else None,
            payload_type="public-envelope",
            summary_lines=summary_lines,
        )
    if raw_payload.strip().startswith(ARMOR_HEADER):
        compact = dearmor_payload(raw_payload)
        report = inspect_payload(f"{embedded_passphrase + '|' if embedded_passphrase else ''}{compact}")
        return InspectReport(
            embedded_passphrase=report.embedded_passphrase,
            passphrase_length=report.passphrase_length,
            payload_type="armored-public-envelope",
            summary_lines=["Payload type       : armored public envelope"] + report.summary_lines[1:],
        )
    try:
        raw = b64d(raw_payload.strip())
    except EnvelopeError:
        return InspectReport(
            embedded_passphrase=embedded_passphrase is not None,
            passphrase_length=len(embedded_passphrase) if embedded_passphrase else None,
            payload_type="unknown",
            summary_lines=["Payload type       : unknown / unsupported by public inspect"],
        )
    if raw[:8] == b"Salted__":
        summary_lines.extend([
            "Payload type       : legacy OpenSSL/CryptoJS AES-256-CBC",
            f"Salt               : {raw[8:16].hex()}",
            f"Ciphertext bytes   : {len(raw) - 16}",
        ])
        return InspectReport(
            embedded_passphrase=embedded_passphrase is not None,
            passphrase_length=len(embedded_passphrase) if embedded_passphrase else None,
            payload_type="legacy-cbc",
            summary_lines=summary_lines,
        )
    return InspectReport(
        embedded_passphrase=embedded_passphrase is not None,
        passphrase_length=len(embedded_passphrase) if embedded_passphrase else None,
        payload_type="unknown",
        summary_lines=["Payload type       : base64 data, but not a supported public format"],
    )


def self_test_roundtrip(profile: str, message: bytes) -> None:
    passphrase = generate_passphrase(PassphrasePolicy(length=28, include_symbols=True))
    payload = PayloadSource(message, classify_bytes_kind(message), "self-test", "bytes")
    if profile == "legacy-cbc":
        result = encrypt_legacy_cbc(payload, passphrase)
        recovered = decrypt_legacy_cbc(result.compact_payload, passphrase)
        if recovered != message:
            raise EncryptorError(f"Self-test failed for profile {profile}")
        return
    if profile in {"gcm-pbkdf2", "gcm-scrypt"}:
        result = encrypt_gcm_envelope(payload, passphrase, profile, "zlib", True, "self-test")
        assert result.envelope is not None
        recovered = decrypt_public_envelope(result.envelope, passphrase)
        if recovered != message:
            raise EncryptorError(f"Self-test failed for profile {profile}")
        return
    if profile in {"cbc-hmac-pbkdf2", "cbc-hmac-scrypt"}:
        result = encrypt_cbc_hmac_envelope(payload, passphrase, profile, "zlib", True, "self-test")
        assert result.envelope is not None
        recovered = decrypt_public_envelope(result.envelope, passphrase)
        if recovered != message:
            raise EncryptorError(f"Self-test failed for profile {profile}")
        return
    raise EncryptorError(f"Unsupported self-test profile: {profile}")


def run_self_tests() -> None:
    require_crypto()
    samples = [
        b"short text",
        "multiline message\nwith unicode-like-safe-ascii replacement\nand symbols !?".encode("utf-8"),
        os.urandom(256),
    ]
    profiles = list(PROFILE_HELP)
    for profile in profiles:
        for sample in samples:
            self_test_roundtrip(profile, sample)
    print("All public encryption self-tests passed.")


def benchmark_profile(profile: str, iterations: int, payload_size: int) -> BenchmarkResult:
    payload = os.urandom(payload_size)
    source = PayloadSource(payload, "binary", "benchmark", "bytes")
    passphrase = generate_passphrase(PassphrasePolicy(length=32, include_symbols=True))
    start = time.perf_counter()
    for _ in range(iterations):
        if profile == "legacy-cbc":
            encrypt_legacy_cbc(source, passphrase)
        elif profile in {"gcm-pbkdf2", "gcm-scrypt"}:
            encrypt_gcm_envelope(source, passphrase, profile, "none", True, "")
        elif profile in {"cbc-hmac-pbkdf2", "cbc-hmac-scrypt"}:
            encrypt_cbc_hmac_envelope(source, passphrase, profile, "none", True, "")
        else:
            raise ValidationError(f"Unsupported benchmark profile: {profile}")
    elapsed = time.perf_counter() - start
    mib = (payload_size * iterations) / (1024 * 1024)
    throughput = mib / elapsed if elapsed else 0.0
    return BenchmarkResult(profile, iterations, payload_size, elapsed, throughput)


def emit_encrypt_summary(result: EncryptionResult, rendered: str, args: argparse.Namespace) -> None:
    print("-" * 72)
    print(f"Profile            : {result.profile}")
    print(f"Payload kind       : {result.payload_source.kind}")
    print(f"Payload source     : {result.payload_source.source_name}")
    print(f"Preview            : {result.preview}")
    print(f"Passphrase strength  : {strength_label(result.passphrase)}")
    print(f"Passphrase entropy   : {estimate_passphrase_entropy(result.passphrase):.2f}")
    if args.audit_passphrase:
        findings = audit_passphrase(result.passphrase)
        print(f"Passphrase audit     : {'clean' if not findings else '; '.join(findings)}")
    print("Output             :")
    print(rendered)
    print("-" * 72)
    if args.output_file:
        Path(args.output_file).write_text(rendered + "\n", encoding="utf-8")
        print(f"Saved to {args.output_file}")


def command_encrypt(args: argparse.Namespace) -> int:
    result = make_encryption_result(args)
    rendered = render_result(result, args.format, not args.no_embed_passphrase)
    emit_encrypt_summary(result, rendered, args)
    return 0


def command_generate_passphrase(args: argparse.Namespace) -> int:
    policy = PassphrasePolicy(
        length=args.length,
        include_lower=not args.no_lower,
        include_upper=not args.no_upper,
        include_digits=not args.no_digits,
        include_symbols=args.symbols,
        avoid_ambiguous=args.avoid_ambiguous,
        reject_common=not args.allow_common_passphrase,
    )
    passphrase = generate_passphrase(policy)
    print(passphrase)
    print(f"Strength: {strength_label(passphrase)}")
    print(f"Entropy : {estimate_passphrase_entropy(passphrase):.2f}")
    findings = audit_passphrase(passphrase)
    print(f"Audit   : {'clean' if not findings else '; '.join(findings)}")
    return 0


def command_inspect(args: argparse.Namespace) -> int:
    payload = args.payload
    if payload is None:
        print("Paste payload, then press Ctrl-D (Unix) or Ctrl-Z (Windows):")
        payload = sys.stdin.read()
    report = inspect_payload(payload)
    print("-" * 72)
    if report.passphrase_length is not None:
        print(f"Embedded passphrase  : yes (length {report.passphrase_length})")
    else:
        print("Embedded passphrase  : no")
    for line in report.summary_lines:
        print(line)
    print("-" * 72)
    return 0


def command_profiles(_: argparse.Namespace) -> int:
    print("Available public profiles:\n")
    for profile, description in PROFILE_HELP.items():
        print(f"- {profile}\n  {description}\n")
    return 0


def command_self_test(_: argparse.Namespace) -> int:
    run_self_tests()
    return 0


def command_benchmark(args: argparse.Namespace) -> int:
    require_crypto()
    profiles = [args.profile] if args.profile else list(PROFILE_HELP)
    for profile in profiles:
        result = benchmark_profile(profile, args.iterations, args.payload_size)
        print(
            f"{profile:<20} iterations={result.iterations:<4} size={human_size(result.bytes_processed):<10} "
            f"elapsed={result.elapsed_seconds:.3f}s throughput={result.throughput_mib_per_second:.2f} MiB/s"
        )
    return 0


def add_common_encrypt_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--message", help="Literal UTF-8 message to encrypt.")
    parser.add_argument("--message-file", help="Read message bytes from a file.")
    parser.add_argument("--binary-file", help="Read binary bytes from a file.")
    parser.add_argument("--stdin", action="store_true", help="Read plaintext from stdin.")
    parser.add_argument("--hex-input", help="Read plaintext from a hex literal.")
    parser.add_argument("--base64-input", help="Read plaintext from a base64 literal.")
    parser.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        choices=sorted(PROFILE_HELP),
        help="Encryption profile to use.",
    )
    parser.add_argument(
        "--format",
        default="compact",
        choices=["compact", "armored", "json"],
        help="Output formatting for public envelope profiles.",
    )
    parser.add_argument(
        "--compression",
        default="zlib",
        choices=["none", "zlib"],
        help="Compression to attempt before encryption.",
    )
    parser.add_argument("--passphrase", help="Use the provided passphrase.")
    parser.add_argument("--passphrase-file", help="Read passphrase from a file.")
    parser.add_argument(
        "--prompt-passphrase",
        action="store_true",
        help="Prompt for a passphrase instead of generating one.",
    )
    parser.add_argument(
        "--no-embed-passphrase",
        action="store_true",
        help="Do not prefix the final output with PASSPHRASE|.",
    )
    parser.add_argument("--length", type=int, default=DEFAULT_PASSPHRASE_LENGTH, help="Generated passphrase length.")
    parser.add_argument("--symbols", action="store_true", help="Allow symbol characters in generated passphrases.")
    parser.add_argument("--avoid-ambiguous", action="store_true", help="Avoid ambiguous characters like 0/O/1/l.")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters from generated passphrases.")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters from generated passphrases.")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits from generated passphrases.")
    parser.add_argument(
        "--allow-common-passphrase",
        action="store_true",
        help="Allow generated passphrases that would otherwise be rejected as common.",
    )
    parser.add_argument(
        "--audit-passphrase",
        action="store_true",
        help="Audit the chosen passphrase and reject weak passphrases by default.",
    )
    parser.add_argument(
        "--allow-weak-passphrase",
        action="store_true",
        help="Allow a passphrase even if the audit reports weakness.",
    )
    parser.add_argument("--note", help="Optional note stored in public envelopes.")
    parser.add_argument("--output-file", help="Save the final rendered output to a file.")
    parser.add_argument(
        "--clear-screen",
        action="store_true",
        help="Clear the terminal after interactive hidden input.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Public encryptor toolkit with standard-only profiles.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            f"  {PROGRAM_NAME} encrypt --message \"sample text\" --profile gcm-pbkdf2\n"
            f"  {PROGRAM_NAME} encrypt --message-file note.txt --format armored\n"
            f"  {PROGRAM_NAME} generate-passphrase --length 28 --symbols\n"
            f"  {PROGRAM_NAME} inspect \"PASSPHRASE|PUBENC1:...\"\n"
            f"  {PROGRAM_NAME} benchmark --iterations 10 --payload-size 65536\n"
        ),
    )

    sub = parser.add_subparsers(dest="command")

    encrypt_parser = sub.add_parser("encrypt", help="Encrypt a message or file using a public profile.")
    add_common_encrypt_arguments(encrypt_parser)

    passphrase_parser = sub.add_parser("generate-passphrase", help="Generate and audit a passphrase.")
    passphrase_parser.add_argument("--length", type=int, default=DEFAULT_PASSPHRASE_LENGTH)
    passphrase_parser.add_argument("--symbols", action="store_true")
    passphrase_parser.add_argument("--avoid-ambiguous", action="store_true")
    passphrase_parser.add_argument("--no-lower", action="store_true")
    passphrase_parser.add_argument("--no-upper", action="store_true")
    passphrase_parser.add_argument("--no-digits", action="store_true")
    passphrase_parser.add_argument("--allow-common-passphrase", action="store_true")

    inspect_parser = sub.add_parser("inspect", help="Inspect a public payload without decrypting it.")
    inspect_parser.add_argument("payload", nargs="?", help="Payload to inspect. If omitted, read stdin.")

    sub.add_parser("profiles", help="List public encryption profiles.")
    sub.add_parser("self-test", help="Run built-in roundtrip tests.")

    benchmark_parser = sub.add_parser("benchmark", help="Benchmark public profiles.")
    benchmark_parser.add_argument("--profile", choices=sorted(PROFILE_HELP), help="Benchmark only one profile.")
    benchmark_parser.add_argument("--iterations", type=int, default=6)
    benchmark_parser.add_argument("--payload-size", type=int, default=256 * 1024)

    return parser


def run_default_interactive() -> int:
    namespace = argparse.Namespace(
        message=None,
        message_file=None,
        binary_file=None,
        stdin=False,
        hex_input=None,
        base64_input=None,
        profile=DEFAULT_PROFILE,
        format="compact",
        compression="zlib",
        passphrase=None,
        passphrase_file=None,
        prompt_passphrase=False,
        no_embed_passphrase=False,
        length=DEFAULT_PASSPHRASE_LENGTH,
        symbols=True,
        avoid_ambiguous=True,
        no_lower=False,
        no_upper=False,
        no_digits=False,
        allow_common_passphrase=False,
        audit_passphrase=True,
        allow_weak_passphrase=False,
        note="interactive",
        output_file=None,
        clear_screen=True,
    )
    result = make_encryption_result(namespace)
    rendered = render_result(result, namespace.format, not namespace.no_embed_passphrase)
    emit_encrypt_summary(result, rendered, namespace)
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if not args.command:
            return run_default_interactive()
        if args.command == "encrypt":
            return command_encrypt(args)
        if args.command == "generate-passphrase":
            return command_generate_passphrase(args)
        if args.command == "inspect":
            return command_inspect(args)
        if args.command == "profiles":
            return command_profiles(args)
        if args.command == "self-test":
            return command_self_test(args)
        if args.command == "benchmark":
            return command_benchmark(args)
        parser.error(f"Unknown command: {args.command}")
        return 2
    except EncryptorError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
