#!/usr/bin/env python3
"""
Code Cracker (educational)

Unified multi-cipher cracker that tests multiple algorithms and encoded-input
variants, then ranks all candidates by how English-like the result is.

Supported ciphers:
  Caesar (incl. ROT13), Atbash, Affine, Vigenere,
  Rail Fence, Columnar Transposition, Monoalphabetic Substitution

Input auto-decode:
  raw, hex, base64, base32, binary (8-bit groups), morse code, reversed
"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections import Counter
from dataclasses import dataclass
import hashlib
import hmac
from itertools import permutations
import json
from math import gcd
from pathlib import Path
import string
import zlib


ENGLISH_FREQ = {
    "a": 8.167,
    "b": 1.492,
    "c": 2.782,
    "d": 4.253,
    "e": 12.702,
    "f": 2.228,
    "g": 2.015,
    "h": 6.094,
    "i": 6.966,
    "j": 0.153,
    "k": 0.772,
    "l": 4.025,
    "m": 2.406,
    "n": 6.749,
    "o": 7.507,
    "p": 1.929,
    "q": 0.095,
    "r": 5.987,
    "s": 6.327,
    "t": 9.056,
    "u": 2.758,
    "v": 0.978,
    "w": 2.360,
    "x": 0.150,
    "y": 1.974,
    "z": 0.074,
}

ENGLISH_BIGRAMS: dict[str, float] = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99,
    "re": 1.85, "on": 1.76, "en": 1.75, "at": 1.49, "es": 1.45,
    "ed": 1.47, "te": 1.35, "ti": 1.34, "or": 1.28, "st": 1.25,
    "ar": 1.21, "nd": 1.18, "to": 1.17, "nt": 1.17, "is": 1.13,
    "it": 1.12, "ng": 1.05, "ha": 1.01, "ou": 0.96, "ea": 0.88,
    "hi": 0.87, "se": 0.87, "al": 0.78, "le": 0.77, "me": 0.76,
}

MORSE_CODE: dict[str, str] = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9",
}

COMPACT_PREFIX = "PUBENC1:"
ARMOR_HEADER = "-----BEGIN PUBLIC ENCRYPTED MESSAGE-----"
ARMOR_FOOTER = "-----END PUBLIC ENCRYPTED MESSAGE-----"
HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}

COMMON_PASSPHRASES = [
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
]


@dataclass(frozen=True)
class Candidate:
    algorithm: str
    key: str
    source_variant: str
    plaintext: str
    score: float


def caesar_shift(text: str, shift: int) -> str:
    """Shift letters by `shift` positions. Non-letters are preserved."""
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def atbash(text: str) -> str:
    """Decode/encode Atbash by mirroring A<->Z and a<->z."""
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(ord("z") - (ord(ch) - ord("a"))))
        elif "A" <= ch <= "Z":
            out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        else:
            out.append(ch)
    return "".join(out)


def mod_inverse(a: int, m: int) -> int | None:
    """Return modular inverse of a mod m, or None if it doesn't exist."""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def affine_decrypt(text: str, a: int, b: int) -> str:
    """Decrypt affine cipher with parameters a, b over alphabet length 26."""
    inv_a = mod_inverse(a, 26)
    if inv_a is None:
        raise ValueError("a has no modular inverse in mod 26")

    out = []
    for ch in text:
        if "a" <= ch <= "z":
            y = ord(ch) - ord("a")
            x = (inv_a * (y - b)) % 26
            out.append(chr(x + ord("a")))
        elif "A" <= ch <= "Z":
            y = ord(ch) - ord("A")
            x = (inv_a * (y - b)) % 26
            out.append(chr(x + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def vigenere_decrypt(text: str, key_shifts: list[int]) -> str:
    """Decrypt Vigenere text with integer shifts (a=0..z=25)."""
    if not key_shifts:
        return text

    out = []
    key_pos = 0
    for ch in text:
        if "a" <= ch <= "z":
            shift = key_shifts[key_pos % len(key_shifts)]
            out.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
            key_pos += 1
        elif "A" <= ch <= "Z":
            shift = key_shifts[key_pos % len(key_shifts)]
            out.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
            key_pos += 1
        else:
            out.append(ch)
    return "".join(out)


def shifts_to_key(key_shifts: list[int]) -> str:
    return "".join(chr(s + ord("A")) for s in key_shifts)


def english_score(text: str) -> float:
    """Lower is better. Combines frequency, word hits, and readability signals."""
    letters = [c.lower() for c in text if c.isalpha()]
    total = len(letters)

    if total == 0:
        return float("inf")

    counts = Counter(letters)
    chi_sq = 0.0

    for letter, expected_pct in ENGLISH_FREQ.items():
        observed = counts.get(letter, 0)
        expected = total * (expected_pct / 100.0)
        if expected > 0:
            chi_sq += (observed - expected) ** 2 / expected

    # Light reward for common space ratio in natural language.
    spaces = text.count(" ")
    space_ratio = spaces / max(1, len(text))
    space_penalty = abs(space_ratio - 0.15) * 30.0

    common_words = {
        "the",
        "be",
        "to",
        "of",
        "and",
        "a",
        "in",
        "that",
        "have",
        "i",
        "it",
        "for",
        "not",
        "on",
        "with",
        "he",
        "as",
        "you",
        "do",
        "at",
        "this",
        "is",
        "code",
        "message",
    }
    words = [w.strip(string.punctuation).lower() for w in text.split()]
    matched = sum(1 for w in words if w in common_words)
    word_bonus = matched * 12.0

    printable_ratio = sum(ch in string.printable for ch in text) / max(1, len(text))
    printable_penalty = (1.0 - printable_ratio) * 100.0

    # Penalize outputs with almost no vowels; natural English tends to have vowels.
    vowel_count = sum(ch in "aeiou" for ch in letters)
    vowel_ratio = vowel_count / max(1, total)
    vowel_penalty = abs(vowel_ratio - 0.38) * 40.0

    # Bigram reward: common English bigrams lower the score.
    lower_text = text.lower()
    bigram_bonus = sum(
        lower_text.count(bg) * freq * 0.5
        for bg, freq in ENGLISH_BIGRAMS.items()
    )

    return chi_sq + space_penalty + printable_penalty + vowel_penalty - word_bonus - bigram_bonus


def decode_hex_variant(text: str) -> str | None:
    compact = "".join(ch for ch in text if not ch.isspace())
    if not compact:
        return None
    if len(compact) % 2 != 0:
        return None
    if any(ch not in string.hexdigits for ch in compact):
        return None
    try:
        decoded = bytes.fromhex(compact).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if decoded else None


def decode_base64_variant(text: str) -> str | None:
    compact = "".join(ch for ch in text.split())
    if len(compact) < 8:
        return None
    b64_alphabet = set(string.ascii_letters + string.digits + "+/=")
    if any(ch not in b64_alphabet for ch in compact):
        return None
    try:
        decoded = base64.b64decode(compact, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if decoded else None


def decode_base32_variant(text: str) -> str | None:
    """Decode base32-encoded text to a UTF-8 string."""
    compact = "".join(text.split()).upper()
    if len(compact) < 8:
        return None
    b32_alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
    if any(c not in b32_alphabet for c in compact):
        return None
    pad = len(compact) % 8
    if pad:
        compact += "=" * (8 - pad)
    try:
        decoded = base64.b32decode(compact).decode("utf-8")
        return decoded if decoded else None
    except Exception:
        return None


def decode_binary_variant(text: str) -> str | None:
    """Decode space-separated 8-bit binary groups to ASCII text."""
    groups = text.strip().split()
    if len(groups) < 2:
        return None
    if not all(len(g) == 8 and all(c in "01" for c in g) for g in groups):
        return None
    try:
        decoded = "".join(chr(int(g, 2)) for g in groups)
    except ValueError:
        return None
    if all(32 <= ord(c) <= 126 for c in decoded):
        return decoded
    return None


def decode_morse_variant(text: str) -> str | None:
    """Decode morse code (dots/dashes, space-separated) to uppercase text."""
    stripped = text.strip()
    if not stripped:
        return None
    if not all(c in ".- /" for c in stripped):
        return None
    tokens = stripped.replace("/", " ").split()
    if len(tokens) < 2:
        return None
    decoded_chars = [MORSE_CODE.get(tok) for tok in tokens]
    if any(c is None for c in decoded_chars):
        return None
    return "".join(decoded_chars)  # type: ignore[arg-type]


def build_variants(ciphertext: str) -> dict[str, str]:
    """Build input variants to support encoded payloads before cracking."""
    variants: dict[str, str] = {"raw": ciphertext}

    hex_decoded = decode_hex_variant(ciphertext)
    if hex_decoded is not None:
        variants["hex-decoded"] = hex_decoded

    b64_decoded = decode_base64_variant(ciphertext)
    if b64_decoded is not None:
        variants["base64-decoded"] = b64_decoded

    b32_decoded = decode_base32_variant(ciphertext)
    if b32_decoded is not None:
        variants["base32-decoded"] = b32_decoded

    binary_decoded = decode_binary_variant(ciphertext)
    if binary_decoded is not None:
        variants["binary-decoded"] = binary_decoded

    morse_decoded = decode_morse_variant(ciphertext)
    if morse_decoded is not None:
        variants["morse-decoded"] = morse_decoded

    reversed_text = ciphertext[::-1]
    if reversed_text != ciphertext:
        variants["reversed"] = reversed_text

    return variants


def crack_caesar(ciphertext: str, source_variant: str) -> list[Candidate]:
    results: list[Candidate] = []
    for decode_shift in range(26):
        plaintext = caesar_shift(ciphertext, -decode_shift)
        score = english_score(plaintext)
        results.append(
            Candidate(
                algorithm="caesar",
                key=f"shift={decode_shift}",
                source_variant=source_variant,
                plaintext=plaintext,
                score=score,
            )
        )

    return results


def crack_atbash(ciphertext: str, source_variant: str) -> list[Candidate]:
    plaintext = atbash(ciphertext)
    return [
        Candidate(
            algorithm="atbash",
            key="mirror",
            source_variant=source_variant,
            plaintext=plaintext,
            score=english_score(plaintext),
        )
    ]


def crack_affine(ciphertext: str, source_variant: str) -> list[Candidate]:
    results: list[Candidate] = []
    valid_a = [a for a in range(1, 26) if gcd(a, 26) == 1]

    for a in valid_a:
        for b in range(26):
            plaintext = affine_decrypt(ciphertext, a=a, b=b)
            results.append(
                Candidate(
                    algorithm="affine",
                    key=f"a={a},b={b}",
                    source_variant=source_variant,
                    plaintext=plaintext,
                    score=english_score(plaintext),
                )
            )

    return results


def crack_vigenere(ciphertext: str, source_variant: str, max_key_len: int) -> list[Candidate]:
    """
    Estimate Vigenere key by solving each key-position as a Caesar crack.
    This is efficient and works well for short to medium messages.
    """
    letters_only = [c for c in ciphertext if c.isalpha()]
    if len(letters_only) < 4:
        return []

    results: list[Candidate] = []
    for key_len in range(1, max(2, max_key_len + 1)):
        key_shifts: list[int] = []

        buckets: list[list[str]] = [[] for _ in range(key_len)]
        alpha_index = 0
        for ch in ciphertext:
            if ch.isalpha():
                buckets[alpha_index % key_len].append(ch)
                alpha_index += 1

        for i in range(key_len):
            slice_chars = buckets[i]
            if not slice_chars:
                key_shifts.append(0)
                continue

            best_shift = 0
            best_shift_score = float("inf")
            slice_text = "".join(slice_chars)
            for shift in range(26):
                decoded_slice = caesar_shift(slice_text, -shift)
                score = english_score(decoded_slice)
                if score < best_shift_score:
                    best_shift_score = score
                    best_shift = shift

            key_shifts.append(best_shift)

        plaintext = vigenere_decrypt(ciphertext, key_shifts)
        results.append(
            Candidate(
                algorithm="vigenere",
                key=f"len={key_len},key={shifts_to_key(key_shifts)}",
                source_variant=source_variant,
                plaintext=plaintext,
                score=english_score(plaintext),
            )
        )

    return results


# ── Rail Fence ────────────────────────────────────────────────────────────
def rail_fence_decrypt(text: str, rails: int) -> str:
    """Decrypt rail fence (zigzag) cipher with the given number of rails."""
    n = len(text)
    if rails <= 1 or rails >= n:
        return text
    cycle = 2 * (rails - 1)
    counts = [0] * rails
    for i in range(n):
        r = i % cycle
        if r >= rails:
            r = cycle - r
        counts[r] += 1
    rails_chars: list[list[str]] = []
    pos = 0
    for count in counts:
        rails_chars.append(list(text[pos : pos + count]))
        pos += count
    indices = [0] * rails
    result = []
    for i in range(n):
        r = i % cycle
        if r >= rails:
            r = cycle - r
        result.append(rails_chars[r][indices[r]])
        indices[r] += 1
    return "".join(result)


def crack_rail_fence(ciphertext: str, source_variant: str, max_rails: int = 8) -> list[Candidate]:
    results: list[Candidate] = []
    if len(ciphertext) < 4:
        return results
    for rails in range(2, min(max_rails + 1, len(ciphertext))):
        plaintext = rail_fence_decrypt(ciphertext, rails)
        results.append(
            Candidate(
                algorithm="rail_fence",
                key=f"rails={rails}",
                source_variant=source_variant,
                plaintext=plaintext,
                score=english_score(plaintext),
            )
        )
    return results


# ── Columnar Transposition ────────────────────────────────────────────────
def columnar_decrypt(text: str, key_order: list[int]) -> str:
    """Decrypt columnar transposition given the column reading order."""
    n = len(text)
    num_cols = len(key_order)
    if num_cols == 0 or n == 0:
        return text
    num_rows = (n + num_cols - 1) // num_cols
    extra = num_rows * num_cols - n  # columns that are one row shorter
    col_lengths = [num_rows] * num_cols
    for i in range(extra):
        col_lengths[key_order[-(i + 1)]] = num_rows - 1
    cols: list[list[str]] = [[] for _ in range(num_cols)]
    pos = 0
    for col_idx in key_order:
        length = col_lengths[col_idx]
        cols[col_idx] = list(text[pos : pos + length])
        pos += length
    result = []
    for row in range(num_rows):
        for col in range(num_cols):
            if row < len(cols[col]):
                result.append(cols[col][row])
    return "".join(result)


def crack_columnar(ciphertext: str, source_variant: str, max_cols: int = 5) -> list[Candidate]:
    results: list[Candidate] = []
    if len(ciphertext) < 6:
        return results
    for num_cols in range(2, max_cols + 1):
        for perm in permutations(range(num_cols)):
            try:
                plaintext = columnar_decrypt(ciphertext, list(perm))
                results.append(
                    Candidate(
                        algorithm="columnar",
                        key=f"cols={num_cols},order={''.join(str(p) for p in perm)}",
                        source_variant=source_variant,
                        plaintext=plaintext,
                        score=english_score(plaintext),
                    )
                )
            except Exception:
                pass
    return results


# ── Monoalphabetic Substitution ───────────────────────────────────────────
def crack_substitution(ciphertext: str, source_variant: str) -> list[Candidate]:
    """Frequency-analysis monoalphabetic substitution crack (heuristic)."""
    letters = [c.lower() for c in ciphertext if c.isalpha()]
    if len(letters) < 20:
        return []
    counts = Counter(letters)
    sorted_cipher = [ch for ch, _ in counts.most_common()]
    sorted_english = sorted(ENGLISH_FREQ, key=lambda k: ENGLISH_FREQ[k], reverse=True)
    results: list[Candidate] = []
    for offset in range(min(6, len(sorted_cipher))):
        mapping: dict[str, str] = {}
        for i, eng_ch in enumerate(sorted_english):
            ci = (i + offset) % len(sorted_cipher)
            mapping[sorted_cipher[ci]] = eng_ch
        plaintext = "".join(
            (mapping.get(c.lower(), c.lower()).upper() if c.isupper() else mapping.get(c, c))
            if c.isalpha() else c
            for c in ciphertext
        )
        results.append(
            Candidate(
                algorithm="substitution",
                key=f"freq-offset={offset}",
                source_variant=source_variant,
                plaintext=plaintext,
                score=english_score(plaintext),
            )
        )
    return results


def algorithm_preference(algorithm: str) -> int:
    """Lower is preferred when scores tie."""
    order = {
        "caesar": 0,
        "atbash": 1,
        "affine": 2,
        "vigenere": 3,
        "rail_fence": 4,
        "columnar": 5,
        "substitution": 6,
    }
    return order.get(algorithm, 99)


def crack_all(ciphertext: str, top_n: int, max_key_len: int) -> list[Candidate]:
    """Run all supported cracker versions and return best global candidates."""
    variants = build_variants(ciphertext)
    all_results: list[Candidate] = []

    for variant_name, variant_text in variants.items():
        all_results.extend(crack_caesar(variant_text, source_variant=variant_name))
        all_results.extend(crack_atbash(variant_text, source_variant=variant_name))
        all_results.extend(crack_affine(variant_text, source_variant=variant_name))
        all_results.extend(
            crack_vigenere(
                variant_text,
                source_variant=variant_name,
                max_key_len=max_key_len,
            )
        )
        all_results.extend(crack_rail_fence(variant_text, source_variant=variant_name))
        all_results.extend(crack_columnar(variant_text, source_variant=variant_name))
        all_results.extend(crack_substitution(variant_text, source_variant=variant_name))

    best_by_plaintext: dict[str, Candidate] = {}
    for candidate in all_results:
        existing = best_by_plaintext.get(candidate.plaintext)
        if existing is None:
            best_by_plaintext[candidate.plaintext] = candidate
            continue

        replace = False
        if candidate.score < existing.score:
            replace = True
        elif (
            candidate.score == existing.score
            and algorithm_preference(candidate.algorithm)
            < algorithm_preference(existing.algorithm)
        ):
            replace = True

        if replace:
            best_by_plaintext[candidate.plaintext] = candidate

    ranked = list(best_by_plaintext.values())
    ranked.sort(key=lambda c: (c.score, algorithm_preference(c.algorithm), len(c.key)))
    return ranked[: max(1, top_n)]


def _banner(title: str) -> None:
    width = 68
    print("\n" + "=" * width)
    print(title)
    print("=" * width)


def _identify_hash(text: str) -> str | None:
    compact = text.strip().lower()
    if not compact or any(ch not in string.hexdigits for ch in compact):
        return None
    return HASH_LENGTHS.get(len(compact))


def _safe_b64decode(text: str) -> bytes | None:
    compact = "".join(text.split())
    try:
        return base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error):
        return None


def _split_embedded_passphrase(text: str) -> tuple[str | None, str]:
    if "|" not in text:
        return None, text.strip()
    left, right = text.split("|", 1)
    if left and right:
        return left, right.strip()
    return None, text.strip()


def _dearmor_payload(text: str) -> str:
    stripped = text.strip()
    if ARMOR_HEADER not in stripped or ARMOR_FOOTER not in stripped:
        return stripped
    lines = [line.strip() for line in stripped.splitlines()]
    body: list[str] = []
    in_body = False
    for line in lines:
        if line == ARMOR_HEADER:
            in_body = True
            continue
        if line == ARMOR_FOOTER:
            break
        if in_body and line:
            body.append(line)
    if not body:
        raise ValueError("Armored payload body is empty.")
    return "".join(body)


def _decode_json_payload(text: str) -> tuple[str | None, str]:
    stripped = text.strip()
    if not stripped.startswith("{"):
        return None, stripped
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return None, stripped
    if isinstance(parsed, dict) and {"passphrase", "payload"}.issubset(parsed):
        payload = parsed["payload"]
        if not isinstance(payload, str):
            raise ValueError("JSON wrapper payload must be a string.")
        passphrase = parsed.get("passphrase")
        if passphrase is not None and not isinstance(passphrase, str):
            raise ValueError("JSON wrapper passphrase must be a string.")
        return passphrase, payload
    if isinstance(parsed, dict) and {"profile", "cipher", "kdf", "ciphertext_b64"}.issubset(parsed):
        compact = COMPACT_PREFIX + base64.urlsafe_b64encode(
            json.dumps(parsed, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).decode("ascii").rstrip("=")
        return None, compact
    return None, stripped


def _normalize_input_payload(text: str) -> tuple[str | None, str]:
    embedded_passphrase, payload = _split_embedded_passphrase(text)
    json_passphrase, json_payload = _decode_json_payload(payload)
    if json_passphrase and not embedded_passphrase:
        embedded_passphrase = json_passphrase
    payload = json_payload
    payload = _dearmor_payload(payload)
    return embedded_passphrase, payload


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty CBC plaintext.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS7 padding.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS7 padding bytes.")
    return data[:-pad_len]


def _evp_bytes_to_key(passphrase: bytes, salt: bytes, key_len: int, iv_len: int) -> tuple[bytes, bytes]:
    digest = b""
    block = b""
    while len(digest) < key_len + iv_len:
        block = hashlib.md5(block + passphrase + salt).digest()
        digest += block
    return digest[:key_len], digest[key_len:key_len + iv_len]


def _decrypt_legacy_aes_cbc(ciphertext: str, passphrase: str) -> bytes:
    from Crypto.Cipher import AES
    raw = _safe_b64decode(ciphertext)
    if raw is None or raw[:8] != b"Salted__":
        raise ValueError("Not a legacy OpenSSL/CryptoJS payload.")
    salt = raw[8:16]
    cipherdata = raw[16:]
    key, iv = _evp_bytes_to_key(passphrase.encode("utf-8"), salt, 32, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return _pkcs7_unpad(cipher.decrypt(cipherdata))


def _decode_compact_envelope(payload: str) -> dict:
    if not payload.startswith(COMPACT_PREFIX):
        raise ValueError("Compact public envelope prefix not found.")
    compact = payload[len(COMPACT_PREFIX):]
    compact += "=" * ((4 - len(compact) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(compact.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Malformed public compact envelope.") from exc
    if not isinstance(data, dict):
        raise ValueError("Public compact envelope is not a JSON object.")
    return data


def _decompress_payload(data: bytes, mode: str) -> bytes:
    if mode == "none":
        return data
    if mode == "zlib":
        try:
            return zlib.decompress(data)
        except zlib.error as exc:
            raise ValueError("Envelope compression is invalid.") from exc
    raise ValueError(f"Unsupported compression mode: {mode}")


def _make_aad(profile: str, payload_kind: str, compression: str, source_name: str) -> bytes:
    data = {
        "profile": profile,
        "payload_kind": payload_kind,
        "compression": compression,
        "source_name": source_name,
    }
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _derive_envelope_material(passphrase: str, envelope: dict, length: int) -> bytes:
    kdf = envelope["kdf"]
    salt = base64.b64decode(kdf["salt_b64"])
    if kdf["name"] == "pbkdf2-sha256":
        return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, int(kdf["rounds"]), dklen=length)
    if kdf["name"] == "scrypt":
        if hasattr(hashlib, "scrypt"):
            return hashlib.scrypt(
                passphrase.encode("utf-8"),
                salt=salt,
                n=int(kdf["n"]),
                r=int(kdf["r"]),
                p=int(kdf["p"]),
                dklen=length,
            )
        from Crypto.Protocol.KDF import scrypt as crypto_scrypt  # type: ignore
        return crypto_scrypt(
            passphrase.encode("utf-8"),
            salt,
            key_len=length,
            N=int(kdf["n"]),
            r=int(kdf["r"]),
            p=int(kdf["p"]),
        )
    raise ValueError(f"Unsupported envelope KDF: {kdf['name']}")


def _decrypt_public_envelope(payload: str, passphrase: str) -> tuple[bytes, dict]:
    from Crypto.Cipher import AES
    envelope = _decode_compact_envelope(payload)
    ciphertext = base64.b64decode(envelope["ciphertext_b64"])
    cipher_data = envelope["cipher"]
    iv_or_nonce = base64.b64decode(cipher_data["iv_or_nonce_b64"])
    aad = _make_aad(envelope["profile"], envelope["payload_kind"], envelope["compression"], envelope["source_name"])
    if envelope["profile"].startswith("gcm-"):
        key = _derive_envelope_material(passphrase, envelope, 32)
        tag = base64.b64decode(cipher_data["tag_b64"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv_or_nonce)
        cipher.update(aad)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise ValueError("GCM authentication failed.") from exc
        return _decompress_payload(plaintext, envelope["compression"]), envelope
    if envelope["profile"].startswith("cbc-hmac-"):
        material = _derive_envelope_material(passphrase, envelope, 64)
        enc_key = material[:32]
        mac_key = material[32:]
        expected_mac = base64.b64decode(cipher_data["mac_b64"])
        actual_mac = hmac.new(mac_key, aad + iv_or_nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, actual_mac):
            raise ValueError("CBC-HMAC authentication failed.")
        cipher = AES.new(enc_key, AES.MODE_CBC, iv_or_nonce)
        plaintext = _pkcs7_unpad(cipher.decrypt(ciphertext))
        return _decompress_payload(plaintext, envelope["compression"]), envelope
    raise ValueError(f"Unsupported public envelope profile: {envelope['profile']}")


def _inspect_payload(payload: str) -> list[str]:
    lines: list[str] = []
    embedded_passphrase, normalized = _normalize_input_payload(payload)
    if embedded_passphrase:
        lines.append(f"Embedded passphrase  : yes (length {len(embedded_passphrase)})")
    else:
        lines.append("Embedded passphrase  : no")
    if normalized.startswith(COMPACT_PREFIX):
        envelope = _decode_compact_envelope(normalized)
        lines.extend([
            "Payload type       : public compact envelope",
            f"Profile            : {envelope['profile']}",
            f"Created at         : {envelope.get('created_at', 'unknown')}",
            f"Kind               : {envelope.get('payload_kind', 'unknown')}",
            f"Source name        : {envelope.get('source_name', 'unknown')}",
            f"Compression        : {envelope.get('compression', 'unknown')}",
            f"Original size      : {envelope.get('original_size', 'unknown')}",
            f"Stored size        : {envelope.get('compressed_size', 'unknown')}",
            f"KDF                : {envelope['kdf'].get('name', 'unknown')}",
            f"Cipher mode        : {envelope['cipher'].get('mode', 'unknown')}",
        ])
        return lines
    raw = _safe_b64decode(normalized)
    if raw is not None and raw[:8] == b"Salted__":
        lines.extend([
            "Payload type       : legacy OpenSSL/CryptoJS AES-256-CBC",
            f"Salt               : {raw[8:16].hex()}",
            f"Ciphertext bytes   : {len(raw) - 16}",
        ])
        return lines
    hash_type = _identify_hash(normalized)
    if hash_type:
        lines.extend([
            f"Payload type       : hash ({hash_type})",
            f"Hex length         : {len(normalized.strip())}",
        ])
        return lines
    lines.append("Payload type       : classical cipher candidate or unsupported format")
    return lines


def _read_ciphertext(args: argparse.Namespace) -> str:
    if args.ciphertext is not None:
        return args.ciphertext.strip()
    if args.input_file is not None:
        return Path(args.input_file).read_text(encoding="utf-8").strip()
    return input("Enter encrypted text: ").strip()


def _write_plaintext(data: bytes, output_file: str | None) -> None:
    if output_file:
        Path(output_file).write_bytes(data)
        print(f"Saved decrypted output to {output_file}")
        return
    try:
        text = data.decode("utf-8")
        print(f"\nDecrypted message:\n{text}\n")
    except UnicodeDecodeError:
        print("\nDecrypted payload is binary data.")
        print(f"Byte length: {len(data)}")
        print(f"Base64     : {base64.b64encode(data).decode('ascii')}\n")


def _passphrase_candidates(args: argparse.Namespace, embedded_passphrase: str | None) -> list[str]:
    candidates: list[str] = []
    if embedded_passphrase:
        candidates.append(embedded_passphrase)
    if args.passphrase:
        candidates.append(args.passphrase)
    if args.passphrase_file:
        content = Path(args.passphrase_file).read_text(encoding="utf-8").strip()
        if content:
            candidates.append(content)
    if args.brute:
        candidates.extend(COMMON_PASSPHRASES)
    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in candidates:
        if candidate not in seen:
            ordered.append(candidate)
            seen.add(candidate)
    return ordered


def _try_standard_decrypt(payload: str, passphrases: list[str]) -> tuple[bytes, str, str] | None:
    errors: list[str] = []
    for passphrase in passphrases:
        if payload.startswith(COMPACT_PREFIX):
            try:
                plaintext, envelope = _decrypt_public_envelope(payload, passphrase)
                return plaintext, passphrase, envelope["profile"]
            except ValueError as exc:
                errors.append(str(exc))
        raw = _safe_b64decode(payload)
        if raw is not None and raw[:8] == b"Salted__":
            try:
                plaintext = _decrypt_legacy_aes_cbc(payload, passphrase)
                return plaintext, passphrase, "legacy-cbc"
            except ValueError as exc:
                errors.append(str(exc))
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Public decoder: decrypt public envelopes and crack classical ciphers."
    )
    parser.add_argument("ciphertext", nargs="?", help="Ciphertext to process.")
    parser.add_argument("--input-file", help="Read ciphertext from a file.")
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of best candidates to show (default: 5).",
    )
    parser.add_argument(
        "--max-key-len",
        type=int,
        default=10,
        help="Maximum key length to test for Vigenere (default: 10).",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="After showing results, prompt to select a candidate for full details.",
    )
    parser.add_argument("--inspect", action="store_true", help="Inspect the input instead of decrypting/cracking.")
    parser.add_argument("--passphrase", help="Passphrase for public envelopes or legacy AES-CBC.")
    parser.add_argument("--passphrase-file", help="Read passphrase from a file.")
    parser.add_argument("--brute", action="store_true", help="Try a built-in common-passphrase list.")
    parser.add_argument("--output-file", help="Write decrypted bytes to a file.")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    ciphertext = _read_ciphertext(args)

    if not ciphertext:
        raise SystemExit("No text provided.")

    if args.inspect:
        _banner("Payload Inspection")
        for line in _inspect_payload(ciphertext):
            print(line)
        return

    embedded_passphrase, normalized = _normalize_input_payload(ciphertext)

    hash_type = _identify_hash(normalized)
    if hash_type:
        _banner(f"Hash Detected: {hash_type}")
        print(f"This looks like a {hash_type} hash ({len(normalized.strip())} hex chars).")
        print("Hashes are one-way. Use a cracker or dictionary attack instead of decryption.\n")
        return

    if normalized.startswith(COMPACT_PREFIX) or ((_safe_b64decode(normalized) or b"")[:8] == b"Salted__"):
        _banner("Standard Encryption Detected")
        passphrases = _passphrase_candidates(args, embedded_passphrase)
        if not passphrases:
            raise SystemExit("No passphrase available. Provide --passphrase, --passphrase-file, use embedded PASSPHRASE|..., or add --brute.")
        result = _try_standard_decrypt(normalized, passphrases)
        if result is None:
            raise SystemExit("Could not decrypt the standard encrypted payload with the supplied passphrase candidates.")
        plaintext, passphrase_used, profile_used = result
        print(f"Passphrase used      : {passphrase_used}")
        print(f"Profile            : {profile_used}")
        _write_plaintext(plaintext, args.output_file)
        return

    print("\nBest candidates:\n")
    candidates = crack_all(normalized, top_n=args.top, max_key_len=args.max_key_len)
    for idx, candidate in enumerate(candidates, start=1):
        print(
            f"{idx}. Algo: {candidate.algorithm:<12} "
            f"| Key: {candidate.key:<26} "
            f"| Source: {candidate.source_variant:<14} "
            f"| Score: {candidate.score:>8.2f}"
        )
        preview = candidate.plaintext[:120]
        if len(candidate.plaintext) > 120:
            preview += "..."
        print(f"   {preview}\n")

    if args.interactive:
        print("─" * 62)
        print("Interactive — enter a number to see full details, or press Enter to quit.")
        while True:
            try:
                choice = input("Select #: ").strip()
            except EOFError:
                break
            if not choice:
                break
            try:
                sel = int(choice) - 1
            except ValueError:
                print(f"  Enter a number between 1 and {len(candidates)}.")
                continue
            if 0 <= sel < len(candidates):
                c = candidates[sel]
                print(f"\n  Algorithm : {c.algorithm}")
                print(f"  Key       : {c.key}")
                print(f"  Source    : {c.source_variant}")
                print(f"  Score     : {c.score:.2f}")
                print(f"\n  Plaintext :\n{c.plaintext}\n")
            else:
                print(f"  Enter a number between 1 and {len(candidates)}.")


if __name__ == "__main__":
    main()
