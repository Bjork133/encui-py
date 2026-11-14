from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


class CryptoError(Exception):
    """Ошибка криптографической операции или некорректных параметров."""


@dataclass
class ConwayParams:
    public: bytes
    private: bytes
    method: bytes


# ==========================================
# Порт conway-aes (1-в-1 с оригиналом на Rust)
# ==========================================

def derive_aes_key(public: bytes, private: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"conway-aes/key/v1")
    hasher.update(public)
    hasher.update(private)
    return hasher.digest()


def derive_nonce(public: bytes, private: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"conway-aes/nonce/v1")
    hasher.update(public)
    hasher.update(private)
    return hasher.digest()[:16]


def aes_ctr(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def xor_with_method(data: bytes, method: bytes) -> bytes:
    if not method:
        return data
    m_len = len(method)
    return bytes(b ^ method[i % m_len] for i, b in enumerate(data))


def derive_generations(method: bytes) -> int:
    if not method:
        return 1
    half_len = max(len(method) // 2, 1)
    value = 0
    for b in method[:half_len]:
        value = (value << 8) | b
    n = value
    while n >= 100:
        n //= 3
    return max(n, 1)


def apply_n_generations(data: bytes, n: int) -> bytes:
    if not data or n == 0:
        return data
    length = len(data)
    k = math.ceil(math.sqrt(length))
    total = k * k
    grid = bytearray(total)
    grid[:length] = data

    for _ in range(n):
        i = 0
        while i + 1 < total:
            grid[i] ^= grid[i + 1]
            i += 2

    return bytes(grid[:length])


def conway_encrypt(data: bytes, params: ConwayParams) -> bytes:
    if not params.method:
        raise CryptoError("Method key не может быть пустым")
    xored = xor_with_method(data, params.method)
    n = derive_generations(params.method)
    after_life = apply_n_generations(xored, n)
    key = derive_aes_key(params.public, params.private)
    nonce = derive_nonce(params.public, params.private)
    return aes_ctr(after_life, key, nonce)


def conway_decrypt(data: bytes, params: ConwayParams) -> bytes:
    if not params.method:
        raise CryptoError("Method key не может быть пустым")
    key = derive_aes_key(params.public, params.private)
    nonce = derive_nonce(params.public, params.private)
    after_aes = aes_ctr(data, key, nonce)
    n = derive_generations(params.method)
    after_life = apply_n_generations(after_aes, n)
    return xor_with_method(after_life, params.method)


# ==========================================
# Дополнительные алгоритмы из encui
# ==========================================

def caesar_cipher(data: bytes, shift: int, decrypt: bool = False) -> bytes:
    s = (-shift if decrypt else shift) % 26
    out = bytearray()
    for b in data:
        if 65 <= b <= 90:  # A-Z
            out.append((b - 65 + s) % 26 + 65)
        elif 97 <= b <= 122:  # a-z
            out.append((b - 97 + s) % 26 + 97)
        else:
            out.append(b)
    return bytes(out)


def vigenere_cipher(data: bytes, key: str, decrypt: bool = False) -> bytes:
    letters = [ord(c.upper()) - 65 for c in key if "A" <= c.upper() <= "Z"]
    if not letters:
        raise CryptoError("Ключ Виженера должен содержать латинские буквы (A-Z)")

    out = bytearray()
    k_idx = 0
    for b in data:
        if 65 <= b <= 90:
            shift = letters[k_idx % len(letters)]
            if decrypt:
                shift = -shift
            out.append((b - 65 + shift) % 26 + 65)
            k_idx += 1
        elif 97 <= b <= 122:
            shift = letters[k_idx % len(letters)]
            if decrypt:
                shift = -shift
            out.append((b - 97 + shift) % 26 + 97)
            k_idx += 1
        else:
            out.append(b)
    return bytes(out)


def vernam_cipher(data: bytes, key: bytes) -> bytes:
    if len(key) < len(data):
        raise CryptoError(
            f"Для Вернама/OTP длина ключа ({len(key)} Б) должна быть >= длины данных ({len(data)} Б)"
        )
    return bytes(d ^ k for d, k in zip(data, key))


def _parse_hex(hex_str: str, expected_bytes: int, field_name: str) -> bytes:
    cleaned = "".join(hex_str.split())
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise CryptoError(f"{field_name}: некорректная hex-строка") from exc
    if len(raw) != expected_bytes:
        raise CryptoError(
            f"{field_name}: ожидается {expected_bytes} байт ({expected_bytes * 2} hex-символов), получено {len(raw)} байт"
        )
    return raw


def aead_cipher(
    algo: str,
    data: bytes,
    key_hex: str,
    nonce_hex: str,
    decrypt: bool = False,
) -> bytes:
    key = _parse_hex(key_hex, 32, "Key")
    nonce = _parse_hex(nonce_hex, 12, "Nonce")
    cipher = AESGCM(key) if algo == "aes-gcm" else ChaCha20Poly1305(key)
    try:
        if decrypt:
            return cipher.decrypt(nonce, data, None)
        return cipher.encrypt(nonce, data, None)
    except Exception as exc:
        raise CryptoError("Ошибка проверки целостности или расшифровки AEAD (неверный ключ/nonce/данные)") from exc


# ==========================================
# Единая точка вызова
# ==========================================

def run_crypto_operation(
    algo: str,
    mode: str,
    raw_data: bytes,
    params: dict[str, str],
) -> bytes:
    is_decrypt = mode == "decrypt"

    if algo == "conway-aes":
        c_params = ConwayParams(
            public=params.get("public", "").encode("utf-8"),
            private=params.get("private", "").encode("utf-8"),
            method=params.get("method", "").encode("utf-8"),
        )
        return conway_decrypt(raw_data, c_params) if is_decrypt else conway_encrypt(raw_data, c_params)

    if algo == "caesar":
        shift_str = params.get("shift", "").strip()
        if not shift_str:
            raise CryptoError("Укажите сдвиг (Shift)")
        try:
            shift = int(shift_str)
        except ValueError as exc:
            raise CryptoError("Shift должен быть целым числом") from exc
        return caesar_cipher(raw_data, shift, decrypt=is_decrypt)

    if algo == "vigenere":
        key = params.get("key", "").strip()
        if not key:
            raise CryptoError("Ключ Виженера пуст")
        return vigenere_cipher(raw_data, key, decrypt=is_decrypt)

    if algo == "vernam":
        key_bytes = params.get("key", "").encode("utf-8")
        if not key_bytes:
            raise CryptoError("Ключ Вернама пуст")
        return vernam_cipher(raw_data, key_bytes)

    if algo in ("aes-gcm", "chacha20poly1305"):
        key_hex = params.get("aead_key", "")
        nonce_hex = params.get("aead_nonce", "")
        if not key_hex.strip() or not nonce_hex.strip():
            raise CryptoError("Key и Nonce не могут быть пустыми")
        return aead_cipher(algo, raw_data, key_hex, nonce_hex, decrypt=is_decrypt)

    raise CryptoError(f"Неизвестный алгоритм: {algo}")
