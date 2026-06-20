"""Encryption primitives matching the zhixuewang front-end: RC4 + hex, and RSA R2/P."""

from __future__ import annotations


# ---- RC4 (matches rc4.js exactly) ----

_RC4_SECRET = "iflytzhixueweb"


def _rc4(data: str, key: str) -> str:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + ord(key[i % len(key)])) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out: list[str] = []
    for ch in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(chr(ord(ch) ^ s[(s[i] + s[j]) % 256]))
    return "".join(out)


def _to_hex(s: str) -> str:
    return "".join(f"{ord(c):02x}" for c in s)


def rc4_encrypt_password(password: str) -> str:
    """Encrypt plaintext password → hex(RC4(password, zxlogin_secret))."""
    return _to_hex(_rc4(password, _RC4_SECRET))


# ---- RSA R2/P (matches sso.all.min.js encryptedString, NOT security.js) ----

# Public key used by zhixuewang SSO (same across all deployments)
_RSA_MODULUS_HEX = (
    "00ccd806a03c7391ee8f884f5902102d95f6d534d597ac42219dd8a79b1465e"
    "186c0162a6771b55e7be7422c4af494ba0112ede4eb00fc751723f2c235ca419"
    "876e7103ea904c29522b72d754f66ff1958098396f17c6cd2c9446e8c2bb5f40"
    "00a9c1c6577236a57e270bef07e7fe7bbec1f0e8993734c8bd4750e01feb21b6dc9"
)
_RSA_EXPONENT_HEX = "010001"


def _bigint_from_hex(hex_str: str) -> int:
    return int(hex_str, 16)


def _bigint_high_index(n: int) -> int:
    """Return the number of 16-bit digits minus 1 (matches JS biHighIndex)."""
    if n == 0:
        return 0
    return (n.bit_length() - 1) // 16


def _bi_to_hex(val: int) -> str:
    """Convert a Python int to hex string matching JS biToHex format.

    Each 16-bit digit is zero-padded to exactly 4 hex chars (digitToHex).
    Digits are output from highest to lowest index (biToHex).
    """
    digits: list[int] = []
    temp = val
    while temp > 0:
        digits.append(temp & 0xFFFF)
        temp >>= 16
    if not digits:
        return "0000"
    # Reverse: highest index first, each digit 4 hex chars
    return "".join(f"{d:04x}" for d in reversed(digits))


def rsa_encrypt_r2p(plaintext: str) -> str:
    """Encrypt plaintext using the SSO RSA R2/P scheme.

    This matches sso.all.min.js encryptedString (NOT security.js!):
    1. digitSize = 2 * biHighIndex(modulus) + 2 (= 128)
    2. chunkSize = digitSize - 11 (= 117)
    3. Each block: [plaintext bytes] [0x00] [random padding] [0x02] [0x00]
       - Random padding length = max(8, digitSize - 3 - plaintext_len)
       - Each padding byte is 1-254 (not 0 or 255)
    4. Convert byte array to BigInt digits (pairs, little-endian per digit)
    5. RSA modular exponentiation (powMod)
    6. biToHex (each 16-bit digit → 4 hex chars)
    7. Space-join blocks, reverse order, concatenate
    """
    import random as _random

    modulus = _bigint_from_hex(_RSA_MODULUS_HEX)
    exponent = _bigint_from_hex(_RSA_EXPONENT_HEX)

    # digitSize = 2 * biHighIndex + 2 (SSO-specific, different from security.js)
    digit_size = 2 * _bigint_high_index(modulus) + 2  # = 128
    chunk_size = digit_size - 11  # = 117

    chars = [ord(c) for c in plaintext]
    total_len = len(chars)

    blocks: list[str] = []
    offset = 0
    while offset < total_len:
        # Determine chunk length
        t = total_len - offset if offset + chunk_size > total_len else chunk_size

        # Build the block byte array
        B: list[int] = []

        # 1) Plaintext bytes for this chunk
        for u in range(t):
            B.append(chars[offset + u])

        # 2) Zero separator
        B.append(0)

        # 3) Random padding (each byte 1-254, matching JS:
        #    Math.floor(254 * Math.random()) + 1)
        r = max(8, digit_size - 3 - t)
        for _ in range(r):
            B.append(_random.randint(1, 254))

        # 4) Type marker and trailing zero (fill to digit_size)
        while len(B) < digit_size - 2:
            B.append(0)
        B.append(2)  # type marker: B[digitSize - 2] = 2
        B.append(0)  # final zero:    B[digitSize - 1] = 0

        # 5) Convert byte array to BigInt digits (pairs, little-endian)
        val = 0
        j = 0
        k = 0
        while k < digit_size:
            low = B[k]
            k += 1
            high = B[k] if k < digit_size else 0
            k += 1
            val |= (low + (high << 8)) << (j * 16)
            j += 1

        # 6) RSA modular exponentiation
        encrypted = pow(val, exponent, modulus)

        # 7) biToHex format (each 16-bit digit -> 4 hex chars, high to low)
        blocks.append(_bi_to_hex(encrypted))

        offset += chunk_size

    # 8) Reverse block order and concatenate (matches JS final reverse step)
    blocks.reverse()
    return "".join(blocks)
