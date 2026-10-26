"""Pure-Python AES-128 (decrypt-first) for CTF work.

The sandbox has no ``Crypto``, no ``cryptography``, no ``nacl``. Reimplementing AES is
usually the wrong call - but when a challenge hands you 48 bytes of ciphertext and a
password hint, having no AES at all is worse.

Scope, stated plainly:

* AES-128 only (16-byte keys). That covers the overwhelming majority of CTF challenges.
* ECB and CBC decryption, plus CBC/ECB *encryption* for round-trip self-tests.
* No padding removal beyond :func:`unpad_pkcs7`, which reports rather than guesses.
* Not constant-time, not hardened. Do not use this for anything real.

The self-test in ``tests/test_aes.py`` encrypts and decrypts the FIPS-197 Appendix C
vectors, so a typo in the tables cannot silently produce plausible-looking garbage.
"""

from __future__ import annotations

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

_INV_SBOX = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_INV_SBOX = bytes(_INV_SBOX)

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a & 0xFF


def _mul(a: int, b: int) -> int:
    """Multiply in GF(2^8) with the AES polynomial."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise ValueError(f"AES-128 needs a 16-byte key, got {len(key)}")
    words = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [_SBOX[b] for b in temp]  # SubWord
            temp[0] ^= _RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    # group into 11 round keys of 16 bytes, column-major
    round_keys = []
    for r in range(11):
        flat = []
        for w in words[4 * r : 4 * r + 4]:
            flat.extend(w)
        round_keys.append(flat)
    return round_keys


def _to_state(block: bytes) -> list[list[int]]:
    """state[r][c] = block[r + 4c] (AES column-major convention)."""
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _from_state(state: list[list[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _add_round_key(state, round_key) -> None:
    for c in range(4):
        for r in range(4):
            state[r][c] ^= round_key[4 * c + r]


def _inv_sub_bytes(state) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = _INV_SBOX[state[r][c]]


def _inv_shift_rows(state) -> None:
    for r in range(1, 4):
        row = [state[r][c] for c in range(4)]
        row = row[-r:] + row[:-r]  # rotate right by r
        for c in range(4):
            state[r][c] = row[c]


def _inv_mix_columns(state) -> None:
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
        state[1][c] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
        state[2][c] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
        state[3][c] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)


def _sub_bytes(state) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = _SBOX[state[r][c]]


def _shift_rows(state) -> None:
    for r in range(1, 4):
        row = [state[r][c] for c in range(4)]
        row = row[r:] + row[:r]  # rotate left by r
        for c in range(4):
            state[r][c] = row[c]


def _mix_columns(state) -> None:
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
        state[3][c] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


def decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = _to_state(block)
    _add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[rnd])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return _from_state(state)


def encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = _to_state(block)
    _add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    return _from_state(state)


def _chunks(data: bytes) -> list[bytes]:
    if len(data) % 16:
        raise ValueError(f"ciphertext length {len(data)} is not a multiple of 16")
    return [data[i : i + 16] for i in range(0, len(data), 16)]


def decrypt_ecb(data: bytes, key: bytes) -> bytes:
    rk = _expand_key(key)
    return b"".join(decrypt_block(block, rk) for block in _chunks(data))


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    rk = _expand_key(key)
    return b"".join(encrypt_block(block, rk) for block in _chunks(data))


def decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("CBC needs a 16-byte IV")
    rk = _expand_key(key)
    out = []
    prev = iv
    for block in _chunks(data):
        plain = decrypt_block(block, rk)
        out.append(bytes(a ^ b for a, b in zip(plain, prev)))
        prev = block
    return b"".join(out)


def encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("CBC needs a 16-byte IV")
    rk = _expand_key(key)
    out = []
    prev = iv
    for block in _chunks(data):
        xored = bytes(a ^ b for a, b in zip(block, prev))
        cipher = encrypt_block(xored, rk)
        out.append(cipher)
        prev = cipher
    return b"".join(out)


def unpad_pkcs7(data: bytes) -> tuple[bytes, bool]:
    """Strip PKCS#7 padding. Returns ``(data, padding_was_valid)`` - never guesses."""
    if not data:
        return data, False
    pad = data[-1]
    if pad < 1 or pad > 16 or pad > len(data):
        return data, False
    if data[-pad:] != bytes([pad]) * pad:
        return data, False
    return data[:-pad], True


def pad_pkcs7(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad
