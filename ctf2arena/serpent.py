"""Pure-Python Serpent (128-bit block, 128/192/256-bit key), ECB.

Three things about Serpent are easy to get wrong in a way that still yields plausible
ciphertext, so they are stated up front and pinned by :func:`selftest`:

1. **Eight S-boxes, reused as ``round % 8``** - not 32 distinct per-round boxes.
2. **The S-box is bit-sliced vertically**: nibble *i* is bit *i* of x0..x3, with ``x0``
   the least significant bit. The ``x0 <<< 13 ...`` linear transform is the matching
   partner for that representation.
3. **There is no IP/FP.** They appear in the AES submission's reference C code but are
   only a bit reordering; implementations fold them away, so a block maps straight to
   four little-endian words.

The prekey recurrence is also a trap in Python specifically: written as ``w[i - 8]`` over
a list that grows by ``append``, negative indices silently wrap and corrupt the whole
schedule. The loop below indexes a pre-filled flat array instead.

Known-answer test: key ``80 00..00`` (128-bit) with an all-zero block must encrypt to
``264E5481EFF42A4606ABDA06C0BFDA3D``.
"""

from __future__ import annotations

MASK32 = 0xFFFFFFFF
PHI = 0x9E3779B9
ROUNDS = 32
ROUND_KEYS = ROUNDS + 1

#: The eight S-boxes from the Serpent submission, applied as ``round % 8``.
SBOX = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
]

SBOX_INV: list[list[int]] = []
for _row in SBOX:
    _inv = [0] * 16
    for _i, _v in enumerate(_row):
        _inv[_v] = _i
    SBOX_INV.append(_inv)


def rotl(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK32


def rotr(x: int, n: int) -> int:
    n &= 31
    return ((x >> n) | (x << (32 - n))) & MASK32


def sbox_words(words: list[int], box: int, *, inverse: bool = False) -> list[int]:
    """Apply one S-box across the 32 vertical nibbles of the four words."""
    table = SBOX_INV[box] if inverse else SBOX[box]
    x0, x1, x2, x3 = words
    y = [0, 0, 0, 0]
    for bit in range(32):
        nibble = (
            ((x0 >> bit) & 1)
            | (((x1 >> bit) & 1) << 1)
            | (((x2 >> bit) & 1) << 2)
            | (((x3 >> bit) & 1) << 3)
        )
        out = table[nibble]
        y[0] |= (out & 1) << bit
        y[1] |= ((out >> 1) & 1) << bit
        y[2] |= ((out >> 2) & 1) << bit
        y[3] |= ((out >> 3) & 1) << bit
    return y


def linear_transform(words: list[int]) -> list[int]:
    x0 = rotl(words[0], 13)
    x2 = rotl(words[2], 3)
    x1 = words[1] ^ x0 ^ x2
    x3 = words[3] ^ x2 ^ ((x0 << 3) & MASK32)
    x1 = rotl(x1, 1)
    x3 = rotl(x3, 7)
    x0 = x0 ^ x1 ^ x3
    x2 = x2 ^ x3 ^ ((x1 << 7) & MASK32)
    x0 = rotl(x0, 5)
    x2 = rotl(x2, 22)
    return [x0 & MASK32, x1 & MASK32, x2 & MASK32, x3 & MASK32]


def inverse_linear_transform(words: list[int]) -> list[int]:
    x0 = rotr(words[0], 5)
    x1 = words[1]
    x2 = rotr(words[2], 22)
    x3 = words[3]
    x2 = x2 ^ x3 ^ ((x1 << 7) & MASK32)
    x0 = x0 ^ x1 ^ x3
    x3 = rotr(x3, 7)
    x1 = rotr(x1, 1)
    x3 = x3 ^ x2 ^ ((x0 << 3) & MASK32)
    x1 = x1 ^ x0 ^ x2
    x2 = rotr(x2, 3)
    x0 = rotr(x0, 13)
    return [x0 & MASK32, x1 & MASK32, x2 & MASK32, x3 & MASK32]


def pad_key(key: bytes) -> bytes:
    """Keys shorter than 256 bits gain a single 1 bit at the MSB end, then zeros."""
    if len(key) > 32:
        raise ValueError("Serpent keys are at most 32 bytes")
    if len(key) == 32:
        return key
    return key + b"\x01" + b"\x00" * (31 - len(key))


def round_keys(key: bytes) -> list[list[int]]:
    """Expand a key into the 33 round keys."""
    padded = pad_key(key)
    seed_words = len(padded) // 4
    prekey_count = seed_words + 4 * ROUND_KEYS
    w = [0] * prekey_count
    for i in range(seed_words):
        w[i] = int.from_bytes(padded[i * 4 : i * 4 + 4], "little")
    # Indices below are non-negative because the array is pre-filled, not appended to.
    for i in range(seed_words, prekey_count):
        w[i] = rotl(
            (w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ (i - seed_words))
            & MASK32,
            11,
        )

    keys = []
    for r in range(ROUND_KEYS):
        first = seed_words + 4 * r
        box = (3 - r) % 8
        keys.append(sbox_words(w[first : first + 4], box))
    return keys


def _words_from_block(block: bytes, *, big_endian: bool = False) -> list[int]:
    order = "big" if big_endian else "little"
    return [int.from_bytes(block[i * 4 : i * 4 + 4], order) for i in range(4)]


def _block_from_words(words: list[int], *, big_endian: bool = False) -> bytes:
    order = "big" if big_endian else "little"
    return b"".join(w.to_bytes(4, order) for w in words)


def encrypt_block(block: bytes, keys: list[list[int]], *, big_endian: bool = False) -> bytes:
    state = _words_from_block(block, big_endian=big_endian)
    for r in range(ROUNDS - 1):
        state = sbox_words([state[j] ^ keys[r][j] for j in range(4)], r % 8)
        state = linear_transform(state)
    state = [state[j] ^ keys[ROUNDS - 1][j] for j in range(4)]
    state = sbox_words(state, (ROUNDS - 1) % 8)
    state = [state[j] ^ keys[ROUNDS][j] for j in range(4)]
    return _block_from_words(state, big_endian=big_endian)


def decrypt_block(block: bytes, keys: list[list[int]], *, big_endian: bool = False) -> bytes:
    state = _words_from_block(block, big_endian=big_endian)
    state = [state[j] ^ keys[ROUNDS][j] for j in range(4)]
    state = sbox_words(state, (ROUNDS - 1) % 8, inverse=True)
    state = [state[j] ^ keys[ROUNDS - 1][j] for j in range(4)]
    for r in range(ROUNDS - 2, -1, -1):
        state = inverse_linear_transform(state)
        state = sbox_words(state, r % 8, inverse=True)
        state = [state[j] ^ keys[r][j] for j in range(4)]
    return _block_from_words(state, big_endian=big_endian)


def decrypt_ecb(data: bytes, key: bytes, **kwargs) -> bytes:
    if len(data) % 16:
        raise ValueError(f"length {len(data)} is not a multiple of 16")
    keys = round_keys(key)
    return b"".join(
        decrypt_block(data[i : i + 16], keys, **kwargs)
        for i in range(0, len(data), 16)
    )


def encrypt_ecb(data: bytes, key: bytes, **kwargs) -> bytes:
    if len(data) % 16:
        raise ValueError(f"length {len(data)} is not a multiple of 16")
    keys = round_keys(key)
    return b"".join(
        encrypt_block(data[i : i + 16], keys, **kwargs)
        for i in range(0, len(data), 16)
    )


# ---------------------------------------------------------------------- self-test

#: NESSIE-format Serpent-128 vector in this module's byte order (no reversal).
KAT_KEY = bytes([0x80]) + bytes(15)
KAT_PLAIN = bytes(16)
KAT_CIPHER = bytes.fromhex("264E5481EFF42A4606ABDA06C0BFDA3D")


def selftest() -> tuple[bool, dict]:
    checks: dict[str, object] = {}
    checks["sbox_inverses"] = all(
        SBOX_INV[i][SBOX[i][x]] == x for i in range(8) for x in range(16)
    )
    probes = [
        [0x12345678, 0x9ABCDEF0, 0x0F0F0F0F, 0xDEADBEEF],
        [0, 0, 0, 0],
        [MASK32] * 4,
    ]
    checks["lt_roundtrip"] = all(
        inverse_linear_transform(linear_transform(list(p))) == list(p) for p in probes
    )
    keys = round_keys(KAT_KEY)
    got = encrypt_block(KAT_PLAIN, keys)
    checks["kat_encrypt"] = got == KAT_CIPHER
    checks["kat_decrypt"] = decrypt_block(KAT_CIPHER, keys) == KAT_PLAIN
    checks["got"] = got.hex()
    checks["expect"] = KAT_CIPHER.hex()
    ok = all(v is True for v in checks.values() if isinstance(v, bool))
    return ok, checks
