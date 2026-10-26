"""Pure-Python QR decoder for clean, machine-generated symbols.

No zbar, no OpenCV, no pyzbar - just the spec. Written because the CTF sandbox has none of
those, and because two challenges in one sitting needed it.

Scope, stated honestly:

* **Reads** version 1-10, byte / alphanumeric / numeric segments, any EC level and mask.
* **Does not** run Reed-Solomon error correction. It *de-interleaves*, which is what you
  need to recover the data codewords, but it assumes the symbol is clean. A damaged symbol
  needs the RS decoder (see the ``qr-repair-ctf`` skill for that direction).
* **Sampling** assumes an axis-aligned symbol on a light background. It tries each
  plausible module count and keeps the one whose three finder patterns validate, so a
  non-integer pixels-per-module render (common after an image resize) still works.

The design choice worth keeping: the mask pattern and EC level are **not** trusted from the
format-info bits. Both are brute-forced (8 masks x 4 EC levels) and the combination that
yields a parseable segment stream wins. Parsing success is a much stronger oracle than a
15-bit read whose bit order is easy to get backwards.
"""

from __future__ import annotations

from dataclasses import dataclass

# --------------------------------------------------------------------------- tables

#: (version, level) -> (ec_per_block, group1_blocks, group1_data, group2_blocks, group2_data)
#: group2 blocks carry exactly one more data codeword than group1 blocks.
_BLOCKS = {
    (1, "L"): (7, 1, 19, 0, 0), (1, "M"): (10, 1, 16, 0, 0),
    (1, "Q"): (13, 1, 13, 0, 0), (1, "H"): (17, 1, 9, 0, 0),
    (2, "L"): (10, 1, 34, 0, 0), (2, "M"): (16, 1, 28, 0, 0),
    (2, "Q"): (22, 1, 22, 0, 0), (2, "H"): (28, 1, 16, 0, 0),
    (3, "L"): (15, 1, 55, 0, 0), (3, "M"): (26, 1, 44, 0, 0),
    (3, "Q"): (18, 2, 17, 0, 0), (3, "H"): (22, 2, 13, 0, 0),
    (4, "L"): (20, 1, 80, 0, 0), (4, "M"): (18, 2, 32, 0, 0),
    (4, "Q"): (26, 2, 24, 0, 0), (4, "H"): (16, 4, 9, 0, 0),
    (5, "L"): (26, 1, 108, 0, 0), (5, "M"): (24, 2, 43, 0, 0),
    (5, "Q"): (18, 2, 15, 2, 16), (5, "H"): (22, 2, 11, 2, 12),
    (6, "L"): (18, 2, 68, 0, 0), (6, "M"): (16, 4, 27, 0, 0),
    (6, "Q"): (24, 4, 19, 0, 0), (6, "H"): (28, 4, 15, 0, 0),
    (7, "L"): (20, 2, 78, 0, 0), (7, "M"): (18, 4, 31, 0, 0),
    (7, "Q"): (18, 2, 14, 4, 15), (7, "H"): (26, 4, 13, 1, 14),
    (8, "L"): (24, 2, 97, 0, 0), (8, "M"): (22, 2, 38, 2, 39),
    (8, "Q"): (22, 4, 18, 2, 19), (8, "H"): (26, 4, 14, 2, 15),
    (9, "L"): (30, 2, 116, 0, 0), (9, "M"): (22, 3, 36, 2, 37),
    (9, "Q"): (20, 4, 16, 4, 17), (9, "H"): (24, 4, 12, 4, 13),
    (10, "L"): (18, 2, 68, 2, 69), (10, "M"): (26, 4, 43, 1, 44),
    (10, "Q"): (24, 6, 19, 2, 20), (10, "H"): (28, 6, 15, 2, 16),
}

#: Alignment-pattern centre coordinates per version.
_ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
    7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
}

_FINDER = [
    "1111111",
    "1000001",
    "1011101",
    "1011101",
    "1011101",
    "1000001",
    "1111111",
]

_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


class QrError(Exception):
    pass


@dataclass
class Decoded:
    text: str
    version: int
    size: int
    mask: int
    level: str
    segments: list


# --------------------------------------------------------------------- image sampling


def _binarize(gray) -> list[list[bool]]:
    """``gray`` is a sequence of rows of 0..255 ints. True = dark."""
    h = len(gray)
    w = len(gray[0]) if h else 0
    values = sorted(v for row in gray for v in row)
    threshold = values[len(values) // 2] if values else 128
    return [[v < threshold for v in row] for row in gray]


def _bbox(dark: list[list[bool]]) -> tuple[int, int, int, int]:
    rows = [y for y, row in enumerate(dark) if any(row)]
    if not rows:
        raise QrError("image contains no dark pixels")
    cols = [x for row in dark for x, v in enumerate(row) if v]
    return min(cols), min(rows), max(cols), max(rows)


def _sample(dark, x0: int, y0: int, x1: int, y1: int, n: int) -> list[list[bool]]:
    w = x1 - x0 + 1
    h = y1 - y0 + 1
    out = []
    for r in range(n):
        row = []
        y = y0 + int((r + 0.5) * h / n)
        for c in range(n):
            x = x0 + int((c + 0.5) * w / n)
            row.append(dark[y][x])
        out.append(row)
    return out


def _finders_ok(m: list[list[bool]]) -> int:
    """Return how many of the three finder patterns match (0..3)."""
    n = len(m)
    corners = [
        (0, 0), (0, n - 7), (n - 7, 0),
    ]
    good = 0
    for r0, c0 in corners:
        ok = True
        for dr in range(7):
            for dc in range(7):
                want = _FINDER[dr][dc] == "1"
                if m[r0 + dr][c0 + dc] != want:
                    ok = False
                    break
            if not ok:
                break
        if ok:
            good += 1
    return good


def matrix_from_gray(gray) -> tuple[list[list[bool]], int]:
    """Locate the symbol and return ``(module_matrix, version)``.

    Tries every plausible module count and keeps the one where all three finder patterns
    validate - that is what makes a resized render (non-integer px per module) work.
    """
    dark = _binarize(gray)
    x0, y0, x1, y1 = _bbox(dark)
    span_x = x1 - x0 + 1
    span_y = y1 - y0 + 1

    best = None
    for version in range(1, 11):
        n = 17 + 4 * version
        # A sane render has >= 1px per module.
        if span_x < n or span_y < n:
            continue
        m = _sample(dark, x0, y0, x1, y1, n)
        score = _finders_ok(m)
        if score == 3:
            return m, version
        if best is None or score > best[0]:
            best = (score, m, version)

    if best and best[0] >= 2:
        raise QrError(
            f"only {best[0]}/3 finder patterns matched for version {best[2]} "
            f"({span_x}x{span_y}px bbox); the symbol may be rotated, mirrored or damaged"
        )
    raise QrError(f"no QR finder patterns found in a {span_x}x{span_y}px bounding box")


# ------------------------------------------------------------------ structure helpers


def _function_mask(version: int) -> list[list[bool]]:
    n = 17 + 4 * version
    fn = [[False] * n for _ in range(n)]

    def mark(r0: int, c0: int, h: int, w: int) -> None:
        for r in range(r0, r0 + h):
            for c in range(c0, c0 + w):
                if 0 <= r < n and 0 <= c < n:
                    fn[r][c] = True

    # finder + separator + format bits (9x9 at three corners)
    mark(0, 0, 9, 9)
    mark(0, n - 8, 9, 8)
    mark(n - 8, 0, 8, 9)
    # timing patterns
    mark(6, 0, 1, n)
    mark(0, 6, n, 1)
    # alignment patterns
    centres = _ALIGN.get(version, [])
    last = n - 7
    for r in centres:
        for c in centres:
            if (r == 6 and c == 6) or (r == 6 and c == last) or (r == last and c == 6):
                continue
            mark(r - 2, c - 2, 5, 5)
    # version information (version >= 7)
    if version >= 7:
        mark(0, n - 11, 6, 3)
        mark(n - 11, 0, 3, 6)
    # dark module
    fn[4 * version + 9][8] = True
    return fn


def _mask_bit(mask: int, r: int, c: int) -> bool:
    if mask == 0:
        return (r + c) % 2 == 0
    if mask == 1:
        return r % 2 == 0
    if mask == 2:
        return c % 3 == 0
    if mask == 3:
        return (r + c) % 3 == 0
    if mask == 4:
        return (r // 2 + c // 3) % 2 == 0
    if mask == 5:
        return (r * c) % 2 + (r * c) % 3 == 0
    if mask == 6:
        return ((r * c) % 2 + (r * c) % 3) % 2 == 0
    if mask == 7:
        return ((r + c) % 2 + (r * c) % 3) % 2 == 0
    raise ValueError(f"bad mask {mask}")


def _data_positions(version: int) -> list[tuple[int, int]]:
    """Codeword read order: upward/downward column pairs, right to left, skipping col 6."""
    n = 17 + 4 * version
    fn = _function_mask(version)
    out: list[tuple[int, int]] = []
    col = n - 1
    upward = True
    while col > 0:
        if col == 6:  # the vertical timing pattern is not a data column
            col -= 1
            continue
        rows = range(n - 1, -1, -1) if upward else range(n)
        for r in rows:
            for c in (col, col - 1):
                if not fn[r][c]:
                    out.append((r, c))
        upward = not upward
        col -= 2
    return out


def _codewords(m: list[list[bool]], version: int, mask: int) -> bytes:
    positions = _data_positions(version)
    bits = []
    for r, c in positions:
        value = m[r][c]
        if _mask_bit(mask, r, c):
            value = not value
        bits.append(1 if value else 0)
    usable = (len(bits) // 8) * 8
    out = bytearray()
    for i in range(0, usable, 8):
        byte = 0
        for bit in bits[i : i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def _deinterleave(data: bytes, version: int, level: str) -> bytes:
    """Undo the interleaving so the returned bytes are the contiguous data codewords."""
    try:
        ec_per_block, g1n, g1d, g2n, g2d = _BLOCKS[(version, level)]
    except KeyError:
        raise QrError(f"no block table for version {version} level {level}") from None

    lens = [g1d] * g1n + [g2d] * g2n
    if not lens:
        raise QrError("empty block layout")
    blocks = [[] for _ in lens]
    idx = 0
    for i in range(max(lens)):
        for b, length in enumerate(lens):
            if i < length:
                if idx >= len(data):
                    return b"".join(bytes(x) for x in blocks)
                blocks[b].append(data[idx])
                idx += 1
    return b"".join(bytes(x) for x in blocks)


# ------------------------------------------------------------------------- bit parsing


def _length_bits(mode: str, version: int) -> int:
    group = 0 if version <= 9 else 1  # versions 10-26 share the same widths as group 1
    table = {
        "numeric": (10, 12),
        "alnum": (9, 11),
        "byte": (8, 16),
    }
    return table[mode][min(group, 1)]


class _Bits:
    def __init__(self, data: bytes) -> None:
        self.bits = "".join(f"{b:08b}" for b in data)
        self.pos = 0

    def take(self, n: int) -> int | None:
        if self.pos + n > len(self.bits):
            return None
        chunk = self.bits[self.pos : self.pos + n]
        self.pos += n
        return int(chunk, 2)

    @property
    def remaining(self) -> int:
        return len(self.bits) - self.pos


def _parse_segments(data: bytes, version: int) -> tuple[str, list]:
    bits = _Bits(data)
    out: list[str] = []
    segments: list[tuple[str, int]] = []

    while bits.remaining >= 4:
        mode = bits.take(4)
        if mode is None or mode == 0:  # 0000 terminator
            break
        if mode == 0b0111:  # ECI designator - skip the assignment number
            first = bits.take(8)
            if first is None:
                break
            if first & 0x80 == 0:
                continue
            if first & 0xC0 == 0x80:
                bits.take(8)
                continue
            bits.take(16)
            continue
        if mode == 0b0011:  # structured append
            bits.take(16)
            continue
        if mode == 0b0101 or mode == 0b1001:  # FNC1 - no payload header
            continue

        if mode == 0b0001:
            kind = "numeric"
        elif mode == 0b0010:
            kind = "alnum"
        elif mode == 0b0100:
            kind = "byte"
        else:
            raise QrError(f"unsupported mode {mode:04b} at bit {bits.pos - 4}")

        count = bits.take(_length_bits(kind, version))
        if count is None:
            raise QrError(f"truncated length for {kind} segment")
        segments.append((kind, count))

        if kind == "numeric":
            while count >= 3:
                v = bits.take(10)
                if v is None or v > 999:
                    raise QrError("bad numeric group")
                out.append(f"{v:03d}")
                count -= 3
            if count == 2:
                v = bits.take(7)
                if v is None or v > 99:
                    raise QrError("bad numeric tail")
                out.append(f"{v:02d}")
            elif count == 1:
                v = bits.take(4)
                if v is None or v > 9:
                    raise QrError("bad numeric tail")
                out.append(f"{v}")
        elif kind == "alnum":
            while count >= 2:
                v = bits.take(11)
                if v is None or v >= 45 * 45:
                    raise QrError("bad alnum pair")
                out.append(_ALNUM[v // 45] + _ALNUM[v % 45])
                count -= 2
            if count == 1:
                v = bits.take(6)
                if v is None or v >= 45:
                    raise QrError("bad alnum tail")
                out.append(_ALNUM[v])
        else:  # byte
            buf = bytearray()
            for _ in range(count):
                v = bits.take(8)
                if v is None:
                    raise QrError("truncated byte segment")
                buf.append(v)
            try:
                out.append(buf.decode("utf-8"))
            except UnicodeDecodeError:
                out.append(buf.decode("latin-1"))

    return "".join(out), segments


# ----------------------------------------------------------------------------- public


def decode_matrix(m: list[list[bool]], version: int) -> Decoded:
    """Decode an already-sampled module matrix, brute-forcing mask and EC level."""
    n = 17 + 4 * version
    if len(m) != n or any(len(row) != n for row in m):
        raise QrError(f"matrix is not {n}x{n}")

    attempts = []
    for level in ("L", "M", "Q", "H"):
        for mask in range(8):
            raw = _codewords(m, version, mask)
            data = _deinterleave(raw, version, level)
            try:
                text, segments = _parse_segments(data, version)
            except QrError as exc:
                attempts.append((level, mask, f"parse: {exc}"))
                continue
            if text:
                return Decoded(text=text, version=version, size=n, mask=mask,
                               level=level, segments=segments)
            attempts.append((level, mask, "empty payload"))

    raise QrError("no (level, mask) produced a parseable payload; first failures: "
                  + "; ".join(f"{lv}/{mk}:{why}" for lv, mk, why in attempts[:4]))


def decode_gray(gray) -> Decoded:
    """Decode a greyscale image given as rows of 0..255 ints."""
    m, version = matrix_from_gray(gray)
    return decode_matrix(m, version)


def decode_pil(image) -> Decoded:
    """Decode a PIL image."""
    gray_img = image.convert("L")
    w, h = gray_img.size
    px = gray_img.load()
    gray = [[px[x, y] for x in range(w)] for y in range(h)]
    return decode_gray(gray)
