"""Static ELF reconnaissance without a decompiler.

This module automates what repeatedly took the longest during the arena run:
locating ``main``, reading the GOT slot table, and finding stack pivots.
Everything here works on a *stripped* ELF as long as ``binutils`` is present.

Two hard-won rules are baked in:

* ``.dynsym`` usually still exports ``main`` (the C runtime needs it), so
  ``objdump`` prints a ``<main@@Base>`` label even after ``strip``.
* **PLT stubs need ``ebx`` to point at the GOT** (``jmp DWORD PTR [ebx+0x10]``).
  A pivot that pops ``ebx`` therefore silently breaks every library call.
  :func:`find_pivots` marks such gadgets instead of letting you discover it by
  crashing — that exact trap cost several rounds on ``rec_33c3_2016``.

Gadget search is **byte-level on purpose**: linear disassembly never marks a
gadget that starts mid-instruction, so grepping ``objdump`` output under-reports.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TIMEOUT = 60

#: Single-byte ``pop r32`` encodings (x86).
POP_BYTES = {
    0x58: "eax", 0x59: "ecx", 0x5A: "edx", 0x5B: "ebx",
    0x5D: "ebp", 0x5E: "esi", 0x5F: "edi",
}


class ToolMissing(RuntimeError):
    """A required binutils tool is not on PATH."""


class NotAnElf(ValueError):
    """The file does not start with the ELF magic."""


@dataclass(frozen=True)
class Section:
    name: str
    addr: int
    offset: int
    size: int
    flags: str

    def contains(self, vaddr: int) -> bool:
        return self.addr <= vaddr < self.addr + self.size and self.size > 0


@dataclass(frozen=True)
class PivotHit:
    """One stack-pivot candidate."""

    addr: int
    kind: str
    pops: tuple[str, ...] = ()
    advance: int = 0
    clobbers_ebx: bool = False

    @property
    def usable_with_plt(self) -> bool:
        return not self.clobbers_ebx

    def __str__(self) -> str:
        ebx = "  (clobbers ebx -> breaks PLT)" if self.clobbers_ebx else ""
        return f"0x{self.addr:x}  {self.kind}  advance=0x{self.advance:x}{ebx}"


def _tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise ToolMissing(f"{name} not on PATH; install binutils")
    return found


def _run(argv: list[str]) -> str:
    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=DEFAULT_TIMEOUT
    )
    return (proc.stdout or "") + (proc.stderr or "")


def scan_bytes(data: bytes, needle: bytes) -> list[int]:
    """Every offset where ``needle`` occurs (overlapping matches included)."""
    if not needle:
        return []
    out, start = [], 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return out
        out.append(i)
        start = i + 1


def find_pivots(
    data: bytes,
    *,
    base: int = 0,
    avoid_ebx: bool = False,
    max_imm: int = 0x40,
) -> list[PivotHit]:
    """Locate ``ret``-terminated stack pivots by decoding backwards from each ``ret``.

    Recognises ``add esp, imm8; ret``, ``ret imm16`` and up to four consecutive
    ``pop r32; ret``.  With ``avoid_ebx=True`` the results are filtered down to
    pivots that leave ``ebx`` alone, i.e. the ones still usable in front of a
    PLT call.

    .. warning::
       Backward decoding from every ``0xC3`` byte also matches ``0xC3`` bytes
       that are merely *operands* of some longer instruction, so candidates are
       hints, not facts.  ``ret imm16`` is additionally filtered by ``max_imm``
       because an immediate of 0x2a17 is never a real epilogue.  Confirm any
       candidate with :meth:`ElfFacts.confirm` before building a chain on it.
    """
    hits: list[PivotHit] = []
    for i, byte in enumerate(data):
        if byte != 0xC3:  # ret
            continue
        # add esp, imm8 ; ret
        if i >= 3 and data[i - 3] == 0x83 and data[i - 2] == 0xC4:
            hits.append(
                PivotHit(
                    addr=base + i - 3, kind="add esp,imm; ret",
                    advance=data[i - 1],
                )
            )
        # up to four pops ; ret
        for count in (4, 3, 2, 1):
            if i - count < 0:
                continue
            window = data[i - count:i]
            if all(b in POP_BYTES for b in window):
                pops = tuple(POP_BYTES[b] for b in window)
                hits.append(
                    PivotHit(
                        addr=base + i - count,
                        kind=f"{count} pop; ret",
                        pops=pops,
                        advance=4 * count,
                        clobbers_ebx="ebx" in pops,
                    )
                )
                break
    # ret imm16 (0xC2 <imm16>) advances by 4 + imm after popping the return address
    for i in range(len(data) - 2):
        if data[i] == 0xC2:
            imm = struct.unpack_from("<H", data, i + 1)[0]
            if imm <= max_imm:
                hits.append(
                    PivotHit(addr=base + i, kind="ret imm16", advance=4 + imm)
                )
    if avoid_ebx:
        hits = [h for h in hits if not h.clobbers_ebx]
    hits.sort(key=lambda h: h.addr)
    return hits


@dataclass
class ElfFacts:
    """Reconnaissance summary for one ELF, filled by :meth:`load`."""

    path: Path
    sections: list[Section] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    got_slots: dict[str, int] = field(default_factory=dict)
    main: int | None = None
    has_textrel_plt: bool = False

    @classmethod
    def load(cls, path: str | Path) -> "ElfFacts":
        p = Path(path)
        head = p.read_bytes()[:4]
        if head != b"\x7fELF":
            raise NotAnElf(f"{p} is not an ELF")
        self = cls(path=p)
        self.sections = self._parse_sections()
        self.imports = self._parse_imports()
        self.got_slots = self._parse_got()
        self.main = self._parse_main()
        return self

    # -- readers -----------------------------------------------------
    def _parse_sections(self) -> list[Section]:
        text = _run([_tool("readelf"), "-SW", str(self.path)])
        out: list[Section] = []
        pat = re.compile(
            r"\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)"
        )
        for line in text.splitlines():
            m = pat.match(line.strip())
            if not m:
                continue
            name, _type, addr, off, size = m.groups()
            try:
                out.append(
                    Section(name, int(addr, 16), int(off, 16), int(size, 16), "")
                )
            except ValueError:
                continue
        return out

    def _parse_imports(self) -> list[str]:
        text = _run([_tool("readelf"), "--dyn-syms", str(self.path)])
        names = []
        for line in text.splitlines():
            if " UND " not in line:
                continue
            tail = line.split()[-1]
            name = tail.split("@")[0]
            if name and name not in names:
                names.append(name)
        return names

    def _parse_got(self) -> dict[str, int]:
        text = _run([_tool("readelf"), "-rW", str(self.path)])
        slots: dict[str, int] = {}
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 5 or not re.fullmatch(r"[0-9a-f]{6,16}", parts[0]):
                continue
            name = parts[-1].split("@")[0]
            try:
                slots[name] = int(parts[0], 16)
            except ValueError:
                continue
        return slots

    def _parse_main(self) -> int | None:
        text = _run([_tool("objdump"), "-d", str(self.path)])
        for line in text.splitlines():
            if "<main@@Base>:" in line or "<main>:" in line:
                token = line.split()[0].rstrip(":")
                try:
                    return int(token, 16)
                except ValueError:
                    return None
        return None

    # -- mapping -----------------------------------------------------
    def offset_of(self, vaddr: int) -> int:
        for s in self.sections:
            if s.contains(vaddr):
                return s.offset + (vaddr - s.addr)
        raise KeyError(f"0x{vaddr:x} is not inside any section")

    def vaddr_of(self, offset: int) -> int:
        for s in self.sections:
            if s.size and s.offset <= offset < s.offset + s.size:
                return s.addr + (offset - s.offset)
        raise KeyError(f"file offset 0x{offset:x} is not inside any section")

    def section(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def pivots(self, *, avoid_ebx: bool = True) -> list[PivotHit]:
        """Scan ``.text`` for pivots, reported as PIE-relative addresses."""
        text = self.section(".text")
        if text is None or text.size == 0:
            return []
        data = self.path.read_bytes()[text.offset:text.offset + text.size]
        return find_pivots(data, base=text.addr, avoid_ebx=avoid_ebx)

    def confirm(self, addr: int, *, count: int = 3) -> list[str]:
        """Disassemble *at exactly* ``addr`` and return the first ``count`` instructions.

        Byte-level scanning produces candidates; this is how you promote one to
        a fact.  A real gadget disassembles cleanly from its own first byte,
        whereas a mid-instruction false positive usually shows up as garbage.
        """
        text = _run(
            [
                _tool("objdump"), "-d", "-M", "intel",
                f"--start-address=0x{addr:x}",
                f"--stop-address=0x{addr + 0x20:x}",
                str(self.path),
            ]
        )
        out: list[str] = []
        for line in text.splitlines():
            m = re.match(r"\s+([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*(.+)", line)
            if not m:
                continue
            mnemonic = m.group(2).strip()
            if not mnemonic:
                continue
            out.append(mnemonic)
            if len(out) >= count:
                break
        return out

    def summary(self) -> str:
        lines = [f"{self.path.name}: {len(self.sections)} sections"]
        if self.main is not None:
            lines.append(f"  main          = 0x{self.main:x}")
        lines.append(f"  imports       = {', '.join(self.imports) or '(none)'}")
        if self.got_slots:
            got = ", ".join(
                f"{k}@0x{v:x}" for k, v in sorted(self.got_slots.items())[:8]
            )
            lines.append(f"  got slots     = {got}")
        pivots = [p for p in self.pivots(avoid_ebx=False)]
        usable = [p for p in pivots if p.usable_with_plt]
        lines.append(
            f"  pivots        = {len(pivots)} found, {len(usable)} usable before PLT"
        )
        for p in pivots[:6]:
            lines.append(f"    {p}")
        if not usable:
            lines.append(
                "    !! no ebx-safe pivot: any PLT call through these will crash"
            )
        return "\n".join(lines)
