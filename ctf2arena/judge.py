"""Judgements that cannot flatter you.

Most lost rounds in the arena were not "I did not know the technique" but
"I believed a check that could never fail".  Two of them were expensive
enough to deserve code:

* **Page alignment as a libc-version oracle.**  ``leak - offset`` is a
  multiple of 0x1000 *whenever the low 12 bits of the two values agree*, and
  a lookup service that matches on those bits guarantees exactly that.  Ten
  candidates "passing" the check is therefore evidence of nothing.
* **Printable-rate as a flag oracle.**  Requiring "mostly printable" or
  "contains a brace" happily accepts binary garbage; the real requirement is
  a complete ``shell{...}`` whose body is entirely printable.

The primitive that separates the two mistakes from a real test is the
**negative control**: a judgement is only allowed to count when it also
rejects the alternatives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CONFIDENCE_LEVELS = ("observed", "derived", "inferred")

#: ``shell{...}`` with a fully printable, non-empty body.
#: The body is matched *lazily* on purpose: a greedy ``[ -~]{1,200}`` happily
#: swallows ``}`` and spaces to reach a later brace, which silently defeats the
#: "body is entirely printable" rule (``CTF2{x} and CTF2{x}`` would parse as one
#: flag with a space in it).  Bodies containing a brace are rejected outright.
FLAG_PATTERN = re.compile(rb"([A-Za-z][A-Za-z0-9_]{0,31})\{([ -~]{1,200}?)\}")

_PRINTABLE = set(range(0x20, 0x7F))


class BadJudgement(ValueError):
    """A judgement was stated without usable support."""


@dataclass(frozen=True)
class Judgement:
    """A claim plus the evidence that supports it."""

    claim: str
    evidence: str
    confidence: str = "derived"

    def __post_init__(self) -> None:
        if self.confidence not in CONFIDENCE_LEVELS:
            raise BadJudgement(f"confidence must be one of {CONFIDENCE_LEVELS}")
        if not self.claim.strip():
            raise BadJudgement("claim must not be empty")
        if self.confidence == "observed" and not self.evidence.strip():
            raise BadJudgement("an 'observed' claim needs concrete evidence")


def find_flags(blob: bytes, *, min_body: int = 1) -> list[str]:
    """Strict flag extraction: complete shell, body entirely printable.

    Never returns a candidate whose body straddles binary bytes — the
    failure mode that makes "contains a brace" useless.
    """
    out: list[str] = []
    for m in FLAG_PATTERN.finditer(blob):
        shell, body = m.group(1), m.group(2)
        if len(body) < min_body:
            continue
        if not all(b in _PRINTABLE for b in body):
            continue
        if b"{" in body or b"}" in body:
            continue
        try:
            text = (shell + b"{" + body + b"}").decode("ascii")
        except UnicodeDecodeError:
            continue
        if text not in out:
            out.append(text)
    return out


def printable_rate(blob: bytes) -> float:
    """Fraction of printable bytes — reported for context, never decisive."""
    if not blob:
        return 0.0
    return sum(1 for b in blob if b in _PRINTABLE) / len(blob)


def alignment_is_tautological(leak: int, symbol_offset: int) -> bool:
    """True when the page-alignment check on ``leak - symbol_offset`` cannot fail.

    That happens exactly when the two values share their low 12 bits, which is
    what nibble-matching lookup services guarantee by construction.
    """
    return (leak & 0xFFF) == (symbol_offset & 0xFFF)


def discriminating(hits_on_target: int, hits_on_control: int) -> bool:
    """A test only counts if it fires on the target and *not* on the control."""
    return hits_on_target > 0 and hits_on_control == 0


def alignment_warning(leak: int, symbol_offset: int) -> str | None:
    """Human-readable warning, or ``None`` when the check is informative."""
    if alignment_is_tautological(leak, symbol_offset):
        base = leak - symbol_offset
        return (
            f"alignment check is vacuous: leak low12=0x{leak & 0xFFF:03x} equals "
            f"offset low12=0x{symbol_offset & 0xFFF:03x}, so base=0x{base:x} "
            "is page-aligned for every candidate sharing those bits"
        )
    return None
