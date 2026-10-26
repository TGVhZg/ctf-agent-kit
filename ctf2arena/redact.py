"""Scrubbing of secrets (tokens) and answers (flags) from anything we print or persist.

Two different jobs, deliberately kept apart:

* :class:`Redactor` removes *credentials* from outbound text. Tokens must never reach a
  log file, a git commit, or a replay note.
* :func:`looks_like_flag` detects *answers* so :mod:`ctf2arena.policy` can refuse to put
  them in a note. The platform publishes replay notes to the Agent's owner, so a flag in
  a note is a leak.

Neither function tries to be clever about entropy. A false negative on the flag detector
would leak an answer, so the detector is intentionally broad; a false positive only costs
one rejected note, which is the cheap direction to fail in.
"""

from __future__ import annotations

import re

_MASK = "«redacted»"

#: Obvious credential shapes: match and drop them.
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(authorization)\s*:\s*(?:bearer|x-ctf2-api-key)\s+\S+"),
    re.compile(r"(?i)\b(x-ctf2-api-key)\s*:\s*\S+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT
    re.compile(r"\bctf2_[A-Za-z0-9]{16,}\b"),
)

#: Flag shapes worth refusing in a note: a word-ish prefix, then a non-empty brace body.
#:
#: The body length floor is deliberately 1 rather than something "realistic": this
#: detector guards a note that is published to the challenge owner, so a false positive
#: costs one rejected note while a false negative leaks an answer. An empty body (``a{}``)
#: is excluded because it is never a flag and shows up in ordinary code snippets.
_FLAG_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,31}\{[^{}\r\n]{1,512}\}")


class Redactor:
    """Removes known secret values from text before it is logged or written."""

    def __init__(self, secrets=()):
        # Longest first so a token that contains another token is fully masked.
        self._secrets = sorted({s for s in secrets if s and len(s) >= 6}, key=len, reverse=True)

    def add(self, secret: str) -> None:
        if secret and len(secret) >= 6 and secret not in self._secrets:
            self._secrets.append(secret)
            self._secrets.sort(key=len, reverse=True)

    def __call__(self, text: str) -> str:
        return self.redact(text)

    def redact(self, text: str) -> str:
        if not text:
            return text
        out = text
        for secret in self._secrets:
            out = out.replace(secret, _MASK)
        for pattern in _SECRET_PATTERNS:
            out = pattern.sub(_MASK, out)
        return out

    def redact_obj(self, value):
        """Recursively redact strings inside lists/dicts (used for captured payloads)."""
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, dict):
            return {k: self.redact_obj(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.redact_obj(v) for v in value]
        return value


def looks_like_flag(text: str) -> str | None:
    """Return the first flag-shaped substring in *text*, or ``None``.

    Used as a hard gate before writing a replay note. Keeping the return value (rather
    than a bool) lets the caller say *what* tripped the rule without echoing a whole note.
    """
    if not text:
        return None
    match = _FLAG_PATTERN.search(text)
    return match.group(0) if match else None
