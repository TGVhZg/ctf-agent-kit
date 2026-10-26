"""Typed errors for the CTF2 Open API.

The platform returns ``{"error": {"code": ..., "key": ..., "params": ...}, "success": false}``
on the Open API and a richer ``structuredContent`` envelope on the MCP transport. Both are
normalised here into :class:`Ctf2Error` so callers branch on ``.code`` instead of parsing
prose.

``RETRYABLE_CODES`` mirrors the recovery table in the official ``agent-play.md`` reference.
Anything not listed is treated as terminal: retrying a non-retryable code wastes the
120 reads / 30 writes per minute budget and, for submissions, can burn an attempt.
"""

from __future__ import annotations


#: Codes where the official play guide says "retry after retry_after_ms".
RETRYABLE_CODES = frozenset(
    {
        "backend_unavailable",
        "challenge_not_open",
        "competition_not_started",
        "competition_paused",
        "conflict",
        "environment_not_running",
        "internal_error",
        "agent_note_limit",
        "rate_limit_exceeded",
        "rate_limited",
        "stage_paused",
        "submission_cooldown",
    }
)

#: Codes that mean "your credential is done, stop working until a human intervenes".
TERMINAL_AUTH_CODES = frozenset(
    {
        "AUTH_REQUIRED",
        "TOKEN_EXPIRED",
        "unauthorized",
        "permission_denied",
        "agent_disabled",
        "agent_arena_disabled",
        "user_banned",
        "team_banned",
    }
)

#: Codes that mean "this Agent identity is not allowed to touch that surface at all".
AGENT_FORBIDDEN_CODES = frozenset(
    {
        "agent_only_operation",
        "agent_scope_forbidden",
        "agent_competition_not_enabled",
        "agent_competition_opted_out",
        "agent_competition_not_open",
        "stage_audience_forbidden",
    }
)


class Ctf2Error(Exception):
    """A structured failure returned by, or inferred about, the CTF2 API."""

    def __init__(
        self,
        code: str,
        message: str = "",
        *,
        status: int | None = None,
        retryable: bool | None = None,
        retry_after_ms: int | None = None,
        hint: str | None = None,
        payload: dict | None = None,
        request_id: str | None = None,
    ) -> None:
        self.code = code
        self.message = message or code
        self.status = status
        self.retry_after_ms = retry_after_ms
        self.hint = hint
        self.payload = payload or {}
        self.request_id = request_id
        if retryable is None:
            retryable = code.lower() in {c.lower() for c in RETRYABLE_CODES}
        self.retryable = bool(retryable)
        super().__init__(self.__str__())

    @property
    def auth_fatal(self) -> bool:
        """True when the credential itself is unusable and must not be reused."""
        return self.status == 401 or self.code in TERMINAL_AUTH_CODES

    @property
    def scope_forbidden(self) -> bool:
        """True when the credential is valid but lacks the required scope."""
        return self.status == 403 and not self.auth_fatal

    def __str__(self) -> str:
        bits = [self.code]
        if self.status is not None:
            bits.append(f"http={self.status}")
        if self.retryable:
            bits.append(f"retryable in {self.retry_after_ms or 0}ms")
        if self.hint:
            bits.append(f"hint={self.hint}")
        head = " ".join(bits)
        return f"{head}: {self.message}" if self.message and self.message != self.code else head


class RetryableError(Ctf2Error):
    """Convenience subclass for the retry loop."""


class PolicyViolation(Exception):
    """Raised when local policy refuses an action the platform would have allowed.

    This is a *client-side* refusal. It exists so that a caller cannot violate the Agent
    safety rules by accident: reading community writeups, writing a flag into a replay
    note, or submitting without a human-confirmed flag.
    """

    def __init__(self, rule: str, detail: str) -> None:
        self.rule = rule
        self.detail = detail
        super().__init__(f"[{rule}] {detail}")
