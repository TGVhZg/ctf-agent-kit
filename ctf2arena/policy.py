"""Client-side enforcement of the CTF2 Agent safety rules.

The official ``references/safety.md`` lists prohibitions in prose. Prose does not stop a
bug, so each rule that can be checked locally is encoded here and called from the client
before a request leaves the machine:

============================  =====================================================
rule                          enforcement
============================  =====================================================
no flag in a replay note      :meth:`Guard.check_note`
no reading others' writeups   :meth:`Guard.check_operation` (writeup:/community: blocks)
no unconfirmed submission     :meth:`Guard.check_submission`
no credential in a commit     :func:`assert_no_secret_in_text` (used by the git hook)
============================  =====================================================

Rules that *cannot* be enforced locally (do not attack the platform, do not scan hosts
other than your own environment) are stated in the README and in each skill, because they
require judgement rather than a predicate.
"""

from __future__ import annotations

from .errors import PolicyViolation
from .redact import looks_like_flag

#: Scopes that expose other people's solutions or community content. The play guide closes
#: these to Agents; requesting them is a rule violation, not just an inefficiency.
FORBIDDEN_SCOPES = frozenset({"writeup:read", "community:read", "ticket:read", "ticket:write"})

#: Operation-id prefixes that reach the same surfaces even when scope metadata is absent.
FORBIDDEN_OPERATION_MARKERS = ("writeups", "community", "private_practice", "tickets")

#: Player-vs-player / infrastructure-admin surfaces an Agent must never touch.
ADMIN_MARKERS = ("_admin_", "/admin/")


class Guard:
    """Fail-closed checks applied immediately before a request is sent."""

    def __init__(self, *, allow_competition: bool = False) -> None:
        self.allow_competition = allow_competition

    def check_operation(self, operation) -> None:
        """Refuse operations that reach surfaces closed to Agents."""
        scope = (operation.scope or "").lower()
        op_id = operation.operation_id

        if scope in FORBIDDEN_SCOPES:
            raise PolicyViolation(
                "closed-surface",
                f"{op_id} needs scope {scope!r}, which the Agent play guide closes to "
                "Agents (writeups, community, tickets, private practice). Use your own "
                "solves instead.",
            )
        for marker in FORBIDDEN_OPERATION_MARKERS:
            if marker in op_id:
                raise PolicyViolation(
                    "closed-surface",
                    f"{op_id} reaches a surface closed to Agents ({marker}).",
                )
        if any(marker in operation.path for marker in ADMIN_MARKERS):
            raise PolicyViolation(
                "admin-surface",
                f"{op_id} is an administrator route; an Agent grant must not be reused for "
                "admin workflows.",
            )
        if "competition" in op_id and not self.allow_competition:
            raise PolicyViolation(
                "competition-not-enabled",
                f"{op_id} is a competition operation but competitions are not enabled for "
                "this Agent. Ask the owner to allow competitions in the CTF2 Agent arena, "
                "then construct AgentSession(allow_competition=True).",
            )

    def check_submission(self, flag: str, *, confirmation: bool) -> str:
        """Validate a flag submission and return the normalised flag.

        Triple gate: the caller must pass ``confirmation=True`` (a human said yes to this
        exact value), the value must be non-empty, and it must not look like a placeholder.
        """
        if not confirmation:
            raise PolicyViolation(
                "unconfirmed-submit",
                "flag submission requires confirmation=True after the exact flag has been "
                "confirmed; the platform rejects the body without it anyway.",
            )
        value = (flag or "").strip()
        if not value:
            raise PolicyViolation("empty-flag", "refusing to submit an empty flag.")
        if len(value) > 4096:
            raise PolicyViolation(
                "oversized-flag",
                f"flag is {len(value)} chars; the API caps it at 4096, so this is almost "
                "certainly a dump rather than a flag.",
            )
        if not looks_like_flag(value) and " " in value:
            raise PolicyViolation(
                "flag-looks-wrong",
                "flag contains whitespace and no flag-shaped token; check for a copy error.",
            )
        return value

    def check_note(self, content: str) -> str:
        """Refuse to write a flag (or credential-shaped text) into a replay note."""
        hit = looks_like_flag(content)
        if hit:
            # Report the rule without echoing the secret back into logs.
            raise PolicyViolation(
                "flag-in-note",
                f"note contains a flag-shaped token ({len(hit)} chars). Replay notes are "
                "visible to the owner and may be published; describe the method instead.",
            )
        return content


def assert_no_secret_in_text(text: str, secrets) -> None:
    """Raise if any known secret appears verbatim in *text* (pre-commit guard)."""
    for secret in secrets:
        if secret and len(secret) >= 6 and secret in text:
            raise PolicyViolation(
                "secret-in-artifact",
                "a live credential appears in a file that is about to be committed; "
                "rotate it and remove it from history.",
            )
