"""The Agent play loop: find -> read -> fetch -> environment -> submit -> note.

This mirrors ``references/agent-play.md`` step by step, but as callable methods that keep
the invariants straight:

* environments are polled idempotently until ``access_ready`` and the quota (default 1) is
  respected by refusing to start a second one while the first is alive;
* attachments are fetched *immediately* after the signed URL is issued, because that URL
  dies after five minutes and is bound to this credential;
* submissions go through :meth:`Guard.check_submission`, so ``confirmation=True`` has to be
  passed deliberately;
* notes go through :meth:`Guard.check_note`, which refuses flag-shaped text.
"""

from __future__ import annotations

import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .client import Client
from .errors import Ctf2Error, PolicyViolation

DEFAULT_POLL_SECONDS = 4.0
DEFAULT_POLL_BUDGET = 90.0


@dataclass
class Challenge:
    """A practice or competition challenge, normalised across both tool families."""

    id: str
    name: str
    source: str = "practice"  # "practice" | "competition"
    category: str | None = None
    difficulty: str | None = None
    points: int | None = None
    solve_count: int | None = None
    is_solved: bool = False
    has_container: bool = False
    has_attachments: bool = False
    practice_ground_id: str | None = None
    competition_id: str | None = None
    stage_id: str | None = None
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(cls, item: dict) -> "Challenge":
        src = item.get("source") or {}
        source = src.get("type") or ("competition" if item.get("competition_id") else "practice")
        return cls(
            id=item.get("id") or item.get("challenge_id") or "",
            name=item.get("name") or item.get("title") or "(unnamed)",
            source=source,
            category=item.get("category"),
            difficulty=item.get("difficulty"),
            points=item.get("points"),
            solve_count=item.get("solve_count"),
            is_solved=bool(item.get("is_solved")),
            has_container=bool(item.get("has_container")),
            has_attachments=bool(item.get("has_attachments") or item.get("files")),
            practice_ground_id=item.get("practice_ground_id") or src.get("practice_ground_id"),
            competition_id=item.get("competition_id") or src.get("competition_id"),
            stage_id=item.get("stage_id") or src.get("stage_id"),
            raw=item,
        )

    def __str__(self) -> str:
        tags = [self.source]
        if self.category:
            tags.append(self.category)
        if self.difficulty:
            tags.append(str(self.difficulty))
        if self.points is not None:
            tags.append(f"{self.points}pt")
        where = self.practice_ground_id or self.competition_id
        suffix = f" ground={where}" if where else ""
        return f"{self.name} [{', '.join(tags)}] id={self.id}{suffix}"


@dataclass
class Endpoint:
    """One structured connection target derived from a practice environment."""

    kind: str
    url: str
    host: str | None
    port: int | None
    tls: bool

    @staticmethod
    def split_host_port(url: str) -> tuple[str | None, int | None]:
        """Pull host and port out of ``http://h:p`` or a bare ``h:p``."""
        import re

        if not url:
            return None, None
        match = re.search(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*://)?([^/:]+)(?::(\d+))?", url)
        if not match:
            return None, None
        host = match.group(1)
        port = int(match.group(2)) if match.group(2) else None
        return host, port


class AgentSession:
    """High-level Agent operations over a :class:`~ctf2arena.client.Client`."""

    def __init__(self, client: Client | None = None, *, allow_competition: bool = False) -> None:
        if client is None:
            from .policy import Guard

            client = Client(guard=Guard(allow_competition=allow_competition))
        self.client = client

    # -- identity ---------------------------------------------------------------

    def whoami(self) -> dict:
        """``ctf2_agent_whoami``: identity, results, quotas, allowed tools, rules."""
        return self.client.call("user_get_agent_me")

    # -- discovery --------------------------------------------------------------

    def next_challenges(
        self,
        *,
        limit: int = 10,
        category: str | None = None,
        difficulty: str | None = None,
        source: str = "all",
    ) -> list[Challenge]:
        data = self.client.call(
            "user_get_agent_next_challenges",
            query={
                "limit": max(1, min(100, limit)),
                "category": category,
                "difficulty": difficulty,
                "source": source,
            },
        )
        return [Challenge.from_api(item) for item in (data or {}).get("items", [])]

    def practice_grounds(self) -> list[dict]:
        data = self.client.call("user_get_practice")
        return _as_items(data)

    def practice_challenges(
        self,
        ground_id: str,
        *,
        category: str | None = None,
        difficulty: str | None = None,
        unsolved_only: bool = True,
    ) -> list[Challenge]:
        data = self.client.call(
            "user_get_practice_id_challenges",
            path_params={"id": ground_id},
            query={
                "category": category,
                "difficulty": difficulty,
                "unsolved_only": "true" if unsolved_only else None,
            },
        )
        out = []
        for item in _as_items(data):
            challenge = Challenge.from_api(item)
            challenge.practice_ground_id = challenge.practice_ground_id or ground_id
            out.append(challenge)
        return out

    def get_challenge(self, ground_id: str, challenge_id: str) -> dict:
        """Full statement: description, ``files[].id``, ``has_container``, sub-flags."""
        return self.client.call(
            "user_get_practice_id_challenges_challengeid",
            path_params={"id": ground_id, "challengeId": challenge_id},
        )

    # -- attachments ------------------------------------------------------------

    def attachment_url(self, ground_id: str, challenge_id: str, file_id: str) -> str:
        data = self.client.call(
            "user_get_practice_id_challenges_challengeid_files_fileid_download",
            path_params={"id": ground_id, "challengeId": challenge_id, "fileId": file_id},
        )
        return _pick_url(data)

    def fetch_attachment(
        self,
        ground_id: str,
        challenge_id: str,
        file_id: str,
        dest_dir: str | Path,
        *,
        filename: str | None = None,
        tries: int = 2,
    ) -> Path:
        """Issue a signed URL and download it *now* (it dies after five minutes)."""
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        name = _safe_filename(filename or file_id)
        target = dest / name

        last: Exception | None = None
        for _ in range(max(1, tries)):
            url = self.attachment_url(ground_id, challenge_id, file_id)
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "ctf2arena/0.1"})
                with urllib.request.urlopen(request, timeout=120) as response:
                    target.write_bytes(response.read())
                return target
            except Exception as exc:  # noqa: BLE001 - re-issue once, then surface it
                last = exc
                if isinstance(exc, Ctf2Error) and exc.code == "attachment_link_expired":
                    continue
                break
        raise Ctf2Error(
            "attachment_download_failed",
            f"could not download file {file_id}: {last}",
            retryable=False,
        )

    # -- environments -----------------------------------------------------------

    def environment(self, ground_id: str, challenge_id: str) -> dict:
        return self.client.call(
            "user_get_practice_id_challenges_challengeid_environment",
            path_params={"id": ground_id, "challengeId": challenge_id},
        )

    def start_environment(self, ground_id: str, challenge_id: str) -> dict:
        """Start or reuse. Raises with the play guide's hint on the quota error."""
        try:
            return self.client.call(
                "user_post_practice_id_challenges_challengeid_environment_start",
                path_params={"id": ground_id, "challengeId": challenge_id},
            )
        except Ctf2Error as exc:
            if exc.code == "agent_environment_limit":
                raise Ctf2Error(
                    "agent_environment_limit",
                    "practice and competition environments share one quota; destroy the "
                    "one you no longer need (destroy_environment) then start this one.",
                    status=exc.status,
                    retryable=False,
                    hint="agent_environment_limit",
                ) from exc
            raise

    def wait_ready(
        self,
        ground_id: str,
        challenge_id: str,
        *,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        budget_seconds: float = DEFAULT_POLL_BUDGET,
    ) -> dict:
        """Poll until ``access_ready`` is true, then return the environment payload."""
        deadline = time.monotonic() + budget_seconds
        while True:
            state = self.environment(ground_id, challenge_id)
            if state.get("access_ready"):
                return state
            if time.monotonic() >= deadline:
                raise Ctf2Error(
                    "environment_not_ready",
                    f"no access after {budget_seconds:.0f}s; last status="
                    f"{state.get('status')!r}",
                    retryable=True,
                    retry_after_ms=int(poll_seconds * 1000),
                )
            time.sleep(poll_seconds)

    def extend_environment(self, ground_id: str, challenge_id: str) -> dict:
        return self.client.call(
            "user_post_practice_id_challenges_challengeid_environment_extend",
            path_params={"id": ground_id, "challengeId": challenge_id},
        )

    def destroy_environment(self, ground_id: str, challenge_id: str) -> dict:
        return self.client.call(
            "user_delete_practice_id_challenges_challengeid_environment",
            path_params={"id": ground_id, "challengeId": challenge_id},
        )

    @staticmethod
    def access_urls(state: dict) -> list[str]:
        urls = state.get("access_urls")
        if isinstance(urls, list) and urls:
            return [u if isinstance(u, str) else str(u.get("url", "")) for u in urls if u]
        single = state.get("access_url")
        return [single] if single else []

    @staticmethod
    def endpoints(state: dict) -> list["Endpoint"]:
        """Parse ``access_urls`` into structured connection targets.

        ``access_urls`` only yields strings, which loses two facts a solver needs:

        * ``type`` - ``http`` must be spoken as HTTP, ``tcp`` as a raw stream.
        * ``nc_ssl`` - when true the stream is **TLS-wrapped**. Ignoring this makes a
          perfectly healthy service look dead: the banner is empty, commands get no
          reply, and the peer resets the connection. Every symptom points at "not
          running" while the real cause is "wrong protocol".
        """
        entries = state.get("access_urls")
        targets: list[Endpoint] = []
        if not isinstance(entries, list):
            entries = []
        for entry in entries:
            if isinstance(entry, str):
                entry = {"url": entry}
            if not isinstance(entry, dict):
                continue
            raw = str(entry.get("url") or "")
            kind = str(entry.get("type") or ("http" if raw.startswith("http") else "tcp"))
            host, port = Endpoint.split_host_port(raw)
            targets.append(
                Endpoint(
                    kind=kind,
                    url=raw,
                    host=host,
                    port=port,
                    tls=bool(entry.get("nc_ssl")),
                )
            )
        if not targets:
            single = state.get("access_url")
            if single:
                host, port = Endpoint.split_host_port(str(single))
                targets.append(
                    Endpoint(
                        kind=str(state.get("access_type") or "http"),
                        url=str(single),
                        host=host,
                        port=port,
                        tls=bool(state.get("nc_ssl")),
                    )
                )
        return targets

    # -- submission -------------------------------------------------------------

    def submit(
        self,
        ground_id: str,
        challenge_id: str,
        flag: str,
        *,
        confirmation: bool,
        sub_flag_id: str | None = None,
    ) -> dict:
        """Submit one confirmed practice flag.

        ``confirmation`` must be passed explicitly: it is the code-level expression of
        "a human confirmed this exact value". Suites require the stable ``sub_flag_id``
        from the challenge details (never a display index).
        """
        value = self.client.guard.check_submission(flag, confirmation=confirmation)
        body: dict[str, Any] = {"flag": value, "confirmation": True}
        if sub_flag_id:
            body["sub_flag_id"] = sub_flag_id
        return self.client.call(
            "user_post_practice_id_challenges_challengeid_submit",
            path_params={"id": ground_id, "challengeId": challenge_id},
            body=body,
        )

    # -- replay notes -----------------------------------------------------------

    def note(self, challenge_id: str, kind: str, content: str) -> dict:
        """Record a plan/finding/result note. Flags are refused client-side."""
        if kind not in {"plan", "finding", "result"}:
            raise ValueError("kind must be one of: plan, finding, result")
        text = self.client.guard.check_note(content)
        if len(text) > 2000:
            text = text[:1997] + "..."
        return self.client.call(
            "user_post_agent_notes",
            body={"challenge_id": challenge_id, "kind": kind, "content": text},
        )


# -- helpers -------------------------------------------------------------------


def _as_items(data: Any) -> list[dict]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("items", "results", "challenges", "grounds", "practice"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def _pick_url(data: Any) -> str:
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        for key in ("download_url", "url", "signed_url", "access_url"):
            value = data.get(key)
            if isinstance(value, str) and value:
                return value
        nested = data.get("data")
        if isinstance(nested, dict):
            return _pick_url(nested)
    raise Ctf2Error("attachment_url_missing", f"no URL in response: {data!r}", retryable=False)


def _safe_filename(name: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in str(name)).strip("._")
    return cleaned or "attachment.bin"
