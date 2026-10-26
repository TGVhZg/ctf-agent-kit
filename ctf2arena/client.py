"""HTTP client for the CTF2 Open API.

Deliberately thin and dependency-free. Responsibilities, in order:

1. Resolve the credential from the environment (never from argv, never from a file - an
   argv token lands in shell history and ``ps``, a file token lands in a backup).
2. Apply the local token bucket *before* sending, so the server's 429 path is the
   exception rather than the loop.
3. Unwrap ``{"success": true, "data": ...}`` and raise :class:`Ctf2Error` on
   ``{"success": false, "error": {...}}``.
4. Retry only codes the play guide calls retryable, honouring ``Retry-After``.

Every log line goes through a :class:`~ctf2arena.redact.Redactor` built from the live token.
"""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from .catalog import Catalog
from .errors import Ctf2Error
from .policy import Guard
from .ratelimit import Quotas
from .redact import Redactor

DEFAULT_BASE_URL = "https://ctf2.dasctf.com"
TOKEN_ENV = "CTF2_TOKEN"
BASE_URL_ENV = "CTF2_BASE_URL"

_UA = "ctf2arena/0.1 (+https://github.com/) python-urllib"


def resolve_token(explicit: str | None = None) -> str:
    """Return the credential, preferring an explicit argument over the environment.

    An explicit argument is for tests. Interactive use should leave it ``None`` so the
    token stays out of process listings.
    """
    token = (explicit or os.environ.get(TOKEN_ENV) or "").strip()
    if not token:
        raise Ctf2Error(
            "missing_credential",
            f"no API token. Export {TOKEN_ENV}=<agent token> (never commit it).",
            retryable=False,
        )
    return token


class Client:
    """Minimal, rate-limit-aware Open API client."""

    def __init__(
        self,
        token: str | None = None,
        *,
        base_url: str | None = None,
        catalog: Catalog | None = None,
        guard: Guard | None = None,
        quotas: Quotas | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        trace: Callable[[str], None] | None = None,
    ) -> None:
        self._token = resolve_token(token)
        self.base_url = (base_url or os.environ.get(BASE_URL_ENV) or DEFAULT_BASE_URL).rstrip("/")
        self.catalog = catalog or Catalog.load()
        self.guard = guard or Guard()
        self.quotas = quotas or Quotas()
        self.timeout = timeout
        self.max_retries = max_retries
        self.redactor = Redactor([self._token])
        self._trace = trace
        #: Rolling counters, handy for a run summary.
        self.stats = {"reads": 0, "writes": 0, "retries": 0, "errors": 0}

    # -- plumbing ---------------------------------------------------------------

    def _log(self, message: str) -> None:
        if self._trace:
            self._trace(self.redactor.redact(message))

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": _UA,
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        url = f"{self.base_url}{path}"
        if query:
            clean = {k: v for k, v in query.items() if v is not None}
            if clean:
                url = f"{url}?{urllib.parse.urlencode(clean)}"

        data = None
        headers = self._headers()
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        self._log(f"{method} {path}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, dict(response.headers), _decode(response.read())
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            return exc.code, dict(exc.headers or {}), _decode(raw)
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            raise Ctf2Error(
                "network_error",
                f"{type(exc).__name__}: {exc}",
                retryable=True,
                retry_after_ms=1000,
            ) from exc

    # -- public API -------------------------------------------------------------

    def call(
        self,
        operation_id: str,
        *,
        path_params: dict | None = None,
        query: dict | None = None,
        body: dict | None = None,
    ) -> Any:
        """Execute one catalog operation and return its unwrapped ``data``."""
        operation = self.catalog.get(operation_id)
        self.guard.check_operation(operation)
        path = self.catalog.build_path(operation_id, path_params)
        is_write = operation.is_write

        attempt = 0
        while True:
            attempt += 1
            self.quotas.before_request(is_write)
            status, headers, payload = self._request(
                operation.method, path, query=query, body=body
            )
            self.stats["writes" if is_write else "reads"] += 1

            if 200 <= status < 300 and _is_success(payload):
                return _unwrap(payload)

            error = _to_error(status, headers, payload)

            if error.retryable and attempt <= self.max_retries:
                self.stats["retries"] += 1
                delay_ms = error.retry_after_ms or min(2 ** attempt * 500, 8000)
                self._log(f"retrying {operation_id} after {delay_ms}ms ({error.code})")
                if is_write:
                    # Never blind-retry a write that may have been applied.
                    if operation.idempotency != "idempotent":
                        self.stats["errors"] += 1
                        raise error
                self.quotas.defer(is_write, delay_ms / 1000.0)
                time.sleep(delay_ms / 1000.0)
                continue

            self.stats["errors"] += 1
            raise error

    def get_json(self, path: str, query: dict | None = None) -> Any:
        """Escape hatch for a raw GET on an absolute path (used for signed URLs)."""
        status, headers, payload = self._request("GET", path, query=query)
        if not (200 <= status < 300):
            raise _to_error(status, headers, payload)
        return payload


def _decode(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return raw.decode("utf-8", errors="replace")


def _is_success(payload: Any) -> bool:
    if not isinstance(payload, dict) or "success" not in payload:
        return True
    return bool(payload.get("success"))


def _unwrap(payload: Any) -> Any:
    if isinstance(payload, dict) and payload.get("success") is True and "data" in payload:
        return payload["data"]
    return payload


def _to_error(status: int, headers: dict[str, str], payload: Any) -> Ctf2Error:
    retry_after_ms = None
    raw_retry = _header(headers, "retry-after")
    if raw_retry:
        try:
            retry_after_ms = int(float(raw_retry) * 1000)
        except ValueError:
            retry_after_ms = None

    code = f"http_{status}"
    message = ""
    hint = None
    params = None
    if isinstance(payload, dict):
        err = payload.get("error")
        if isinstance(err, dict):
            code = str(err.get("code") or code)
            message = str(err.get("messages") or err.get("message") or err.get("key") or "")
            params = err.get("params")
            hint = err.get("hint")
        elif isinstance(err, str):
            code, message = err, err
        elif isinstance(payload.get("message"), str):
            message = payload["message"]
    elif isinstance(payload, str):
        message = payload[:300]

    if params:
        message = f"{message} {params}".strip()

    return Ctf2Error(
        code,
        message or f"HTTP {status}",
        status=status,
        retry_after_ms=retry_after_ms,
        hint=hint,
        payload=payload if isinstance(payload, dict) else {"raw": message},
        request_id=_header(headers, "x-request-id"),
    )


def _header(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None
