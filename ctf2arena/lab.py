"""Interactive TCP/TLS client for service-type challenges.

Written after hand-rolling the same socket boilerplate 36 times across
``plays/``.  The three rules encoded here are the ones that actually cost
time in practice:

1. **Bounded reads.**  A naive ``while True: recv()`` on a chatty service
   will happily pull megabytes into the caller's context.  Every read here
   is capped, and drains stop as soon as the socket goes quiet.
2. **Echo confirmation.**  Menu prompts desynchronise constantly: if you
   read a value after a mis-aligned write you will believe a wrong number
   (a ``price=1024`` that was really ``1234`` once cost a whole round).
   :meth:`ServiceClient.expect_echo` refuses to let you proceed until the
   bytes you sent are seen coming back.
3. **TLS without ceremony.**  Arena tcp endpoints are TLS with a
   certificate that does not match the hostname, so verification is always
   disabled, explicitly, in one place.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass

DEFAULT_TIMEOUT = 8.0
DEFAULT_QUIET = 0.25
DEFAULT_LIMIT = 1 << 20


class ServiceError(RuntimeError):
    """Raised when a service interaction cannot be completed."""


class EchoMismatch(ServiceError):
    """The bytes we sent were not seen coming back; state is untrusted."""


@dataclass(frozen=True)
class Service:
    """Where a challenge service lives."""

    host: str
    port: int
    tls: bool = True

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}"


def service_from_endpoint(endpoint) -> Service:
    """Build a :class:`Service` from ``AgentSession.endpoints`` output."""
    kind = getattr(endpoint, "kind", "tcp")
    if kind != "tcp":
        raise ServiceError(f"endpoint kind {kind!r} is not a raw TCP service")
    return Service(
        host=endpoint.host,
        port=int(endpoint.port),
        tls=bool(getattr(endpoint, "tls", False)),
    )


class ServiceClient:
    """A bounded, echo-checked interactive client."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        tls: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
        limit: int = DEFAULT_LIMIT,
        encoding: str = "latin-1",
    ) -> None:
        self.service = Service(host, port, tls)
        self.encoding = encoding
        self.limit = limit
        self._sock = None
        self._raw = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self._sock = ctx.wrap_socket(self._raw, server_hostname=host)
        else:
            self._sock = self._raw
        self._sock.settimeout(timeout)

    # -- lifecycle ---------------------------------------------------
    def __enter__(self) -> "ServiceClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass
        try:
            self._raw.close()
        except Exception:
            pass

    # -- reading -----------------------------------------------------
    def recv(self, quiet: float = DEFAULT_QUIET, limit: int | None = None) -> bytes:
        """Drain whatever is available, stopping when the peer goes quiet."""
        cap = self.limit if limit is None else min(limit, self.limit)
        out = b""
        time.sleep(quiet)
        self._sock.settimeout(quiet + 0.75)
        while len(out) < cap:
            try:
                chunk = self._sock.recv(4096)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not chunk:
                break
            out += chunk
        return out

    def read_until(self, marker: bytes, timeout: float = 5.0) -> bytes:
        """Read until ``marker`` appears, or raise :class:`ServiceError`."""
        deadline = time.monotonic() + timeout
        out = b""
        self._sock.settimeout(0.5)
        while time.monotonic() < deadline:
            if marker in out:
                return out
            try:
                chunk = self._sock.recv(4096)
            except (socket.timeout, ssl.SSLError, OSError):
                continue
            if not chunk:
                break
            out += chunk
            if len(out) > self.limit:
                break
        if marker not in out:
            raise ServiceError(f"marker {marker!r} not seen within {timeout}s")
        return out

    # -- writing -----------------------------------------------------
    def send(self, data: bytes) -> None:
        self._sock.sendall(data)

    def sendline(self, line: bytes | str) -> None:
        if isinstance(line, str):
            line = line.encode(self.encoding)
        self._sock.sendall(line + b"\n")

    # -- echo confirmation -------------------------------------------
    def expect_echo(
        self,
        line: bytes | str,
        *,
        marker: bytes | None = None,
        quiet: float = DEFAULT_QUIET,
    ) -> bytes:
        """Send ``line`` and require evidence that it was consumed as input.

        ``marker`` defaults to the first 4 bytes of ``line``.  Raises
        :class:`EchoMismatch` when the echo is absent, which means every
        subsequent reading of this session should be treated as garbage.
        """
        if isinstance(line, str):
            line = line.encode(self.encoding)
        self.sendline(line)
        seen = self.recv(quiet)
        needle = marker if marker is not None else line[:4]
        if needle and needle not in seen:
            raise EchoMismatch(
                f"no echo of {needle!r} after sending {line[:32]!r}; "
                f"got {seen[:120]!r}"
            )
        return seen
