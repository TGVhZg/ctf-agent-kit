"""ctf2arena - a policy-guarded client and solve-loop toolkit for the CTF2 Agent Arena.

The package is deliberately dependency-free (Python 3.8+ standard library only) so the
same code runs inside a CTF sandbox, on a laptop, and in CI.

Design rules baked into the code, not just documented:

1. Credentials come from the environment only (``CTF2_TOKEN``). Nothing is ever written
   to disk, and every outbound log line is scrubbed through :mod:`ctf2arena.redact`.
2. The platform's Agent safety rules are enforced as code in :mod:`ctf2arena.policy`,
   so a buggy caller cannot accidentally read writeups, leak a flag into a replay note,
   or submit without an explicit confirmation.
3. Rate limits are respected before the server has to say 429 (see :mod:`ctf2arena.ratelimit`).
"""

from .errors import Ctf2Error, PolicyViolation, RetryableError
from .catalog import Catalog, Operation
from .client import Client
from .session import AgentSession, Challenge

__all__ = [
    "Ctf2Error",
    "PolicyViolation",
    "RetryableError",
    "Catalog",
    "Operation",
    "Client",
    "AgentSession",
    "Challenge",
]

__version__ = "0.1.0"
