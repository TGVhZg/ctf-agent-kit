"""The operation catalog: a machine-readable map of every CTF2 Open API endpoint.

``spec/operations.json`` is produced by the official CLI (``ctf2 operations``) and is the
single source of truth for method, path, required scope, risk level and idempotency. The
client never hard-codes a URL, so a platform-side rename shows up as one regenerated file
instead of a scattering of 404s.

Regenerate with::

    CTF2_BASE_URL=https://ctf2.dasctf.com ctf2 operations > spec/operations.json

(or ``python -m ctf2arena ops --refresh``, which uses the packaged baseline plus the live
catalog when a token is present).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_PARAM = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

#: Where the packaged catalog lives relative to the repository root.
DEFAULT_CATALOG = Path(__file__).resolve().parent.parent / "spec" / "operations.json"


@dataclass(frozen=True)
class Operation:
    operation_id: str
    method: str
    path: str
    scope: str
    risk_level: str
    idempotency: str
    summary: str = ""

    @property
    def path_params(self) -> list[str]:
        return _PARAM.findall(self.path)

    @property
    def is_write(self) -> bool:
        return self.method.upper() not in {"GET", "HEAD"}

    @property
    def is_agent_only(self) -> bool:
        """True for the 15 operations whose summary says 'Agent credentials only'."""
        return "agent credentials only" in self.summary.lower()


class Catalog:
    """Lookup table over the Open API operations."""

    def __init__(self, operations: list[Operation]) -> None:
        self._by_id = {op.operation_id: op for op in operations}

    @classmethod
    def load(cls, path: Path | str | None = None) -> "Catalog":
        source = Path(path) if path else DEFAULT_CATALOG
        if not source.exists():
            raise FileNotFoundError(
                f"operation catalog not found at {source}. "
                "Regenerate it with `ctf2 operations > spec/operations.json`."
            )
        raw = json.loads(source.read_text(encoding="utf-8"))
        # Tolerate both the bare list from the CLI and a {"data": [...]} envelope.
        if isinstance(raw, dict):
            raw = raw.get("data") or raw.get("operations") or []
        ops = [
            Operation(
                operation_id=item["operation_id"],
                method=item["method"].upper(),
                path=item["path"],
                scope=item.get("scope", ""),
                risk_level=item.get("risk_level", ""),
                idempotency=item.get("idempotency", ""),
                summary=item.get("summary", ""),
            )
            for item in raw
        ]
        if not ops:
            raise ValueError(f"operation catalog at {source} is empty")
        return cls(ops)

    def __len__(self) -> int:
        return len(self._by_id)

    def __iter__(self):
        return iter(sorted(self._by_id.values(), key=lambda o: o.operation_id))

    def get(self, operation_id: str) -> Operation:
        try:
            return self._by_id[operation_id]
        except KeyError:
            close = [oid for oid in self._by_id if operation_id.split("_")[0] in oid][:8]
            suffix = f" Did you mean: {', '.join(close)}?" if close else ""
            raise KeyError(f"unknown operation_id {operation_id!r}.{suffix}") from None

    def agent_operations(self) -> list[Operation]:
        return [op for op in self if op.is_agent_only]

    def build_path(self, operation_id: str, path_params: dict | None = None) -> str:
        """Fill ``{placeholders}`` and verify that nothing required was left unset."""
        op = self.get(operation_id)
        needed = op.path_params
        given = dict(path_params or {})
        missing = [name for name in needed if name not in given]
        if missing:
            raise ValueError(
                f"{operation_id} needs path params {needed}, missing {missing}"
            )
        unknown = [name for name in given if name not in needed]
        if unknown:
            raise ValueError(
                f"{operation_id} has no path param(s) {unknown}; expected {needed or 'none'}"
            )

        def _sub(match: re.Match) -> str:
            # Values are opaque UUIDs; still quote anything path-unsafe.
            from urllib.parse import quote

            return quote(str(given[match.group(1)]), safe="")

        return _PARAM.sub(_sub, op.path)
