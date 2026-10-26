"""The self-improvement loop: record attempts, mine them, draft skills.

The brief for this project was "solve, then get better at solving". That needs a memory
that survives the session, because the interesting signal is not a single solve - it is the
*second* time the same shape of challenge appears.

Three artefacts, in increasing order of commitment:

``memory/attempts.jsonl``
    Append-only ledger. One JSON object per (challenge, attempt): what was tried, which
    route was recommended, whether it worked, and how long it took. Cheap to write, so it
    is always written.

``retro`` (in-memory / printed)
    Aggregations over the ledger: win rate per category, which routes actually convert,
    and the recurring blockers. This is the thing that should change behaviour - if
    ``pyjail`` routes are 0/5, stop leading with them.

``skill draft``
    When a route produces a *new* reusable pattern, emit a scaffold conforming to the local
    skill conventions (``name`` matching ``^[a-z0-9]+(-[a-z0-9]+)*$``, block-scalar
    ``description`` with the trigger words inside the first 500 normalised characters, and
    the mandatory ``harness.py`` / ``skillcheck.py`` / ``solve_local.py`` files for anything
    that carries code). The draft is written to ``skill_drafts/`` - never straight into the
    live skill library, because an unreviewed skill silently degrades routing.
"""

from __future__ import annotations

import json
import re
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

LEDGER_NAME = "attempts.jsonl"
_SKILL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_RESULT_VALUES = {"solved", "failed", "abandoned", "partial"}


@dataclass
class Attempt:
    """One try at one challenge."""

    challenge_id: str
    challenge_name: str = ""
    category: str = ""
    difficulty: str = ""
    route: list[str] = field(default_factory=list)
    result: str = "failed"
    minutes: float | None = None
    blocker: str = ""
    technique: str = ""
    notes: str = ""
    at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def __post_init__(self) -> None:
        if self.result not in _RESULT_VALUES:
            raise ValueError(f"result must be one of {sorted(_RESULT_VALUES)}")

    @property
    def solved(self) -> bool:
        return self.result == "solved"


class Ledger:
    """Append-only JSONL store of attempts."""

    def __init__(self, root: str | Path = "memory") -> None:
        self.root = Path(root)
        self.path = self.root / LEDGER_NAME

    def append(self, attempt: Attempt) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(attempt), ensure_ascii=False) + "\n")
        return self.path

    def load(self) -> list[Attempt]:
        if not self.path.exists():
            return []
        out: list[Attempt] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(Attempt(**json.loads(line)))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue  # a torn line must not poison the whole history
        return out


@dataclass
class Retro:
    total: int = 0
    solved: int = 0
    by_category: dict = field(default_factory=dict)
    blockers: list[tuple[str, int]] = field(default_factory=list)
    routes_that_convert: list[tuple[str, float, int]] = field(default_factory=list)
    median_minutes: float | None = None

    @property
    def win_rate(self) -> float:
        return 0.0 if not self.total else self.solved / self.total

    def render(self) -> str:
        lines = ["# 复盘", ""]
        lines.append(f"- 总尝试 {self.total}，已解 {self.solved}，胜率 {self.win_rate:.0%}")
        if self.median_minutes is not None:
            lines.append(f"- 中位耗时 {self.median_minutes:.0f} 分钟")
        if self.by_category:
            lines.append("")
            lines.append("| 分类 | 解出/尝试 | 胜率 |")
            lines.append("| --- | --- | --- |")
            for cat, (solved, total) in sorted(self.by_category.items()):
                rate = solved / total if total else 0.0
                lines.append(f"| {cat or '(none)'} | {solved}/{total} | {rate:.0%} |")
        if self.routes_that_convert:
            lines.append("")
            lines.append("## 真正能转化的路由")
            lines.append("")
            for skill, rate, n in self.routes_that_convert:
                lines.append(f"- `{skill}` — {rate:.0%} (n={n})")
        if self.blockers:
            lines.append("")
            lines.append("## 反复卡点")
            lines.append("")
            for blocker, count in self.blockers:
                lines.append(f"- {blocker} ×{count}")
        if not self.total:
            lines.append("")
            lines.append("_尚无记录。先跑几道题再复盘。_")
        return "\n".join(lines) + "\n"


def build_retro(attempts: list[Attempt]) -> Retro:
    """Aggregate the ledger into something that can actually change a decision."""
    retro = Retro(total=len(attempts), solved=sum(1 for a in attempts if a.solved))
    if not attempts:
        return retro

    per_cat: dict[str, list[int]] = {}
    blocker_counts: dict[str, int] = {}
    route_hits: dict[str, list[int]] = {}
    durations: list[float] = []

    for attempt in attempts:
        cat = attempt.category or "(uncategorised)"
        bucket = per_cat.setdefault(cat, [0, 0])
        bucket[1] += 1
        if attempt.solved:
            bucket[0] += 1
        else:
            for blocker in _blocker_tags(attempt.blocker):
                blocker_counts[blocker] = blocker_counts.get(blocker, 0) + 1
        for skill in attempt.route[:1]:  # credit the leading route only
            hits = route_hits.setdefault(skill, [0, 0])
            hits[1] += 1
            if attempt.solved:
                hits[0] += 1
        if attempt.minutes:
            durations.append(float(attempt.minutes))

    retro.by_category = {k: (v[0], v[1]) for k, v in per_cat.items()}
    retro.blockers = sorted(blocker_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    retro.routes_that_convert = sorted(
        ((skill, solved / total, total) for skill, (solved, total) in route_hits.items() if total >= 2),
        key=lambda item: (-item[1], -item[2]),
    )[:10]
    if durations:
        retro.median_minutes = statistics.median(durations)
    return retro


def _blocker_tags(blocker: str) -> list[str]:
    """Split a free-text blocker into coarse tags so counts actually aggregate."""
    if not blocker:
        return ["(unrecorded)"]
    text = blocker.lower()
    tags = []
    for needle, tag in (
        ("python", "python/tooling"),
        ("module", "python/tooling"),
        ("install", "python/tooling"),
        ("network", "network"),
        ("timeout", "network"),
        ("闸机", "environment"),
        ("environment", "environment"),
        ("脱壳", "unpacking"),
        ("unpack", "unpacking"),
        ("time", "ran-out-of-time"),
        ("时间", "ran-out-of-time"),
        ("scope", "platform/scope"),
        ("scope", "platform/scope"),
    ):
        if needle in text and tag not in tags:
            tags.append(tag)
    return tags or [blocker.strip()[:60]]


# -- skill drafting ------------------------------------------------------------


@dataclass
class SkillDraft:
    name: str
    title: str
    description: str
    triggers: list[str]
    core: list[str]
    pitfalls: list[str] = field(default_factory=list)
    related: list[str] = field(default_factory=list)

    def validate(self) -> list[str]:
        """Return convention violations; an empty list means safe to promote."""
        problems = []
        if not _SKILL_NAME.match(self.name):
            problems.append(
                f"name {self.name!r} must match ^[a-z0-9]+(-[a-z0-9]+)*$ "
                "(lowercase, single hyphens)"
            )
        normalised = " ".join(self.description.split())
        if ": " in normalised:
            problems.append(
                "description contains a raw ': ' sequence, which makes the loader drop the "
                "skill silently; use a block scalar and avoid colon-space"
            )
        trigger_end = normalised.find("核心") if "核心" in normalised else len(normalised)
        if trigger_end > 500:
            problems.append(
                f"trigger words end at char {trigger_end}, beyond the 500-char catalog "
                "window; move them to the front"
            )
        return problems

    def render(self) -> str:
        desc = " ".join(
            [
                self.title.rstrip("。"),
                "触发词——" + "、".join(self.triggers) + "。",
                "核心：" + " ".join(self.core),
            ]
        )
        lines = [
            "---",
            f"name: {self.name}",
            "description: >",
        ]
        for chunk in _wrap(desc, 96):
            lines.append(f"  {chunk}")
        lines.append("agent_created: true")
        lines.append("---")
        lines.append("")
        lines.append(f"# {self.title}")
        lines.append("")
        lines.append("## 适用场景")
        lines.append("")
        lines.append("_待补：用一段原版代码片段或题面特征，把判据写具体（函数名/常量/位宽）。_")
        lines.append("")
        lines.append("## 破局步骤")
        lines.append("")
        for index, item in enumerate(self.core, 1):
            lines.append(f"{index}. {item}")
        lines.append("")
        lines.append("## 自证")
        lines.append("")
        lines.append("_待补：真实跑出来的输出（含 flag 形态），证明这条路过。_")
        lines.append("")
        lines.append("## 坑")
        lines.append("")
        if self.pitfalls:
            for index, item in enumerate(self.pitfalls, 1):
                lines.append(f"{index}. {item}")
        else:
            lines.append("_待补：写自己真踩过的。_")
        lines.append("")
        lines.append("## 相关技能")
        lines.append("")
        for item in self.related or ["_待补_"]:
            lines.append(f"- `{item}`" if not item.startswith("_") else item)
        lines.append("")
        return "\n".join(lines)

    def save(self, directory: str | Path = "skill_drafts") -> Path:
        problems = self.validate()
        if problems:
            raise ValueError("draft violates skill conventions:\n- " + "\n- ".join(problems))
        out = Path(directory) / self.name
        out.mkdir(parents=True, exist_ok=True)
        target = out / "SKILL.md"
        target.write_text(self.render(), encoding="utf-8")
        return target


def _wrap(text: str, width: int) -> list[str]:
    words = text.split(" ")
    lines, current = [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]
