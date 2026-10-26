"""Generate a structured, submission-grade writeup from a solve record.

The output shape follows the house style already used in this skill library: a one-line
conclusion, a "how to recognise this class of challenge" section, the ordered break-through
steps, an explicit self-verification section, the pitfalls that were actually hit, and a
reproduction recipe. The two sections that make a writeup *useful* six months later are
``## 自证`` (what proved the answer, not just what produced it) and ``## 踩坑``
(where the first three attempts died).

Writeups are local artefacts. They contain flags, so ``writeups/`` is git-ignored by
default; publishing one is a deliberate act.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Step:
    title: str
    detail: str = ""
    code: str = ""
    lang: str = ""


@dataclass
class Writeup:
    title: str
    challenge_name: str = ""
    challenge_id: str = ""
    platform: str = "CTF2 Agent Arena"
    category: str = ""
    difficulty: str = ""
    points: int | None = None
    agent: str = ""
    date: str = field(default_factory=lambda: _dt.date.today().isoformat())
    flag: str = ""
    conclusion: str = ""
    recognise: list[str] = field(default_factory=list)
    recon: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    verification: list[str] = field(default_factory=list)
    pitfalls: list[str] = field(default_factory=list)
    reproduction: list[str] = field(default_factory=list)
    skills: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)

    # -- rendering ---------------------------------------------------------------

    def render(self) -> str:
        lines: list[str] = []
        lines.append(f"# {self.title or self.challenge_name or 'CTF writeup'}")
        lines.append("")
        if self.conclusion:
            lines.append(f"> {self.conclusion}")
            lines.append("")

        meta = [
            ("平台", self.platform),
            ("题目", self.challenge_name),
            ("题目 ID", self.challenge_id),
            ("分类", self.category),
            ("难度", self.difficulty),
            ("分值", str(self.points) if self.points is not None else ""),
            ("Agent", self.agent),
            ("日期", self.date),
        ]
        rows = [(k, v) for k, v in meta if v]
        if rows:
            lines.append("| 项 | 值 |")
            lines.append("| --- | --- |")
            for key, value in rows:
                lines.append(f"| {key} | {_cell(value)} |")
            lines.append("")

        self._section(lines, "题目概览", self.recognise)
        self._section(lines, "侦察与信息收集", self.recon)

        if self.steps:
            lines.append("## 解题路径")
            lines.append("")
            for index, step in enumerate(self.steps, 1):
                lines.append(f"### {index}. {step.title}")
                lines.append("")
                if step.detail:
                    lines.append(step.detail)
                    lines.append("")
                if step.code:
                    lines.append(f"```{step.lang}".rstrip())
                    lines.append(step.code.rstrip())
                    lines.append("```")
                    lines.append("")

        self._section(lines, "自证", self.verification)

        if self.flag:
            lines.append("## Flag")
            lines.append("")
            lines.append("```")
            lines.append(self.flag)
            lines.append("```")
            lines.append("")

        if self.pitfalls:
            lines.append("## 踩坑")
            lines.append("")
            for index, pit in enumerate(self.pitfalls, 1):
                lines.append(f"{index}. {pit}")
            lines.append("")

        self._section(lines, "复现", self.reproduction)
        self._section(lines, "相关技能", [f"- `{s}`" for s in self.skills])

        if self.artifacts:
            lines.append("## 产物")
            lines.append("")
            for item in self.artifacts:
                lines.append(f"- `{item}`")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _section(lines: list[str], heading: str, items: list[str]) -> None:
        if not items:
            return
        lines.append(f"## {heading}")
        lines.append("")
        for item in items:
            lines.append(item if item.startswith(("- ", "1.", "##", "|")) else f"- {item}")
        lines.append("")

    # -- persistence -------------------------------------------------------------

    def save(self, directory: str | Path, filename: str | None = None) -> Path:
        out_dir = Path(directory)
        out_dir.mkdir(parents=True, exist_ok=True)
        name = filename or f"{_slug(self.challenge_name or self.title or 'writeup')}.md"
        target = out_dir / name
        target.write_text(self.render(), encoding="utf-8")
        return target


def _cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _slug(text: str) -> str:
    keep = [c if (c.isalnum() or c in "-_") else "-" for c in str(text).strip().lower()]
    slug = "".join(keep).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "writeup"
