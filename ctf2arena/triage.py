"""Route a challenge to the right specialised skill before reading the binary.

We already own ~130 ``ctf-*`` skills. The failure mode when solving a lot of challenges is
not "no skill exists" - it is picking the wrong one and burning an hour going down a path
that a sibling skill already documents as a dead end.

This module is a small, deliberately boring rule table: a challenge's declared category
plus a few text signals from its title/description map to an ordered list of skills to
load, most-specific first. It does not try to be an LLM. When nothing matches, it returns
:data:`GENERIC` so the caller falls back to the dispatcher skill.

Keep this table honest: every entry should name a skill that actually exists, and the
``signals`` should be literal substrings likely to appear in a real statement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

GENERIC = ["solve-challenge"]


@dataclass(frozen=True)
class Route:
    skill: str
    categories: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()
    why: str = ""
    weight: int = 1  # higher wins ties

    def score(self, category: str, haystack: str) -> int:
        """Score this route against a challenge.

        The rule that matters: a *specific* skill (one with ``signals``) must justify
        itself with at least one concrete signal match. Matching the declared category
        alone is not evidence - an "Easy CRYPTO" statement says nothing about truncated
        LCGs, so letting the category alone nominate ``ctf-coppersmith-*`` produced
        confidently wrong advice on trivial ROT13 challenges.

        Generic skills (no signals) exist precisely to catch the category-only case, and
        they rank below any specific route that actually matched.
        """
        hits = sum(self.weight for signal in self.signals if signal.lower() in haystack)
        cat_match = bool(category) and category.lower() in self.categories
        if self.signals:
            return 0 if hits == 0 else hits * 2 + (1 if cat_match else 0)
        return 1 if cat_match else 0


#: Ordered table. Specific beats generic: a "custom VM" reverse challenge should land on
#: the VM skill, not on plain ctf-reverse.
ROUTES: tuple[Route, ...] = (
    # --- pyjail family (very high value: each variant needs a different escape) -----
    Route("pyjail-register-vm-shortattr-1arg", ("misc", "jail"),
          ("registers", "寄存器", "attr too long", "get <src>"), weight=3),
    Route("pyjail-match-stmt-framebuiltins-rce", ("misc", "jail"),
          ("match", "revenge_jail", "ast.Call"), weight=2),
    Route("pyjail-noassign-giframe-builtins", ("misc", "jail"),
          ("undefined", "can't define", "namedexpr"), weight=2),
    Route("pyjail-dense-whitespace-bypass", ("misc", "jail"),
          ("density", "whitespace", "空白", "sparse"), weight=2),
    Route("pyjail-only-open-file-leak", ("misc", "jail"),
          ("only open", "only_open"), weight=3),
    Route("pyjail-eval-noparen-call-gadget", ("misc", "jail"),
          ("no parentheses", "禁括号", "no paren"), weight=2),
    Route("pyjail-nfkc-bypass", ("misc", "jail"),
          ("no alphanumeric", "字母数字", "全角", "dunder"), weight=2),
    Route("pyjail-primitives", ("misc", "jail"), ("pyjail", "jail", "沙箱"), weight=1),
    # --- misc / forensics ----------------------------------------------------------
    Route("ctf-usb-hid-keyboard-pcapng", ("misc", "forensics"),
          ("usb", "hid", "键盘流量", "usbmon"), weight=3),
    Route("ctf-audio-morse-ctc-corevalues", ("misc", "forensics"),
          ("morse", "摩斯", "电报", "wav", "电台"), weight=3),
    Route("ctf-hajimi-zerowidth-multilayer", ("misc",),
          ("零宽", "zero-width", "哈基米", "hachimi"), weight=3),
    Route("ctf-rev-media-pixel-bitplane-payload", ("misc", "reverse"),
          ("video.mp4", "像素", "bitplane", "色块"), weight=2),
    Route("ctf-misc-polyglot-carve", ("misc",),
          ("打不开", "双拼", "polyglot", "假扩展名"), weight=2),
    Route("ctf-numeric-pixel-art-two-axis", ("misc",),
          ("像素画", "坐标轴", "方格"), weight=3),
    Route("qr-repair-ctf", ("misc", "reverse"),
          ("二维码", "qr", "扫码"), weight=2),
    # --- reverse -------------------------------------------------------------------
    Route("ctf-rev-unicorn-oracle-extraction", ("reverse",),
          ("unicorn", "预言机", "oracle", "置换表"), weight=2),
    Route("ctf-rev-stored-table-byte-transform-inversion", ("reverse",),
          ("memcmp", "常量表", "base64", "字母表"), weight=1),
    Route("ctf-rev-tea-family-identification", ("reverse",),
          ("tea", "xtea", "xxtea", "delta", "0x9e3779b9"), weight=3),
    Route("ctf-rev-pyc-magic-version-and-dead-check", ("reverse",),
          ("pyc", "marshal", "magic number"), weight=3),
    Route("ctf-rev-pyinstaller-and-upx-unpack", ("reverse",),
          ("pyinstaller", "upx", "打包"), weight=3),
    Route("ctf-rev-dotnet-cil-managed-assembly", ("reverse",),
          ("mscoree", "_CorExeMain", ".net", "cil"), weight=3),
    Route("ctf-rev-mingw-coff-symbols-and-fingerprints", ("reverse",),
          ("mingw", "coff", "gcc"), weight=2),
    Route("ctf-rev-msvc-symbolless-pdata-rtcs", ("reverse",),
          ("msvc", "pdata", "没有 pdb"), weight=2),
    Route("ctf-rev-flower-junk-code-linear-sweep", ("reverse",),
          ("花指令", "junk", "flower"), weight=3),
    Route("ctf-rev-windows-veh-ollvm-and-runtime-dump", ("reverse",),
          ("veh", "ollvm", "平坦化"), weight=3),
    Route("ctf-rev-ctor-failing-state-machine-blocks-checker", ("reverse",),
          ("sorry", "sorry，", "构造函数", "ctor"), weight=2),
    Route("ctf-rev-iat-hijack-tls-callback-decoy", ("reverse",),
          ("tls 回调", "tls callback", "iat"), weight=3),
    Route("ctf-rev-flag-in-memory-crt-init-and-decoy-imports", ("reverse",),
          ("不打印", "内存里", "dump flag"), weight=2),
    Route("ctf-rev-bigint-recursion-mod-dp", ("reverse",),
          ("大整数", "bigint", "递归"), weight=2),
    Route("ctf-rev-prime-chain-one-way-inversion", ("reverse",),
          ("素数链", "prime chain"), weight=3),
    Route("ctf-rev-clock-constraint-fake-time-injection", ("reverse",),
          ("系统时间", "current time", "qtime"), weight=3),
    Route("ctf-gamevm-bfs-tile-economy", ("reverse",),
          ("游戏", "走格子", "bfs", "商店"), weight=3),
    Route("ctf-vmpwn-signed-index-oob-ret2win", ("pwn",),
          ("vm", "字节码", "opcode", "解释器"), weight=2),
    Route("ctf-android-native-checkflag-tweaked-crypto", ("reverse", "mobile"),
          ("apk", "loadlibrary", "jni"), weight=2),
    Route("ctf-apk-custom-packer-native-checkflag", ("reverse", "mobile"),
          ("加固", "stubapplication", "libloader"), weight=3),
    Route("ctf-rev-dex-java-checkflag-dalvik-vm", ("reverse", "mobile"),
          ("classes.dex", "dalvik", "smali"), weight=2),
    Route("renpy-rpyc-rpyb-reverse", ("reverse",), ("ren'py", "rpyc", "galgame"), weight=3),
    Route("go-pe-pclntab-static-reverse", ("reverse",),
          ("golang", "pclntab", "go build"), weight=3),
    Route("java-exe4j-launcher-jar-extract-and-vm", ("reverse",),
          ("exe4j", "install4j", "jvav"), weight=3),
    # --- pwn -----------------------------------------------------------------------
    Route("ctf-8byte-shellcode-preset-regs", ("pwn",),
          ("8 bytes", "only 8", "极短 shellcode"), weight=3),
    Route("ctf-srop-shadowstack-sigreturn-rounds", ("pwn",),
          ("shadow stack", "影子栈", "sigreturn", "seccomp"), weight=3),
    Route("ctf-pwn-freelist-arbwrite-stackpivot", ("pwn",),
          ("freelist", "任意地址写", "stack pivot"), weight=3),
    Route("glibc-fsop-house-of-apple2-uaf", ("pwn",),
          ("uaf", "glibc 2.3", "__free_hook"), weight=2),
    Route("pwn-fake-canary-selfmatch-rop", ("pwn",),
          ("canary", "blindrop"), weight=2),
    Route("ctf-hexagon-qdsp6-rop-syscall-chain", ("pwn",),
          ("hexagon", "qdsp6"), weight=3),
    Route("ctf-v8-wasm-gc-extern-externalize-pwn", ("pwn",),
          ("d8", "v8", "wasm"), weight=3),
    # --- web -----------------------------------------------------------------------
    Route("web-http-request-smuggling", ("web",),
          ("smuggling", "走私", "transfer-encoding"), weight=3),
    Route("php-unserialize-pop-gitleak", ("web",),
          (".git", "unserialize", "pop 链"), weight=3),
    Route("ssrf-gopher-honeypot-bypass", ("web",),
          ("ssrf", "gopher", "蜜罐"), weight=3),
    Route("web-prototype-pollution-dotpath", ("web",),
          ("prototype pollution", "原型链", "__proto__"), weight=3),
    Route("flask-ssti-config-session-forge", ("web",),
          ("ssti", "render_template_string", "secret_key"), weight=2),
    Route("java-zipslip-spi-plugin-rce", ("web",),
          ("zip slip", "serviceloader", "在线解压"), weight=3),
    Route("java-fastjson-templatesimpl-requestcontext-echo", ("web",),
          ("fastjson", "@type"), weight=3),
    Route("ctf-vite-hmr-fetchmodule-fileread", ("web",),
          ("vite", "hmr", "fetchmodule"), weight=3),
    Route("web-upload-recon-easteregg", ("web",),
          ("上传", "upload", "彩蛋"), weight=2),
    Route("ctf-memory-game-cell-oracle", ("web",),
          ("记忆", "memory game", "翻牌"), weight=3),
    Route("ctf-web-adminbot-chromedriver-root-read", ("web",),
          ("admin bot", "chromedriver", "xss"), weight=2),
    # --- crypto --------------------------------------------------------------------
    Route("ctf-mldsa-noise-leak-forge", ("crypto",),
          ("dilithium", "ml-dsa", "leaky"), weight=3),
    Route("ctf-coppersmith-highbits-truncated-lcg", ("crypto",),
          ("coppersmith", "高位", "partial key"), weight=3),
    Route("ctf-crypto-williams-p1-lucas-factoring", ("crypto",),
          ("p+1", "williams", "光滑"), weight=3),
    Route("moepoly-truncated-lcg-coef-recovery", ("crypto",),
          ("moePoly", "截断 lcg", "truncated lcg"), weight=3),
    Route("mt19937-randbytes-iv-key-recovery", ("crypto",),
          ("mt19937", "randbytes", "iv="), weight=3),
    Route("lfsr-combiner-bitslice-filter", ("crypto",),
          ("lfsr", "组合器", "combiner"), weight=3),
    Route("ctf-rps-rsa-commitment-r-leak", ("crypto",),
          ("石头剪刀布", "commitment"), weight=3),
    Route("ctf-rev-oracle-affine-bytewise-sbox-mitm", ("crypto", "reverse"),
          ("oracle", "mitm", "sbox"), weight=2),
    Route("ctf-rag-cosine-score-vector-leak", ("crypto", "ai"),
          ("rag", "余弦", "检索"), weight=3),
    Route("ctf-ai-backdoor-pickle-tfidf", ("ai",),
          ("backdoor", "后门", "pickle"), weight=3),
    Route("ctf-gguf-chat-template-ssti-rce", ("ai",),
          ("gguf", "chat_template"), weight=3),
    Route("llm-ctf-prompt-injection-playbook", ("ai",),
          ("提示词注入", "prompt injection", "jailbreak"), weight=2),
    # --- generic fallbacks (lowest weight, still useful) ---------------------------
    Route("ctf-reverse", ("reverse",), (), weight=0),
    Route("ctf-pwn", ("pwn",), (), weight=0),
    Route("ctf-web", ("web",), (), weight=0),
    Route("ctf-crypto", ("crypto",), (), weight=0),
    Route("ctf-misc", ("misc",), (), weight=0),
    Route("ctf-forensics", ("forensics",), (), weight=0),
    Route("ctf-ai-ml", ("ai",), (), weight=0),
    Route("ctf-osint", ("osint",), (), weight=0),
)

_SPLIT = re.compile(r"[\s,;/|]+")


def normalise_category(category: str | None) -> str:
    """Map the platform's category strings onto our short keys."""
    if not category:
        return ""
    text = category.strip().lower()
    table = {
        "re": "reverse",
        "rev": "reverse",
        "逆向": "reverse",
        "pwn": "pwn",
        "web": "web",
        "crypto": "crypto",
        "密码": "crypto",
        "misc": "misc",
        "杂项": "misc",
        "forensics": "forensics",
        "取证": "forensics",
        "ai": "ai",
        "mobile": "mobile",
        "osint": "osint",
        "jail": "jail",
        "pyjail": "jail",
    }
    for key, value in table.items():
        if key in text:
            return value
    return text


@dataclass
class Recommendation:
    category: str
    skills: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.category or 'unknown'} -> {', '.join(self.skills)}"


def recommend(
    category: str | None,
    *text: str,
    limit: int = 3,
) -> Recommendation:
    """Return the ordered skills to load for this challenge.

    *text* should be the title and description; they are concatenated and lower-cased for
    substring matching.
    """
    cat = normalise_category(category)
    haystack = " ".join(t for t in text if t).lower()

    scored: list[tuple[int, int, Route]] = []
    for route in ROUTES:
        score = route.score(cat, haystack)
        if score > 0:
            scored.append((score, route.weight, route))

    # Highest score first; stable on insertion order for ties.
    scored.sort(key=lambda item: (-item[0], -item[1]))
    skills: list[str] = []
    reasons: list[str] = []
    for score, _weight, route in scored:
        if route.skill in skills:
            continue
        skills.append(route.skill)
        reasons.append(f"{route.skill}: matched (score {score})")
        if len(skills) >= limit:
            break

    if not skills:
        skills = list(GENERIC)
        reasons = ["no specific route matched; run the dispatcher first"]

    return Recommendation(category=cat, skills=skills, reasons=reasons)
