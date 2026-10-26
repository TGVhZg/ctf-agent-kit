# ctf2arena

**A policy-guarded client and self-improving solve loop for the CTF² Agent Arena.**

`ctf2arena` connects an autonomous agent to the [CTF²](https://ctf2.dasctf.com) Agent Arena
through the platform's official Open API, plays practice challenges (and competitions, when
the owner allows them), and — this is the part that matters — turns every attempt into
either a reusable skill or a recorded failure, so the next challenge of the same shape is
cheaper than the last.

It is dependency-free (Python 3.8+ standard library only), so it runs unchanged inside a CTF
sandbox, on a laptop, and in CI.

```
find ──► read ──► fetch ──► solve ──► verify ──► submit ──► note
              │                                        │
              └──────── triage: which skill? ◄─────────┘
                              │
                    success ──┴── failure
                        │            │
                   skill draft   retro entry
```

---

## Why this exists

The Arena publishes a complete, agent-native surface: 60 Open API operations, a 60-tool MCP
server, and an official `ctf2-platform` skill with a written play protocol. What it does
*not* ship is the layer an agent needs to do this repeatedly without drifting:

| Gap | What `ctf2arena` does |
| --- | --- |
| Nothing stops a caller from reading other people's writeups | `policy.Guard` refuses those scopes before the request is sent |
| Nothing stops a flag from being pasted into a published replay note | `policy.Guard.check_note` fails closed on flag-shaped text |
| Retrying a non-retryable error burns read/write quota | `errors.RETRYABLE_CODES` mirrors the official recovery table; writes are never blind-retried |
| 429s are discovered the hard way | local token bucket, tuned below the published 120 reads / 30 writes per minute |
| Which of ~130 skills applies? | `triage` scores category + statement signals against a curated route table |
| Memory dies with the session | `evolution.Ledger` is an append-only JSONL of attempts, mined by `build_retro` |
| Writeups get written inconsistently, or not at all | `writeup.Writeup` renders the same section skeleton every time, including a mandatory self-verification section |

---

## Install

```bash
git clone <this repo> && cd buuctfagent
python -m unittest discover -s tests      # 66 offline tests, no network, no token
```

No `pip install` is required. Optionally:

```bash
pip install -e .        # provides the `ctf2arena` console script
```

---

## Credentials

The Agent token comes from the **environment only**:

```bash
# Linux / macOS
export CTF2_TOKEN='...'
# Windows PowerShell
$env:CTF2_TOKEN = '...'
```

There is deliberately **no `--token` flag** and no config file. A token on the command line
lands in shell history and `ps`; a token in a file lands in a backup. `redact.Redactor`
scrubs the live token from every trace line as a second line of defence.

### Getting an Agent token

1. Sign in at <https://ctf2.dasctf.com> and open **Dashboard → Agent Arena**.
2. Create an Agent (this is the identity that will hold the score — results go on the
   *Agent* leaderboard, never on your human account).
3. Generate an API token / PAT for that Agent, scoped to what you need
   (`agent:read`, `agent:trace`, `practice:read`, `practice:submit`,
   `environment:read`, `environment:write`).
4. To play competitions, flip **allow competitions** for this Agent in the arena console.

Read-only scopes first. Add `*:write` / `*:submit` only when you mean it.

---

## Quickstart

```bash
# who am I, what are my quotas
python -m ctf2arena whoami

# what should I work on next
python -m ctf2arena next --limit 5

# browse a practice ground
python -m ctf2arena grounds
python -m ctf2arena challenges <ground_id>

# read a statement; prints the recommended skills and attachment ids
python -m ctf2arena read <ground_id> <challenge_id>

# pull an attachment (signed URL lives 5 minutes, so it is fetched immediately)
python -m ctf2arena fetch <ground_id> <challenge_id> <file_id> --out plays/<name>

# environments
python -m ctf2arena env start <ground_id> <challenge_id> --yes
python -m ctf2arena env wait  <ground_id> <challenge_id>

# submit (requires --yes on top of the API's own confirmation field)
python -m ctf2arena submit <ground_id> <challenge_id> 'flag{...}' --yes

# replay notes (flags are refused client-side)
python -m ctf2arena note <challenge_id> finding "patched the checker, inverted TEA rounds"

# learn from the run
python -m ctf2arena attempt --id <challenge_id> --category reverse --result solved \
  --minutes 23 --route ctf-rev-tea-family-identification
python -m ctf2arena retro
```

Offline commands need no credential at all: `ops`, `triage`, `writeup`, `retro`, `attempt`.

```bash
python -m ctf2arena ops --agent-only
python -m ctf2arena triage --category crypto --text "truncated LCG outputs >> 256"
```

---

## Library use

```python
from ctf2arena import AgentSession, Client
from ctf2arena.policy import Guard

session = AgentSession(Client(guard=Guard(allow_competition=False)))

if not (me := session.whoami()):
    raise SystemExit("no identity")

challenge = session.next_challenges(limit=1, category="reverse")[0]
detail = session.get_challenge(challenge.practice_ground_id, challenge.id)

if detail.get("has_container"):
    session.start_environment(challenge.practice_ground_id, challenge.id)
    state = session.wait_ready(challenge.practice_ground_id, challenge.id)
    print(AgentSession.access_urls(state))

# ... solve it ...

session.submit(
    challenge.practice_ground_id, challenge.id, "flag{...}", confirmation=True
)
session.note(challenge.id, "finding", "the checker is TEA with a mutated delta")
```

---

## Architecture

| Module | Responsibility |
| --- | --- |
| `catalog` | Loads `spec/operations.json` (generated by the official CLI) and turns operation ids into URLs. No URL is hard-coded in the client. |
| `client` | HTTP, auth header, quota, retry policy, `{"success":…}` unwrapping, typed errors. |
| `errors` | `Ctf2Error` with `retryable` / `auth_fatal` / `scope_forbidden`, derived from the official recovery table. |
| `ratelimit` | Token buckets for the 120/30 per-minute Agent quotas, with headroom. |
| `policy` | The platform's Agent safety rules expressed as code: no writeup/community surfaces, no flag in a note, no unconfirmed submit, no admin routes, no competitions unless enabled. |
| `redact` | Scrubs tokens and detects flag-shaped text. |
| `session` | The play loop as methods: discovery, attachments, environments, submission, notes. |
| `triage` | Category + statement signals → ordered list of skills to load. |
| `writeup` | Structured writeup renderer (same skeleton every time, self-verification mandatory). |
| `evolution` | Append-only attempt ledger, aggregation into a retro, and skill-draft scaffolding that validates against the local skill conventions. |
| `qr` | Pure-Python QR decoder (versions 1-10). No zbar, no OpenCV. Brute-forces mask and EC level and uses "parses successfully" as the oracle. |
| `aes` | Pure-Python AES-128, ECB/CBC encrypt+decrypt, PKCS#7 helpers. Verified against FIPS-197. |
| `des` | Pure-Python DES/3DES ECB. Verified against the classic `133457799BBCDFF1` vector. |
| `serpent` | Pure-Python Serpent ECB. Verified against the NESSIE Serpent-128 vector. |
| `cli` | `python -m ctf2arena <command>`. |

`spec/` holds the machine-readable contract:

* `operations.json` — all 60 operations with method, path, scope, risk level, idempotency
  (15 of them Agent-only).
* `openapi-user.json` — the platform's published OpenAPI 3.1 document.

Regenerate the catalog when the platform changes:

```bash
ctf2 operations > spec/operations.json
```

---

## Compliance and scope

This project operates **only** inside the authorised arena, with the caller's own
credential, against the caller's own challenge environment.

Encoded in `policy.py`:

* writeups, community feeds, support tickets, private practice and all `/admin/` routes are
  refused — these are closed to Agents by the play guide;
* a flag-shaped string is refused in a replay note (notes are visible to the owner and may
  be published);
* flag submission requires an explicit `confirmation=True` *and* a `--yes` on the CLI;
* competition operations are refused unless `Guard(allow_competition=True)`, which should
  only be set after the owner has enabled competitions.

Not enforceable by predicate, and therefore stated rather than coded:

* do not brute-force or guess flags;
* do not scan hosts other than the environment returned for your current challenge;
* do not attack the platform or other players;
* never share flags between Agents or people.

The platform's own rules win over this README, always.

---

## Bundled solving assets

The Arena sits behind a sandbox that has no `pycryptodome`, no `cryptography`, no `zbar`,
no `cv2`. Challenges still hand you AES ciphertext and QR images, so four decoders ship in
the package rather than assuming a toolchain that is not there:

| Module | Why it exists | Self-check |
| --- | --- | --- |
| `qr` | A QR image with no decoder available. Brute-forces the 8 masks x 4 EC levels and accepts the one that parses; also validates all three finder patterns to locate the module grid, so a resized render (non-integer pixels per module) still works. | Structural invariant: for every version, all four EC levels must yield the same total codeword count. |
| `aes` | 48 bytes of ciphertext and a password hint. | FIPS-197 Appendix C.1 vector. |
| `des` | 48 bytes = six DES blocks and an 8-byte password. | `133457799BBCDFF1` test vector. |
| `serpent` | 48 bytes = three 16-byte blocks, and the challenge was *titled* with the cipher's name. | NESSIE Serpent-128 vector `264E5481EFF42A4606ABDA06C0BFDA3D`. |

Each begins with a vector-based self-test that runs before any output is interpreted. That
ordering matters: a crypto implementation without a KAT will happily produce plausible
garbage, and a wrong key or a typo in a table then looks like "the algorithm is wrong".

---

## Testing

```bash
python -m unittest discover -s tests -v
```

66 tests, all offline. They cover the parts that are easy to get subtly wrong: URL
templating against the real catalog, the `retryable` classification, flag detection,
note/submission guards, retro aggregation, and skill-draft frontmatter validity (a draft
whose `name` has uppercase or whose `description` contains a raw `": "` would be *silently*
dropped by the loader — `SkillDraft.validate` catches that before promotion).

---

## Roadmap

- [ ] MCP transport as an alternative to the Open API, for hosts that prefer it
- [ ] `solve` subcommand that drives a local sandbox from a challenge workspace
- [ ] Retro-driven route weighting fed back into `triage`
- [ ] Published replay templates for the common categories

---

## License

MIT. See `LICENSE`.

CTF² and the Agent Arena are operated by DASCTF; this is an independent client and is not
affiliated with the platform.
