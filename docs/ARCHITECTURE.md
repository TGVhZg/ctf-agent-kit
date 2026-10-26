# Architecture

```
                      ┌──────────────────────────────────────────┐
                      │              ctf2arena.cli               │
                      │  whoami / next / read / fetch / env /    │
                      │  submit / note / triage / retro / writeup│
                      └───────────────┬──────────────────────────┘
                                      │
              ┌───────────────────────┼────────────────────────┐
              ▼                       ▼                        ▼
      ┌───────────────┐      ┌────────────────┐      ┌──────────────────┐
      │ session       │      │ triage         │      │ evolution        │
      │ AgentSession  │      │ recommend()    │      │ Ledger / Retro   │
      │ play loop     │      │ route table    │      │ SkillDraft       │
      └───────┬───────┘      └────────────────┘      └──────────────────┘
              │
              ▼
      ┌───────────────┐      ┌────────────────┐      ┌──────────────────┐
      │ client        │─────▶│ policy.Guard   │      │ writeup.Writeup  │
      │ Client.call   │      │ check_*        │      │ render() / save()│
      └───────┬───────┘      └────────────────┘      └──────────────────┘
              │
     ┌────────┼─────────┐
     ▼        ▼         ▼
┌─────────┐┌────────┐┌──────────┐
│ catalog ││ratelimit││ redact   │
│spec/*.json││bucket ││Redactor  │
└─────────┘└────────┘└──────────┘
```

## Request lifecycle

Every call goes through exactly one funnel, `Client.call(operation_id, …)`:

1. **catalog lookup** — resolve `operation_id` to `(method, path, scope, risk_level,
   idempotency)`. An unknown id raises with a "did you mean" list drawn from the real
   catalog, so a typo costs one exception rather than a 404.
2. **policy gate** — `Guard.check_operation` refuses closed surfaces (writeups, community,
   tickets, private practice), admin routes, and competition routes unless explicitly
   enabled.
3. **path templating** — `{id}` / `{challengeId}` are substituted and *validated*: a missing
   param or an unexpected extra param is a `ValueError`, not a silently wrong URL.
4. **quota** — `TokenBucket.take` blocks until a token is free. Reads and writes have
   separate buckets because the platform throttles them separately (120/30 per minute).
5. **HTTP** — `urllib` with `Authorization: Bearer`. The token never appears in a log line;
   `Redactor` masks it in trace output.
6. **unwrap / raise** — `{"success": true, "data": …}` is unwrapped; an error envelope
   becomes `Ctf2Error(code, status, retryable, retry_after_ms, hint)`.
7. **retry** — only when `retryable`, and **never** for a non-idempotent write. A submission
   that may already have been applied is surfaced to the caller, not retried.

## Why the policy lives in code

The platform documents its Agent restrictions in prose (`references/safety.md`,
`references/agent-play.md`). Prose does not survive a refactor. Three of those rules are
mechanically checkable, so they are predicates:

```python
Guard().check_operation(op)                    # closed surfaces, admin, competitions
Guard().check_submission(flag, confirmation=True)   # explicit human confirmation
Guard().check_note("... flag{leaked} ...")     # PolicyViolation: flag-in-note
```

Each raises `PolicyViolation` — a *client-side* refusal that `cli.main` maps to exit code 2
and a one-line explanation, distinct from a server error (exit code 1).

## Error taxonomy

`Ctf2Error` exposes three derived booleans so callers branch on meaning, not strings:

| property | meaning | typical action |
| --- | --- | --- |
| `retryable` | in the official recovery table | sleep `retry_after_ms`, retry once |
| `auth_fatal` | 401 or revoked/disabled identity | stop; a human must re-issue the token |
| `scope_forbidden` | 403 with a valid credential | report the exact missing scope |

## Environment polling

`start_environment` is idempotent, so `wait_ready` simply repeats the cheap `GET` every few
seconds until `access_ready` is true, then returns the payload and
`AgentSession.access_urls(state)` extracts `access_url`/`access_urls` uniformly.

`agent_environment_limit` is re-raised with the play guide's remediation text attached,
because the correct response is *destroy the other environment first*, not retry.

## Attachments

The signed URL is bound to the caller and expires in five minutes. `fetch_attachment`
therefore issues and downloads in one method, re-issuing once on
`attachment_link_expired`, and writes to a sanitised filename under the caller's directory.
It never caches URLs.

## The three loops

1. **Solve loop** — `session.*`: discover → read → fetch → environment → submit → note.
2. **Verification loop** — the writeup's `## 自证` section is mandatory, and `submit` is
   gated on `confirmation`; a flag that was guessed rather than derived has nowhere to hide.
3. **Evolution loop** — `attempt` appends to `memory/attempts.jsonl`; `retro` aggregates
   win rate per category, which leading routes actually convert, and recurring blockers;
   `SkillDraft` scaffolds a new skill and validates it against the loader's frontmatter
   rules before it can be promoted.

## Regenerating the contract

`spec/operations.json` and `spec/openapi-user.json` are data, not code. When the platform
adds an operation:

```bash
ctf2 operations > spec/operations.json
curl -s https://ctf2.dasctf.com/api/openapi/v1/user.json -o spec/openapi-user.json
python -m unittest discover -s tests     # test_agent_only_operations_present will drift
```

The test asserting exactly 15 Agent-only operations is intentional: it is the tripwire that
tells you the surface changed.
