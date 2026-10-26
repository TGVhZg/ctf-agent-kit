"""Offline test suite - no network, no credential required.

Run with ``python -m unittest discover -s tests -v`` (or ``python -m pytest tests`` if
pytest happens to be available). The catalog tests read the real packaged
``spec/operations.json``, so they also catch a stale catalog after a platform change.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf2arena.catalog import Catalog, Operation  # noqa: E402
from ctf2arena.errors import Ctf2Error, PolicyViolation  # noqa: E402
from ctf2arena.evolution import Attempt, Ledger, SkillDraft, build_retro  # noqa: E402
from ctf2arena.policy import Guard  # noqa: E402
from ctf2arena.ratelimit import Quotas, TokenBucket  # noqa: E402
from ctf2arena.redact import Redactor, looks_like_flag  # noqa: E402
from ctf2arena.session import AgentSession  # noqa: E402
from ctf2arena.triage import normalise_category, recommend  # noqa: E402
from ctf2arena.writeup import Step, Writeup  # noqa: E402


class TestRedact(unittest.TestCase):
    def test_token_is_masked_everywhere(self):
        token = "ctf2_abcdefghijklmnopqrstuvwxyz"
        r = Redactor([token])
        self.assertNotIn(token, r.redact(f"Authorization: Bearer {token}"))
        self.assertNotIn(token, r.redact(f"prefix {token} suffix"))

    def test_bearer_header_masked_without_known_secret(self):
        out = Redactor().redact("Authorization: Bearer sometotallyunknownvalue12345")
        self.assertNotIn("sometotallyunknownvalue12345", out)

    def test_jwt_masked(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"
        self.assertNotIn(jwt, Redactor().redact(f"token={jwt}"))

    def test_nested_redaction(self):
        r = Redactor(["secretvalue123456"])
        out = r.redact_obj({"a": ["secretvalue123456", 1]})
        self.assertEqual(out["a"][1], 1)
        self.assertNotIn("secretvalue123456", str(out))

    def test_flag_detected(self):
        for text in ("flag{abc}", "dasctf{hello_world}", "DASCTF{x}", "moectf{1_2_3}"):
            self.assertIsNotNone(looks_like_flag(text), text)

    def test_plain_text_is_not_a_flag(self):
        # No prefix, or an empty body: genuinely not flag-shaped.
        for text in ("", "no braces here", "just {x}", "a{} empty body", "x{  }"):
            self.assertIsNone(looks_like_flag(text), text)


class TestPolicy(unittest.TestCase):
    def _op(self, op_id="user_get_writeups", scope="writeup:read", path="/api/open/v1/user/writeups/"):
        return Operation(
            operation_id=op_id,
            method="GET",
            path=path,
            scope=scope,
            risk_level="low",
            idempotency="idempotent",
            summary="",
        )

    def test_writeup_scope_refused(self):
        with self.assertRaises(PolicyViolation) as ctx:
            Guard().check_operation(self._op())
        self.assertEqual(ctx.exception.rule, "closed-surface")

    def test_community_scope_refused(self):
        with self.assertRaises(PolicyViolation):
            Guard().check_operation(
                self._op("user_get_community_feeds", "community:read",
                         "/api/open/v1/user/community/feeds/")
            )

    def test_admin_route_refused(self):
        with self.assertRaises(PolicyViolation) as ctx:
            Guard().check_operation(
                self._op("admin_get_users", "admin:user:read", "/api/open/v1/admin/users/")
            )
        self.assertEqual(ctx.exception.rule, "admin-surface")

    def test_competition_refused_until_enabled(self):
        comp = self._op(
            "user_get_agent_competitions",
            "competition:read",
            "/api/open/v1/user/agent/competitions/",
        )
        with self.assertRaises(PolicyViolation):
            Guard().check_operation(comp)
        Guard(allow_competition=True).check_operation(comp)  # must not raise

    def test_ordinary_read_allowed(self):
        Guard().check_operation(
            self._op("user_get_practice", "practice:read", "/api/open/v1/user/practice/")
        )

    def test_flag_in_note_refused(self):
        with self.assertRaises(PolicyViolation) as ctx:
            Guard().check_note("the answer was flag{leaked_value}")
        self.assertEqual(ctx.exception.rule, "flag-in-note")

    def test_clean_note_allowed(self):
        Guard().check_note("patched the checker and inverted the TEA rounds")

    def test_submit_needs_confirmation(self):
        with self.assertRaises(PolicyViolation) as ctx:
            Guard().check_submission("flag{x}", confirmation=False)
        self.assertEqual(ctx.exception.rule, "unconfirmed-submit")

    def test_submit_rejects_empty_and_oversized(self):
        guard = Guard()
        with self.assertRaises(PolicyViolation):
            guard.check_submission("   ", confirmation=True)
        with self.assertRaises(PolicyViolation):
            guard.check_submission("A" * 5000, confirmation=True)

    def test_submit_normalises_whitespace(self):
        self.assertEqual(
            Guard().check_submission("  flag{ok}  ", confirmation=True), "flag{ok}"
        )


class TestCatalog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = Catalog.load()

    def test_catalog_loads_and_is_exhaustive_enough(self):
        self.assertGreaterEqual(len(self.catalog), 60)

    def test_agent_only_operations_present(self):
        ids = {op.operation_id for op in self.catalog.agent_operations()}
        self.assertIn("user_get_agent_me", ids)
        self.assertIn("user_get_agent_next_challenges", ids)
        self.assertIn("user_post_agent_notes", ids)
        self.assertEqual(len(ids), 15, f"expected 15 agent ops, got {sorted(ids)}")

    def test_build_path_fills_and_validates(self):
        path = self.catalog.build_path(
            "user_get_practice_id_challenges_challengeid",
            {"id": "11111111-1111-1111-1111-111111111111",
             "challengeId": "22222222-2222-2222-2222-222222222222"},
        )
        self.assertEqual(
            path,
            "/api/open/v1/user/practice/11111111-1111-1111-1111-111111111111"
            "/challenges/22222222-2222-2222-2222-222222222222/",
        )

    def test_build_path_rejects_missing_param(self):
        with self.assertRaises(ValueError):
            self.catalog.build_path("user_get_practice_id_challenges", {})

    def test_build_path_rejects_unknown_param(self):
        with self.assertRaises(ValueError):
            self.catalog.build_path("user_get_agent_me", {"bogus": "x"})

    def test_unknown_operation_has_suggestion(self):
        with self.assertRaises(KeyError):
            self.catalog.get("user_get_agent_meee")

    def test_write_flag_matches_method(self):
        submit = self.catalog.get("user_post_practice_id_challenges_challengeid_submit")
        self.assertTrue(submit.is_write)
        self.assertEqual(submit.risk_level, "high")
        me = self.catalog.get("user_get_agent_me")
        self.assertFalse(me.is_write)


class TestTriage(unittest.TestCase):
    def test_pyjail_routed_to_specific_skill(self):
        rec = recommend("Misc", "a pyjail with registers and attr too long")
        self.assertEqual(rec.skills[0], "pyjail-register-vm-shortattr-1arg")

    def test_tea_routed(self):
        rec = recommend("Reverse", "drink_tea magic 0x9e3779b9")
        self.assertEqual(rec.skills[0], "ctf-rev-tea-family-identification")

    def test_usb_routed(self):
        rec = recommend("Misc", "usbmon keyboard hid capture")
        self.assertEqual(rec.skills[0], "ctf-usb-hid-keyboard-pcapng")

    def test_unknown_category_falls_back_to_dispatcher(self):
        rec = recommend(None, "something entirely unremarkable")
        self.assertEqual(rec.skills, ["solve-challenge"])

    def test_category_alone_does_not_nominate_advanced_skill(self):
        # Regression: this exact statement (a trivial ROT13 challenge) used to route to
        # ctf-mldsa-noise-leak-forge / ctf-coppersmith-* purely on the category match.
        rec = recommend("CRYPTO", "注意：得到的 flag 请包上 flag{} 提交")
        self.assertEqual(rec.skills[0], "ctf-crypto")
        self.assertNotIn("ctf-mldsa-noise-leak-forge", rec.skills)

    def test_bare_web_category_returns_generic_web(self):
        rec = recommend("WEB", "点击启动靶机。")
        self.assertEqual(rec.skills[0], "ctf-web")
        self.assertNotIn("web-http-request-smuggling", rec.skills)

    def test_specific_skill_requires_a_signal(self):
        from ctf2arena.triage import Route

        route = Route("x", ("crypto",), ("truncated lcg",), weight=3)
        self.assertEqual(route.score("crypto", "some easy crypto"), 0)
        self.assertGreater(route.score("crypto", "truncated lcg outputs"), 0)

    def test_generic_beats_nothing_but_loses_to_signal(self):
        weak = recommend("reverse", "a plain binary with no hints")
        strong = recommend("reverse", "drink_tea with delta 0x9e3779b9")
        self.assertEqual(weak.skills[0], "ctf-reverse")
        self.assertEqual(strong.skills[0], "ctf-rev-tea-family-identification")

    def test_category_normalisation(self):
        self.assertEqual(normalise_category("RE"), "reverse")
        self.assertEqual(normalise_category("逆向"), "reverse")
        self.assertEqual(normalise_category("密码"), "crypto")
        self.assertEqual(normalise_category(None), "")


class TestWriteup(unittest.TestCase):
    def test_render_has_required_sections(self):
        w = Writeup(
            title="Demo writeup",
            challenge_name="demo",
            challenge_id="abc",
            category="reverse",
            flag="flag{demo}",
            conclusion="patched and inverted",
            recognise=["tea-like constants"],
            recon=["strings found the checker"],
            steps=[Step(title="locate checker", detail="xref on the string", code="index = 0x401000", lang="c")],
            verification=["re-encrypting the flag reproduces the table byte for byte"],
            pitfalls=["assumed standard TEA before checking delta"],
            reproduction=["python solve.py"],
            skills=["ctf-rev-tea-family-identification"],
        )
        text = w.render()
        for heading in ("# Demo writeup", "## 自证", "## 踩坑", "## Flag", "## 复现", "## 相关技能"):
            self.assertIn(heading, text)
        self.assertIn("flag{demo}", text)
        self.assertIn("```c", text)

    def test_save_writes_file(self):
        w = Writeup(title="t", challenge_name="Some Challenge!", flag="flag{x}")
        with tempfile.TemporaryDirectory() as tmp:
            path = w.save(tmp)
            self.assertTrue(path.exists())
            self.assertEqual(path.name, "some-challenge.md")

    def test_pipe_in_cell_is_escaped(self):
        w = Writeup(title="t", challenge_name="a|b")
        self.assertIn("a\\|b", w.render())


class TestEvolution(unittest.TestCase):
    def test_ledger_roundtrip_and_torn_line_tolerance(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(tmp)
            ledger.append(Attempt(challenge_id="c1", category="reverse", result="solved",
                                  minutes=12, route=["ctf-rev-tea-family-identification"]))
            ledger.append(Attempt(challenge_id="c2", category="reverse", result="failed",
                                  blocker="module not found", route=["ctf-reverse"]))
            with ledger.path.open("a", encoding="utf-8") as fh:
                fh.write("{not json\n")
            loaded = ledger.load()
            self.assertEqual([a.challenge_id for a in loaded], ["c1", "c2"])

    def test_invalid_result_rejected(self):
        with self.assertRaises(ValueError):
            Attempt(challenge_id="c", result="maybe")

    def test_retro_aggregates(self):
        attempts = [
            Attempt(challenge_id="a", category="reverse", result="solved", minutes=10,
                    route=["x"]),
            Attempt(challenge_id="b", category="reverse", result="failed",
                    blocker="pip install failed", route=["y"]),
            Attempt(challenge_id="c", category="web", result="solved", minutes=30,
                    route=["y"]),
        ]
        retro = build_retro(attempts)
        self.assertEqual(retro.total, 3)
        self.assertEqual(retro.solved, 2)
        self.assertAlmostEqual(retro.win_rate, 2 / 3)
        self.assertEqual(retro.by_category["reverse"], (1, 2))
        self.assertEqual(retro.median_minutes, 20)
        self.assertIn("python/tooling", dict(retro.blockers))
        self.assertIn("# 复盘", retro.render())
        self.assertIn("## 反复卡点", retro.render())

    def test_empty_retro_renders(self):
        self.assertIn("尚无记录", build_retro([]).render())

    def test_retro_deduplicates_repeated_attempts(self):
        # A re-run appends a second row for the same challenge; counting both would
        # inflate attempts and solves and make the win rate meaningless.
        attempts = [
            Attempt(challenge_id="dup", category="web", result="failed", minutes=9),
            Attempt(challenge_id="dup", category="web", result="solved", minutes=11),
            Attempt(challenge_id="other", category="web", result="solved", minutes=5),
        ]
        retro = build_retro(attempts)
        self.assertEqual(retro.total, 2)
        self.assertEqual(retro.solved, 2)
        # the last row wins, so the retry that worked is what counts
        self.assertAlmostEqual(retro.win_rate, 1.0)
        self.assertEqual(retro.by_category["web"], (2, 2))

    def test_skill_draft_validation(self):
        good = SkillDraft(
            name="ctf-demo-skill",
            title="demo",
            description="x",
            triggers=["触发词"],
            core=["步骤一"],
        )
        self.assertEqual(good.validate(), [])

        bad_name = SkillDraft(name="CTF_Demo", title="d", description="x",
                              triggers=["t"], core=["c"])
        self.assertTrue(any("name" in p for p in bad_name.validate()))

        colon = SkillDraft(name="ok-name", title="d",
                           description="uses Transfer-Encoding: chunked",
                           triggers=["t"], core=["c"])
        self.assertTrue(any("colon" in p or "': '" in p for p in colon.validate()))

    def test_skill_draft_renders_valid_frontmatter(self):
        draft = SkillDraft(
            name="ctf-demo-skill",
            title="一句话定位",
            description="x",
            triggers=["触发词一", "触发词二"],
            core=["步骤一", "步骤二"],
        )
        text = draft.render()
        self.assertTrue(text.startswith("---\n"))
        self.assertIn("name: ctf-demo-skill", text)
        self.assertIn("description: >", text)
        self.assertIn("触发词——触发词一、触发词二。", text)

    def test_skill_draft_save_refuses_invalid(self):
        draft = SkillDraft(name="Bad Name", title="d", description="x",
                           triggers=["t"], core=["c"])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                draft.save(tmp)


class TestRateLimit(unittest.TestCase):
    def test_bucket_refills(self):
        bucket = TokenBucket(capacity=1, rate_per_second=1000)
        self.assertTrue(bucket.try_take())
        self.assertFalse(bucket.try_take())
        self.assertLess(bucket.time_until(), 1.0)

    def test_quotas_expose_both_classes(self):
        quota = Quotas()
        self.assertGreater(quota.reads.rate, quota.writes.rate)

    def test_headroom_is_below_published_limit(self):
        quota = Quotas(read_per_minute=120, write_per_minute=30, headroom=0.85)
        self.assertAlmostEqual(quota.reads.rate * 60, 102.0, places=6)
        self.assertAlmostEqual(quota.writes.rate * 60, 25.5, places=6)


class TestRetryPolicy(unittest.TestCase):
    """The write-retry rule: safe only when the error proves nothing was applied."""

    def test_rate_limit_is_retryable_for_writes(self):
        from ctf2arena.client import _safe_to_retry_write

        for code in ("rate_limit_exceeded", "RATE_LIMITED", "http_429"):
            self.assertTrue(_safe_to_retry_write(Ctf2Error(code)), code)

    def test_ambiguous_errors_are_not_retried_for_writes(self):
        from ctf2arena.client import _safe_to_retry_write

        for code in ("internal_error", "backend_unavailable", "conflict",
                     "submission_cooldown"):
            self.assertFalse(_safe_to_retry_write(Ctf2Error(code)), code)


class TestEndpoints(unittest.TestCase):
    """access_urls is a string list; endpoints() recovers the facts a solver needs."""

    def test_tcp_with_tls_is_reported(self):
        state = {
            "access_type": "tcp",
            "access_urls": [
                {"nc_ssl": True, "type": "tcp",
                 "url": "abc123.tcp-ctf2.dasctf.com:9999"}
            ],
        }
        (endpoint,) = AgentSession.endpoints(state)
        self.assertEqual(endpoint.kind, "tcp")
        self.assertEqual(endpoint.host, "abc123.tcp-ctf2.dasctf.com")
        self.assertEqual(endpoint.port, 9999)
        # This single flag is the difference between "service is down" and
        # "you are speaking plaintext to a TLS endpoint".
        self.assertTrue(endpoint.tls)

    def test_http_endpoint_parsed(self):
        state = {
            "access_urls": [
                {"nc_ssl": None, "type": "http",
                 "url": "http://deadbeef.http-ctf2.dasctf.com:80"}
            ]
        }
        (endpoint,) = AgentSession.endpoints(state)
        self.assertEqual(endpoint.kind, "http")
        self.assertEqual(endpoint.host, "deadbeef.http-ctf2.dasctf.com")
        self.assertEqual(endpoint.port, 80)
        self.assertFalse(endpoint.tls)

    def test_falls_back_to_single_url(self):
        state = {"access_type": "http", "access_url": "http://x.test:8080"}
        (endpoint,) = AgentSession.endpoints(state)
        self.assertEqual((endpoint.host, endpoint.port), ("x.test", 8080))

    def test_missing_port_and_empty_state(self):
        self.assertEqual(AgentSession.endpoints({}), [])
        (endpoint,) = AgentSession.endpoints({"access_url": "hostonly.example"})
        self.assertEqual(endpoint.port, None)


class TestErrors(unittest.TestCase):
    def test_retryable_from_code(self):
        self.assertTrue(Ctf2Error("rate_limited").retryable)
        self.assertFalse(Ctf2Error("already_solved").retryable)

    def test_401_is_auth_fatal(self):
        self.assertTrue(Ctf2Error("AUTH_REQUIRED", status=401).auth_fatal)
        self.assertFalse(Ctf2Error("forbidden", status=403).auth_fatal)
        self.assertTrue(Ctf2Error("forbidden", status=403).scope_forbidden)

    def test_str_includes_retry_hint(self):
        err = Ctf2Error("submission_cooldown", "wait", status=429, retry_after_ms=5000)
        text = str(err)
        self.assertIn("submission_cooldown", text)
        self.assertIn("5000ms", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
