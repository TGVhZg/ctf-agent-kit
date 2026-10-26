"""Offline tests for the service client, ELF recon helpers and strict judgements."""

from __future__ import annotations

import socket
import struct
import threading
import unittest

from ctf2arena.binutils import (
    POP_BYTES,
    find_pivots,
    scan_bytes,
)
from ctf2arena.judge import (
    BadJudgement,
    Judgement,
    alignment_is_tautological,
    alignment_warning,
    discriminating,
    find_flags,
    printable_rate,
)
from ctf2arena.lab import EchoMismatch, ServiceClient, service_from_endpoint


class ScanTests(unittest.TestCase):
    def test_scan_bytes_finds_overlapping_matches(self) -> None:
        self.assertEqual(scan_bytes(b"aaaa", b"aa"), [0, 1, 2])
        self.assertEqual(scan_bytes(b"xyz", b"q"), [])
        self.assertEqual(scan_bytes(b"abc", b""), [])

    def test_add_esp_pivot_is_found_and_ebx_safe(self) -> None:
        data = b"\x90\x83\xc4\x10\xc3"
        hits = find_pivots(data, base=0x1000)
        add = [h for h in hits if h.kind.startswith("add esp")]
        self.assertEqual(len(add), 1)
        self.assertEqual(add[0].addr, 0x1001)
        self.assertEqual(add[0].advance, 0x10)
        self.assertFalse(add[0].clobbers_ebx)
        self.assertTrue(add[0].usable_with_plt)

    def test_pop_ebx_pivot_is_flagged_unsafe(self) -> None:
        data = b"\x5b\x5e\x5f\x5d\xc3"  # pop ebx; esi; edi; ebp; ret
        hits = find_pivots(data, base=0)
        self.assertTrue(hits)
        four = [h for h in hits if h.pops]
        self.assertEqual(four[0].pops, ("ebx", "esi", "edi", "ebp"))
        self.assertTrue(four[0].clobbers_ebx)
        self.assertFalse(four[0].usable_with_plt)

    def test_avoid_ebx_keeps_the_shorter_sub_gadgets(self) -> None:
        # rec_33c3_2016 shape: bytes `5b 5e 5f 5d c3`.  Backward decoding used to
        # stop at the longest run, hiding `pop esi; pop edi; pop ebp; ret` at +1.
        # Those shorter variants survive an avoid_ebx filter, so the filter must
        # report them -- while still reporting *zero* candidates that advance far
        # enough (>= 0x10) to line up a call's arguments.
        data = b"\x5b\x5e\x5f\x5d\xc3"
        all_hits = find_pivots(data, avoid_ebx=False)
        self.assertTrue(any(h.clobbers_ebx for h in all_hits))
        safe = find_pivots(data, avoid_ebx=True)
        self.assertTrue(safe, "shorter ebx-free sub-gadgets must be reported")
        self.assertTrue(all(not h.clobbers_ebx for h in safe))
        self.assertEqual(
            [h for h in safe if h.advance >= 0x10],
            [],
            "no ebx-free variant reaches the 0x10 advance this target needs",
        )

    def test_four_pop_without_ebx_is_usable(self) -> None:
        data = b"\x5e\x5f\x5d\x58\xc3"  # pop esi; edi; ebp; eax; ret
        hits = [h for h in find_pivots(data, avoid_ebx=True) if h.pops]
        self.assertEqual(hits[0].pops, ("esi", "edi", "ebp", "eax"))
        self.assertEqual(hits[0].advance, 0x10)
        self.assertFalse(hits[0].clobbers_ebx)

    def test_ret_imm16_advance_includes_immediate(self) -> None:
        data = b"\xc2\x10\x00"
        hits = [h for h in find_pivots(data) if h.kind == "ret imm16"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].advance, 4 + 0x10)

    def test_absurd_ret_imm16_is_rejected_as_false_positive(self) -> None:
        # A 0xC2 byte inside some longer instruction must not masquerade as an
        # epilogue that advances the stack by 0x2a17.
        data = b"\xc2\x17\x2a"
        self.assertEqual([h for h in find_pivots(data) if h.kind == "ret imm16"], [])
        self.assertEqual(
            [h for h in find_pivots(data, max_imm=0xFFFF) if h.kind == "ret imm16"],
            find_pivots(b"\xc2\x17\x2a", max_imm=0xFFFF),
        )

    def test_pop_table_covers_common_registers(self) -> None:
        for code, name in POP_BYTES.items():
            self.assertIn(name, ("eax", "ecx", "edx", "ebx", "ebp", "esi", "edi"))
            self.assertEqual(code & 0xF8, 0x58)


class FlagOracleTests(unittest.TestCase):
    def test_accepts_a_clean_flag(self) -> None:
        self.assertEqual(
            find_flags(b"noise CTF2{abc-123} more noise"),
            ["CTF2{abc-123}"],
        )

    def test_rejects_body_containing_binary(self) -> None:
        blob = b"CTF2{ab\x00\x01cd}"
        self.assertEqual(find_flags(blob), [])

    def test_rejects_missing_shell_or_brace(self) -> None:
        self.assertEqual(find_flags(b"{abc}"), [])
        self.assertEqual(find_flags(b"CTF2_abc"), [])

    def test_deduplicates(self) -> None:
        self.assertEqual(find_flags(b"CTF2{x} and CTF2{x}"), ["CTF2{x}"])

    def test_printable_rate_is_reported_not_decisive(self) -> None:
        self.assertAlmostEqual(printable_rate(b"abcd"), 1.0)
        self.assertLess(printable_rate(b"\x00\x01\x02\x03"), 0.01)
        self.assertEqual(printable_rate(b""), 0.0)


class JudgementTests(unittest.TestCase):
    def test_alignment_tautology_detected(self) -> None:
        # 0xf7f46d60 and 0x46d60 share low 12 bits => the check cannot fail.
        self.assertTrue(alignment_is_tautological(0xF7F46D60, 0x46D60))
        self.assertIsNotNone(alignment_warning(0xF7F46D60, 0x46D60))

    def test_alignment_is_informative_when_bits_differ(self) -> None:
        self.assertFalse(alignment_is_tautological(0xF7F46D60, 0x49020))
        self.assertIsNone(alignment_warning(0xF7F46D60, 0x49020))

    def test_discriminating_needs_a_negative_control(self) -> None:
        self.assertTrue(discriminating(3, 0))
        self.assertFalse(discriminating(3, 3))   # fires on everything => useless
        self.assertFalse(discriminating(0, 0))

    def test_observed_claim_requires_evidence(self) -> None:
        with self.assertRaises(BadJudgement):
            Judgement(claim="it crashes", evidence="", confidence="observed")
        self.assertTrue(Judgement(claim="it crashes", evidence="core dumped"))

    def test_confidence_must_be_known(self) -> None:
        with self.assertRaises(BadJudgement):
            Judgement(claim="x", evidence="y", confidence="certain")


class _FakeServer:
    """Tiny local server used to exercise the service client."""

    def __init__(self, *, echo: bool) -> None:
        self.echo = echo
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            conn.sendall(b"banner> ")
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                if self.echo:
                    conn.sendall(b"Hi, " + data)
                else:
                    conn.sendall(b"...")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class ServiceClientTests(unittest.TestCase):
    def test_read_until_banner(self) -> None:
        srv = _FakeServer(echo=True)
        try:
            with ServiceClient("127.0.0.1", srv.port, tls=False) as client:
                self.assertIn(b"banner> ", client.read_until(b"> "))
        finally:
            srv.close()

    def test_expect_echo_confirms_input(self) -> None:
        srv = _FakeServer(echo=True)
        try:
            with ServiceClient("127.0.0.1", srv.port, tls=False) as client:
                client.read_until(b"> ")
                seen = client.expect_echo(b"AAAA")
                self.assertIn(b"AAAA", seen)
        finally:
            srv.close()

    def test_expect_echo_raises_when_prompt_is_desynchronised(self) -> None:
        srv = _FakeServer(echo=False)
        try:
            with ServiceClient("127.0.0.1", srv.port, tls=False) as client:
                client.read_until(b"> ")
                with self.assertRaises(EchoMismatch):
                    client.expect_echo(b"ZZZZ")
        finally:
            srv.close()

    def test_service_from_endpoint_rejects_non_tcp(self) -> None:
        class Ep:
            kind = "http"
            host = "h"
            port = 80
            tls = False

        with self.assertRaises(Exception):
            service_from_endpoint(Ep())

    def test_service_from_endpoint_builds_tcp(self) -> None:
        class Ep:
            kind = "tcp"
            host = "abc.example"
            port = 9999
            tls = True

        svc = service_from_endpoint(Ep())
        self.assertEqual(svc.label, "abc.example:9999")
        self.assertTrue(svc.tls)


class SectionMappingTests(unittest.TestCase):
    def test_offset_to_vaddr_and_back(self) -> None:
        from ctf2arena.binutils import Section

        secs = [
            Section(".text", addr=0x550, offset=0x550, size=0x100, flags="AX"),
            Section(".data", addr=0x3000, offset=0x2000, size=0x8, flags="WA"),
        ]
        # mirror ElfFacts.offset_of / vaddr_of logic on synthetic sections
        target = secs[1]
        self.assertTrue(target.contains(0x3004))
        self.assertEqual(target.offset + (0x3004 - target.addr), 0x2004)
        self.assertFalse(secs[0].contains(0x3004))


if __name__ == "__main__":
    unittest.main()
