"""Offline tests for the solving assets: AES, DES and the QR decoder.

The QR block table in :mod:`ctf2arena.qr` is transcribed by hand from the spec, which is
exactly the kind of data that acquires a typo. The strong invariant is that a symbol's
**total** codeword count depends only on its version, not on its error-correction level -
so cross-checking every (version, level) pair against the published totals catches a bad
entry without needing a reference QR image.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf2arena import aes, des, qr, serpent  # noqa: E402

#: Published total codeword counts per QR version (ISO/IEC 18004).
QR_TOTALS = {
    1: 26, 2: 44, 3: 70, 4: 100, 5: 134,
    6: 172, 7: 196, 8: 242, 9: 292, 10: 346,
}


class TestAes(unittest.TestCase):
    def test_fips197_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        expect = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        rk = aes._expand_key(key)
        self.assertEqual(aes.encrypt_block(plain, rk), expect)
        self.assertEqual(aes.decrypt_block(expect, rk), plain)

    def test_ecb_roundtrip(self):
        key = b"0123456789abcdef"
        data = b"A" * 32
        self.assertEqual(aes.decrypt_ecb(aes.encrypt_ecb(data, key), key), data)

    def test_cbc_roundtrip_and_iv_matters(self):
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        data = b"C" * 48
        ct = aes.encrypt_cbc(data, key, iv)
        self.assertEqual(aes.decrypt_cbc(ct, key, iv), data)
        # a different IV must not decrypt to the same plaintext
        self.assertNotEqual(aes.decrypt_cbc(ct, key, b"\x00" * 16), data)

    def test_key_length_is_enforced(self):
        with self.assertRaises(ValueError):
            aes._expand_key(b"short")
        with self.assertRaises(ValueError):
            aes.decrypt_ecb(b"x" * 16, b"tooshort")

    def test_bad_block_length_rejected(self):
        with self.assertRaises(ValueError):
            aes.decrypt_ecb(b"x" * 15, b"0123456789abcdef")

    def test_pkcs7_pad_unpad(self):
        self.assertEqual(aes.pad_pkcs7(b"abc"), b"abc" + b"\x0d" * 13)
        self.assertEqual(aes.unpad_pkcs7(b"abc" + b"\x0d" * 13), (b"abc", True))
        # a full block of padding
        self.assertEqual(aes.pad_pkcs7(b"A" * 16), b"A" * 16 + b"\x10" * 16)

    def test_unpad_reports_invalid_instead_of_guessing(self):
        for bad in (b"", b"abc", b"abc\x00", b"abc\x05", b"abc\x20"):
            data, ok = aes.unpad_pkcs7(bad)
            self.assertFalse(ok, bad)
            self.assertEqual(data, bad)


class TestDes(unittest.TestCase):
    def test_standard_vector(self):
        key = bytes.fromhex("133457799BBCDFF1")
        plain = bytes.fromhex("0123456789ABCDEF")
        expect = bytes.fromhex("85E813540F0AB405")
        self.assertEqual(des.encrypt_block(plain, key), expect)
        self.assertEqual(des.decrypt_block(expect, key), plain)
        self.assertTrue(des.selftest_block())

    def test_ecb_roundtrip(self):
        key = b"Anaconda"
        data = b"B" * 24
        self.assertEqual(des.decrypt_ecb(des.encrypt_ecb(data, key), key), data)

    def test_ecb_leaks_repetition(self):
        # ECB enciphers each block independently, so two identical plaintext blocks must
        # produce two identical ciphertext blocks. Asserting the opposite is a classic
        # mistake - this test exists to pin the real property down.
        key = b"Anaconda"
        ct = des.encrypt_ecb(b"A" * 16, key)
        self.assertEqual(ct[:8], ct[8:])
        # ... and CBC must not, because each block is chained.
        iv = b"\x00" * 8
        cbc_first = des.encrypt_block(b"A" * 8, key)
        cbc_second = des.encrypt_block(
            bytes(a ^ b for a, b in zip(b"A" * 8, cbc_first)), key
        )
        self.assertNotEqual(cbc_first, cbc_second)

    def test_key_length_enforced(self):
        with self.assertRaises(ValueError):
            des.encrypt_block(b"x" * 8, b"7bytes!")


class TestSerpent(unittest.TestCase):
    def test_official_nessie_vector(self):
        # The single most valuable test in this file: it pins 8 S-boxes used as
        # round%8, vertical nibbles, the linear transform, and the absence of IP/FP
        # all at once. Any one of them wrong makes this fail.
        self.assertTrue(serpent.selftest()[0])

    def test_kat_constants(self):
        keys = serpent.round_keys(serpent.KAT_KEY)
        self.assertEqual(
            serpent.encrypt_block(serpent.KAT_PLAIN, keys).hex(),
            "264e5481eff42a4606abda06c0bfda3d",
        )

    def test_ecb_roundtrip(self):
        key = b"Anaconda" + b"\x01" + bytes(23)
        data = bytes(range(48))
        self.assertEqual(
            serpent.decrypt_ecb(serpent.encrypt_ecb(data, key), key), data
        )

    def test_key_schedule_is_not_index_wrapped(self):
        # Regression guard for the Python-specific bug: writing the prekey
        # recurrence as w[i-8] over an appended list silently wraps negative
        # indices and corrupts the schedule. Different key lengths must therefore
        # produce genuinely different round keys.
        k8 = serpent.round_keys(b"Anaconda")
        k16 = serpent.round_keys(b"Anaconda" + bytes(8))
        self.assertNotEqual(k8[0], k16[0])

    def test_pad_key_appends_one_bit(self):
        padded = serpent.pad_key(b"Anaconda")
        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[:8], b"Anaconda")
        self.assertEqual(padded[8], 0x01)
        self.assertEqual(padded[9:], bytes(23))

    def test_requires_whole_blocks(self):
        with self.assertRaises(ValueError):
            serpent.decrypt_ecb(b"x" * 15, b"Anaconda")

    def test_sboxes_are_bijections(self):
        for i, row in enumerate(serpent.SBOX):
            self.assertEqual(sorted(row), list(range(16)), f"S{i}")


class TestQrTables(unittest.TestCase):
    def test_total_codewords_per_version_agree_across_levels(self):
        for version, expect in QR_TOTALS.items():
            for level in "LMQH":
                ec, g1n, g1d, g2n, g2d = qr._BLOCKS[(version, level)]
                total = ec * (g1n + g2n) + g1d * g1n + g2d * g2n
                self.assertEqual(
                    total, expect,
                    f"version {version} level {level}: block table yields {total}, "
                    f"spec says {expect}",
                )

    def test_block_table_covers_every_pair(self):
        for version in QR_TOTALS:
            for level in "LMQH":
                self.assertIn((version, level), qr._BLOCKS)

    def test_data_positions_hold_exactly_the_codewords(self):
        for version, total in QR_TOTALS.items():
            positions = qr._data_positions(version)
            self.assertGreaterEqual(len(positions), total * 8, f"v{version}")
            self.assertLess(len(positions), (total + 1) * 8, f"v{version}")

    def test_function_mask_grows_with_version(self):
        prev = 0
        for version in sorted(QR_TOTALS):
            n = 17 + 4 * version
            mask = qr._function_mask(version)
            self.assertEqual(len(mask), n)
            marked = sum(sum(row) for row in mask)
            self.assertGreater(marked, prev)
            prev = marked

    def test_mask_formulas_are_boolean(self):
        for mask in range(8):
            for r in range(8):
                for c in range(8):
                    self.assertIn(qr._mask_bit(mask, r, c), (True, False))

    def test_bad_mask_rejected(self):
        with self.assertRaises(ValueError):
            qr._mask_bit(8, 0, 0)

    def test_decode_known_image_if_present(self):
        """End-to-end on a real symbol, when the working copy still has it."""
        image_path = Path("plays/二维码/QR_code.png")
        if not image_path.exists():
            self.skipTest("sample image not present")
        from PIL import Image

        result = qr.decode_pil(Image.open(image_path))
        self.assertEqual(result.version, 2)
        self.assertEqual(result.size, 25)
        self.assertTrue(result.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
