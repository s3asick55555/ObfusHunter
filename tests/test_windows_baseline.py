import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from analysis_engine import analyze_binary, detect_xor_strings, get_xor_scan_regions
from app import allowed_file


class WindowsBaselineTests(unittest.TestCase):
    def test_upload_filter_is_windows_pe_only(self) -> None:
        self.assertTrue(allowed_file("sample.exe"))
        self.assertTrue(allowed_file("sample.dll"))
        self.assertFalse(allowed_file("sample.apk"))

    def test_xor_scan_regions_prioritize_data_sections(self) -> None:
        def section(name: bytes, flags: int, offset: int, data: bytes) -> SimpleNamespace:
            return SimpleNamespace(
                Name=name,
                Characteristics=flags,
                PointerToRawData=offset,
                get_data=lambda: data,
            )

        read = 0x40000000
        write = 0x80000000
        fake_pe = SimpleNamespace(sections=[
            section(b".rsrc\x00\x00\x00", read, 0x200, b"R" * 64),
            section(b".rdata\x00\x00", read, 0x400, b"RDATA123"),
            section(b".data\x00\x00\x00", read | write, 0x600, b"DATA4567"),
        ])

        with patch("analysis_engine.pefile.PE", return_value=fake_pe):
            regions = get_xor_scan_regions("sample.exe", sample_size=32)

        self.assertEqual([region["name"] for region in regions], [".data", ".rdata"])
        self.assertEqual(regions[0]["offset"], 0x600)

    def test_xor_detection_uses_printable_strings_not_common_strings(self) -> None:
        plaintext = b"PresentationOnlyString42"
        encoded = bytes(byte ^ 0x80 for byte in plaintext)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "encoded.bin"
            path.write_bytes(b"\x00\xff" * 8 + encoded + b"\x00\xff" * 8)

            result = detect_xor_strings(str(path))

        self.assertIn("0x80", result["xor_keys"])
        hit = next(item for item in result["hits"] if item["key"] == "0x80")
        self.assertGreaterEqual(hit["printable_string_count"], 1)
        self.assertIn("PresentationOnlyString42", hit["examples"][0]["decoded"])

    def test_xor_detection_handles_printable_ciphertext_bytes(self) -> None:
        encoded = bytes([
            0x12, 0x3F, 0x36, 0x36, 0x35, 0x7A,
            0x0D, 0x35, 0x28, 0x36, 0x3E, 0x7B, 0x5A,
        ])
        pe_analysis = {
            "capstone": {
                "summary": {
                    "evidence": {
                        "memory_xor_immediate_samples": [{"key_value": 0x5A}],
                    },
                },
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "encoded.bin"
            path.write_bytes(encoded)

            result = detect_xor_strings(str(path), pe_analysis=pe_analysis)

        self.assertEqual(result["xor_keys"][0], "0x5a")
        hit = next(item for item in result["hits"] if item["key"] == "0x5a")
        self.assertTrue(hit["instruction_key_hint"])
        self.assertIn("Hello World!", hit["examples"][0]["decoded"])

    def test_non_pe_is_reported_as_not_pe_without_extra_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.apk"
            path.write_bytes(b"PK\x03\x04not-a-pe")

            result = analyze_binary(str(path))

        self.assertEqual(result["analysis_type"], "pe")
        self.assertFalse(result["pe_analysis"]["valid_pe"])
        self.assertEqual(result["obfuscation"]["status"], "UNSUPPORTED / NOT PE")
        allowed_keys = {"filename", "file_size", "analysis_type", "pe_analysis", "xor_analysis", "features", "obfuscation"}
        self.assertLessEqual(set(result), allowed_keys)


if __name__ == "__main__":
    unittest.main()
