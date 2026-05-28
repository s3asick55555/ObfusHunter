from __future__ import annotations

import unittest
from types import SimpleNamespace

from capstone.x86 import X86_OP_IMM, X86_OP_MEM

from analysis_engine import detect_stack_string_xor_patterns


REG_ESP = 1


class FakeInsn:
    def __init__(
        self,
        address: int,
        mnemonic: str,
        op_str: str,
        operands: list[SimpleNamespace],
        reg_names: dict[int, str] | None = None,
        raw_bytes: bytes = b"\x90",
    ) -> None:
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.operands = operands
        self.bytes = raw_bytes
        self.size = len(raw_bytes)
        self._reg_names = reg_names or {}

    def reg_name(self, reg_id: int) -> str:
        return self._reg_names.get(reg_id, "")


def imm_operand(value: int) -> SimpleNamespace:
    return SimpleNamespace(type=X86_OP_IMM, imm=value, size=4)


def mem_operand(base: int, disp: int, size: int = 4) -> SimpleNamespace:
    return SimpleNamespace(
        type=X86_OP_MEM,
        mem=SimpleNamespace(base=base, disp=disp),
        size=size,
    )


class PEStackStringXorTests(unittest.TestCase):
    def test_detects_push_then_stack_xor_string_pattern(self) -> None:
        reg_names = {REG_ESP: "esp"}
        disassembled = [
            FakeInsn(
                0x401000,
                "push",
                "0x723e3e2b",
                [imm_operand(0x723E3E2B)],
                reg_names=reg_names,
                raw_bytes=b"\x68\x2b\x3e\x3e\x72",
            ),
            FakeInsn(
                0x401005,
                "push",
                "0x61656579",
                [imm_operand(0x61656579)],
                reg_names=reg_names,
                raw_bytes=b"\x68\x79\x65\x65\x61",
            ),
            FakeInsn(
                0x40100A,
                "xor",
                "dword ptr [esp], 0x11111111",
                [mem_operand(REG_ESP, 0), imm_operand(0x11111111)],
                reg_names=reg_names,
                raw_bytes=b"\x81\x34\x24\x11\x11\x11\x11",
            ),
            FakeInsn(
                0x401011,
                "xor",
                "dword ptr [esp+4], 0x11111111",
                [mem_operand(REG_ESP, 4), imm_operand(0x11111111)],
                reg_names=reg_names,
                raw_bytes=b"\x81\x74\x24\x04\x11\x11\x11\x11",
            ),
            FakeInsn(
                0x401019,
                "ret",
                "",
                [],
                reg_names=reg_names,
                raw_bytes=b"\xc3",
            ),
        ]

        hits = detect_stack_string_xor_patterns(
            disassembled,
            section_name=".text",
            pointer_size=4,
        )

        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["section"], ".text")
        self.assertIn("stack-built bytes XOR-decoded on the stack", hit["pattern"])
        self.assertIn("http://c", hit["pattern"])
        self.assertEqual(len(hit["instructions"]), 4)
        self.assertEqual(hit["instructions"][0]["mnemonic"], "push")
        self.assertEqual(hit["instructions"][-1]["mnemonic"], "xor")


if __name__ == "__main__":
    unittest.main()
