import struct
import unittest

import capstone

from analysis.reverse.annotate import disassembly
from analysis.reverse.dispatch import Entry, check, jump_table, markdown, resolve_case
from analysis.reverse.hosts import endpoint, find_hosts
from analysis.reverse.kinds import ENCODE_BUFFER, check as check_kinds, helper_encodes_buffer


class FakeImage:
    def __init__(self, code=b"", base=0x140000000):
        self.img = code
        self.base = base
        self.text = (0, 0x1000000)
        self.rdata = (0, 0)
        self.imports = {}
        self.start_set = set()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def func(self, rva):
        return (0, len(self.img)) if self.img else None

    def disasm(self, start, end=None, count=None):
        for i, ins in enumerate(self.md.disasm(self.img[start:end], self.base + start)):
            if count is not None and i >= count:
                break
            yield ins

    def text_at(self, rva):
        return None


class DispatchTests(unittest.TestCase):
    def test_direct_and_indexed_tables(self):
        image = FakeImage(struct.pack("<III", 0x111, 0x222, 0x333) + bytes([1, 0, 1]))
        self.assertEqual(list(jump_table(image, 0x10, 3, 0)), [(0x10, 0x111), (0x11, 0x222), (0x12, 0x333)])
        self.assertEqual(list(jump_table(image, 0x20, 3, 0, index=12)),
                         [(0x20, 0x222), (0x21, 0x111), (0x22, 0x222)])

    def test_case_resolution_skips_packet_decoder(self):
        code = bytearray()
        code += b"\x48\x83\xec\x08"
        code += b"\xe8" + struct.pack("<i", 0x75CA20 - (len(code) + 5))
        code += b"\xe8" + struct.pack("<i", 0x12345 - (len(code) + 5))
        code += b"\xc3"
        image = FakeImage(bytes(code))
        handler, path, how = resolve_case(image, 0, 0x1000)
        self.assertEqual((handler, path, how), (0x12345, (0, 0x12345), "call"))

    def test_known_dispatch_check_and_unresolved_markdown(self):
        expected = {0x5AC: 0x1B00F90, 0x22D: 0x2A75220, 0x1A9: 0x2127880,
                    0x0E: 0x1BD25A0, 0x44: 0x1BCB570, 0x340: 0x29CDE20}
        entries = [Entry(op, "test", handler) for op, handler in expected.items()]
        self.assertEqual(len(check(entries)), 6)
        self.assertIn("S 0x5ac", markdown(entries))
        with self.assertRaises(AssertionError):
            check(entries[:-1])


class AnnotationTests(unittest.TestCase):
    def test_packet_call_is_labelled_with_rva(self):
        code = b"\xe8" + struct.pack("<i", 0x75C8E0 - 5) + b"\xc3"
        image = FakeImage(code)
        self.assertIn("CInPacket::Decode1", disassembly(image, 0)[0])
        self.assertIn("-> 0x75c8e0", disassembly(image, 0)[0])


class HostTests(unittest.TestCase):
    def test_ascii_wide_urls_hosts_ips_and_ports(self):
        data = (b"https://example.com:8443/a\x00"
                + "jyp.nexon.com:9994".encode("utf-16-le") + b"\x00\x00"
                + b"\x00192.0.2.10:47611\x00"
                + b"\x00300.1.2.3\x00"
                + b"\x00http://ocsp.digicert.com0A\x00")
        found = find_hosts(data)
        self.assertEqual(found["https://example.com:8443/a"], 1)
        self.assertEqual(found["http://ocsp.digicert.com"], 1)
        self.assertEqual(found["jyp.nexon.com:9994"], 1)
        self.assertEqual(found["192.0.2.10:47611"], 1)
        self.assertNotIn("300.1.2.3", found)
        self.assertEqual(endpoint("jyp.nexon.com:9994"), ("domain", "jyp.nexon.com", 9994))


class KindTests(unittest.TestCase):
    def test_unlisted_encode_buffer_thunk(self):
        code = b"\xe9" + struct.pack("<i", ENCODE_BUFFER - 5)
        image = FakeImage(code)
        image.func = lambda rva: None
        self.assertTrue(helper_encodes_buffer(image, 0))

    def test_expected_builders(self):
        sites = [{"builder": 0x98BBF0, "kind": 1},
                 {"builder": 0xD15B10, "kind": 0x76},
                 {"builder": 0xD15860, "kind": 0x76}]
        self.assertEqual(len(check_kinds(sites)), 3)
        with self.assertRaises(AssertionError):
            check_kinds(sites[1:])


if __name__ == "__main__":
    unittest.main()
