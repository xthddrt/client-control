import struct
import unittest

from traffic import fields
from traffic.fields import MARKER, parse


def body(opcode, payload):
    return struct.pack("<H", opcode) + payload


def scan_section(status, key=0x13579BDF, length=4):
    """The inverse of fields.process_scan_status."""
    x = status ^ 0xA0A0B0B0
    value = ((x + 0xD9B30E6C - key + 0xD9B30E6B - (key >> 6)) & 0xFFFFFFFF) ^ key
    return struct.pack("<III", key, length ^ key, value)


class CrcTest(unittest.TestCase):
    def test_table_and_checksum(self):
        self.assertEqual(fields.CRC_TABLE[1], 0x04C11DB7)
        self.assertEqual(fields.crc32_msb(b"123456789"), 0x89A1897F)   # CRC-32/CKSUM check 0x765e7680 without its final XOR

    def test_send_counter_inverts_the_crc(self):
        self.assertEqual(fields.send_counter(fields.crc32_msb(struct.pack("<H", 31 * 7))), 217)

    def test_debug_registers_round_trip(self):
        dr = [0x140001000, 0, 0xDEADBEEF, 0x7FFE0000]
        dr = [v & 0xFFFFFFFF for v in dr]
        self.assertEqual(fields.unscramble_debug_registers(*fields.scramble_debug_registers(dr, 0x89ABCDEF)), dr)


class IntegrityTest(unittest.TestCase):
    def test_s_1b(self):
        b = body(0x1B, struct.pack("<QIIQIBBQQ", 0, 0, 7, 0, 0, 0, 1, 0x111111, 0x222222))
        f = parse("S", 0x1B, b)
        self.assertEqual((f["tag"], f["one"], f["challenge"], f["previous_challenge"]), (7, 1, 0x111111, 0x222222))
        self.assertNotIn("unparsed_hex", f)

    def test_c_9c(self):
        m = struct.pack("<I", MARKER)
        dr = [1, 2, 3, 4]
        payload = (struct.pack("<I", 100) + m + struct.pack("<HQI", 0xBC0F, 0, 0xFFFFA000) + m
                   + struct.pack("<IQI", 5, 0x1000, 2) + b"\xaa\xbb" + struct.pack("<Q", 0x1000 ^ fields.GOLDEN) + m
                   + bytes(8) + m
                   + struct.pack("<5I", *fields.scramble_debug_registers(dr, 0x55AA55AA)) + struct.pack("<II", 6, 7) + m
                   + scan_section(1) + m
                   + struct.pack("<BQQIIII", 1, 0x333333, 0x444444, 0x55555555, 92, 92, 0))
        f = parse("C", 0x9C, body(0x9C, payload))
        self.assertEqual(f["debug_registers"], [1, 2, 3, 4, 6, 7])
        self.assertEqual((f["copy_hex"], f["copy_address_echo"]), ("aabb", 0x1000))
        self.assertEqual((f["process_scan_length"], f["process_scan_status"]), (4, 1))
        self.assertEqual((f["client_challenge"], f["input_events_a"], f["counter_42ec"]), (0x444444, 92, 0))
        self.assertNotIn("unparsed_hex", f)

    def test_c_9c_without_marker_is_an_error(self):
        self.assertIn("parse_error", parse("C", 0x9C, body(0x9C, struct.pack("<II", 100, 1))))

    def test_c_70_subtypes(self):
        scrambled = struct.pack("<5I", *fields.scramble_debug_registers([0, 0, 0, 0], 99)) + bytes(8)
        a = fields.crc32_msb(struct.pack("<H", 62))
        one = parse("C", 0x70, body(0x70, b"\x01" + struct.pack("<IIII", 100, a, a, 2) + b"\x00" + scrambled))
        self.assertEqual((one["send_counter"], one["debug_registers"]), (62, [0] * 6))
        two = parse("C", 0x70, body(0x70, b"\x02" + struct.pack("<IIII", 100, 0, 0, 2) + scrambled))
        self.assertEqual(len(body(0x70, b"\x02" + struct.pack("<IIII", 100, 0, 0, 2) + scrambled)), 47)
        self.assertNotIn("unparsed_hex", two)
        self.assertEqual(parse("C", 0x70, body(0x70, b"\x04" + struct.pack("<I", 100)))["value"], 100)
        self.assertEqual(parse("C", 0x70, body(0x70, b"\x05" + struct.pack("<II", 6588675, 5152)))["frame_counter"],
                         5152)
        uuid = "00000000-1111-2222-3333-444444444444"
        self.assertEqual(parse("C", 0x70, body(0x70, b"\x0d" + struct.pack("<H", 36) + uuid.encode() + b"\0"))["uuid"],
                         uuid)

    def test_chain_407_381(self):
        s = parse("S", 0x381, body(0x381, struct.pack("<IIII", 0x123456, 0, 0x2B3C4D, 0)))
        c = parse("C", 0x407, body(0x407, struct.pack("<IH", 0x654321, 0x3C4D) + bytes(5) + bytes([0x2B, 0, 0x9C])
                                   + bytes(4)))
        self.assertEqual(c["previous_v2_low24"], s["v2"] & 0xFFFFFF)
        self.assertNotIn("unparsed_hex", c)


class AnswersAndWorldTest(unittest.TestCase):
    def test_resolution_and_value_check(self):
        f = parse("C", 0x161, body(0x161, struct.pack("<HII", 3, 13660768, 13660768)))
        self.assertEqual((f["mode_name"], f["width"], f["height"], f["second_matches"]), ("1366x768", 1366, 768, True))
        self.assertEqual(parse("S", 0x165, body(0x165, struct.pack("<i", -1)))["value"], -1)
        self.assertEqual(parse("C", 0x177, body(0x177, struct.pack("<i", -2)))["value"], -2)
        self.assertEqual(parse("C", 0xBA, body(0xBA, b"\x01"))["input"], 1)

    def test_key_bindings(self):
        preset = b"\x00" + b"".join(struct.pack("<BI", 4, i if i < 3 else 0) for i in range(89))
        f = parse("S", 0x5F5, body(0x5F5, preset * 3 + b"\x01" + b"\x00"))
        self.assertEqual(f["presets"][3], "default")
        self.assertEqual(f["bound_keys"][:3], [89, 89, 89])
        self.assertEqual(len(body(0x5F5, preset * 3 + b"\x01" + b"\x00")), 1342)
        self.assertNotIn("quick_slots", f)

    def test_user_effect_and_drop_leave(self):
        f = parse("S", 0x2B9, body(0x2B9, struct.pack("<IBIII", 7, 1, 4201001, 33, 10)))
        self.assertEqual((f["skill_id"], f["skill_level"]), (4201001, 10))
        self.assertEqual(parse("S", 0x2B9, body(0x2B9, struct.pack("<IB", 7, 15))), {"character_id": 7, "effect": 15})
        self.assertEqual(parse("S", 0x472, body(0x472, struct.pack("<IBI", 0x15A, 2, 9)))["picker_id"], 9)
        self.assertNotIn("picker_id", parse("S", 0x472, body(0x472, struct.pack("<IB", 0x15A, 0))))


class ReportsTest(unittest.TestCase):
    def test_event_report_kinds_and_decoy(self):
        f = parse("C", 0x1EF, body(0x1EF, struct.pack("<II", 1, 1) + struct.pack("<III", 1000, 1, 0x66666666)))
        self.assertEqual(f["skills"], [(1000, 1, 0x66666666)])
        self.assertEqual(parse("C", 0x1EF, body(0x1EF, struct.pack("<I", 0x20) + bytes(12)))["values"], [0, 0, 0])
        for opcode in fields.DECOY_OPCODES:
            self.assertTrue(parse("C", opcode, body(opcode, struct.pack("<III", 0x65, 9, 14)))["decoy"])
        self.assertFalse(parse("C", 0x1F9, body(0x1F9, struct.pack("<III", 0x65, 10, 14)))["decoy"])
        real = parse("C", 0x1F9, body(0x1F9, struct.pack("<IQI", 0x3F, 1, 1) + struct.pack("<6Q", *range(6))))
        self.assertEqual(real["entries"], [list(range(6))])
        unknown = parse("C", 0x1EF, body(0x1EF, struct.pack("<I", 0x72) + bytes(5)))
        self.assertEqual(unknown["unparsed_hex"], "0000000000")

    def test_counters_and_skill_check(self):
        f = parse("C", 0x13F, body(0x13F, b"\x00" + struct.pack("<IIIIII", 1, 0xE1, 1, 2, 3, 0) + struct.pack("<I", 0)))
        self.assertEqual(f["built"], [(0xE1, [(2, 3)])])
        self.assertEqual(len(body(0x13F, b"\x00" + bytes(8))), 11)
        f = parse("C", 0x1A7, body(0x1A7, struct.pack("<IIIIIII", 1, 4001003, 1, 1, 4001003, 1, 0x77777777)))
        self.assertEqual(f["checked"], [(4001003, 1, 0x77777777)])

    def test_small_reports(self):
        self.assertEqual(parse("C", 0xBE, body(0xBE, struct.pack("<IIII", 1, 60, 57, 8)))["active_minutes"], 57)
        self.assertEqual(parse("C", 0x1C3, body(0x1C3, struct.pack("<IH", 5, 3) + b"abc"))["character_name"], "abc")
        md5 = "0" * 32
        f = parse("C", 0x1F3, body(0x1F3, struct.pack("<IIIH", 4, 1, 0x01020304, 32) + md5.encode()))
        self.assertEqual(f["sequences"], [(0x01020304, md5)])

    def test_sign_in(self):
        payload = struct.pack("<II", 80, 2) + b"\x01\x01\x00\x01" + b"\x02" + struct.pack("<IBIB", 73, 1, 52, 0)
        self.assertEqual(parse("S", 0x44, body(0x44, payload))["load"], [(73, 1), (52, 0)])
        self.assertEqual(parse("C", 0x75, body(0x75, struct.pack("<BIBB", 0, 80, 0, 0)))["world_id"], 80)

    def test_short_body_and_unknown_type(self):
        self.assertIn("parse_error", parse("S", 0x381, body(0x381, b"\x01")))
        self.assertIsNone(parse("S", 0x1, body(0x1, b"")))
        self.assertTrue(all(doc.startswith("docs/") for doc in fields.DOCS.values()))


if __name__ == "__main__":
    unittest.main()
