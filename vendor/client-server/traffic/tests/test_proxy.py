from __future__ import annotations

import asyncio
import json
import struct
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from traffic.policy import load_policy
from traffic.proxy import GameProxy, Recorder, decode_recording, report
from traffic.stream import ConnectionDecoder
from traffic.transport import (
    OPCODE_TABLE_KEY,
    RECV_MASK,
    client_opcode,
    decrypt_body,
    decrypt_recv,
    get_new_iv,
    high_short,
    opcode_table,
)

from traffic.tests.helpers import game_body, seal_frame

CLIENT_IV = bytes.fromhex("6318e661")
SERVER_IV = bytes.fromhex("781d7b45")
# Same layout as the real channel handshakes (2026-11-14): 19 bytes, the IVs at 9 and 13.
HANDSHAKE = struct.pack("<H", 19) + bytes.fromhex("010001000000010030") + CLIENT_IV + SERVER_IV + b"\x01\x04"


def sealed(bodies, iv=CLIENT_IV):
    out = b""
    for body in bodies:
        out += seal_frame(body, iv)
        iv = get_new_iv(iv)
    return out


def server_sealed(bodies, iv=SERVER_IV, aes=False):
    out = b""
    for body in bodies:
        # decrypt_body is its own inverse (XOR keystream); subtraction is undone by adding iv[0]
        cipher = decrypt_body(iv, body) if aes else bytes((b + iv[0]) & 0xFF for b in body)
        w0 = high_short(iv) ^ RECV_MASK
        out += struct.pack("<HH", w0, w0 ^ len(body)) + cipher
        iv = get_new_iv(iv)
    return out


def table_message(wires, padding=b""):
    text = ("|".join(str(v) for v in [len(wires), *wires])).encode() + b"\0" + padding
    text += b"\0" * (-len(text) % 8)
    encryptor = Cipher(TripleDES(OPCODE_TABLE_KEY + OPCODE_TABLE_KEY[:8]), modes.ECB()).encryptor()
    blob = encryptor.update(text) + encryptor.finalize()
    return struct.pack("<HI", 0x32, len(blob)) + blob


BODIES = [game_body(0x1234 + n, {2: bytes([n]) * 4}, length=12 + n) for n in range(6)]
REPLIES = [game_body(0x39 + n, {2: b"All"}, length=10 + n) for n in range(4)]


def messages(records, direction):
    return [r for r in records if r["kind"] == "message" and r["direction"] == direction]


class TransportFromClientCodeTest(unittest.TestCase):
    def test_the_keystream_starts_again_after_1456_then_every_1460_bytes(self):
        zeros = bytes(4500)
        stream = decrypt_body(CLIENT_IV, zeros)
        self.assertEqual(stream[1456:1456 + 1456], decrypt_body(CLIENT_IV, bytes(1456)))
        self.assertEqual(stream[2916:2916 + 32], stream[1456:1456 + 32])
        self.assertNotEqual(stream[1456:1488], stream[1488:1520])

    def test_channel_replies_subtract_iv0(self):
        self.assertEqual(decrypt_recv(bytes([0x78, 0, 0, 0]), bytes([0x78, 0xD9, 0x77])),
                         bytes([0, 0x61, 0xFF]))

    def test_opcode_table_maps_wire_values_to_0xc7_onwards(self):
        table = opcode_table(table_message([5100, 31549, 6000]))
        self.assertEqual(table, {5100: 0xC7, 31549: 0xC8, 6000: 0xC9})
        self.assertEqual(client_opcode(0x70, table), (0x70, "unmapped_range"))
        self.assertEqual(client_opcode(31549, table), (0xC8, "connection_table"))
        self.assertEqual(client_opcode(7777, table), (None, "not_in_table"))
        self.assertEqual(client_opcode(31549, None), (None, "no_table"))
        self.assertIsNone(opcode_table(game_body(0x32, length=40)))

    def test_opcode_table_ignores_bytes_after_its_end(self):
        # seen live: "...|38869\0!'\x10\0\0"
        self.assertEqual(opcode_table(table_message([5100, 6000], padding=b"!'\x10")), {5100: 0xC7, 6000: 0xC8})


class ConnectionDecoderTest(unittest.TestCase):
    def run_connection(self, server_parts, client_parts, step=None, decoder=None):
        decoder = decoder or ConnectionDecoder()
        out = []
        for direction, data in [*(("server_to_client", p) for p in server_parts),
                                *(("client_to_server", p) for p in client_parts)]:
            chunks = [data[i:i + step] for i in range(0, len(data), step)] if step else [data]
            for number, chunk in enumerate(chunks):
                out += decoder.feed(direction, chunk, number)
        return decoder, out

    def test_handshake_decrypts_both_directions_split_and_combined(self):
        for step in (1, 5, 17, None):
            decoder, out = self.run_connection([HANDSHAKE + server_sealed(REPLIES)], [sealed(BODIES)], step)
            self.assertEqual([bytes.fromhex(m["body_hex"]) for m in messages(out, "client_to_server")], BODIES)
            replies = messages(out, "server_to_client")
            self.assertEqual([bytes.fromhex(m["body_hex"]) for m in replies], REPLIES)
            self.assertEqual({m["cipher"] for m in replies}, {"subtract_iv0"})
            self.assertEqual(replies[0]["opcode"], "0x39")
            self.assertEqual(out[0]["kind"], "handshake")

    def test_login_server_replies_use_aes(self):
        decoder, out = self.run_connection([HANDSHAKE + server_sealed(REPLIES, aes=True)], [])
        self.assertEqual([bytes.fromhex(m["body_hex"]) for m in messages(out, "server_to_client")], REPLIES)
        self.assertEqual(decoder.server.cipher, "aes_ofb")

    def test_the_opcode_table_names_client_messages(self):
        wires = [5000 + n for n in range(10)]
        table = table_message(wires)
        bodies = [game_body(5003, length=8), game_body(0x70, length=8)]
        decoder, out = self.run_connection([HANDSHAKE + server_sealed([REPLIES[0], table, REPLIES[1]])],
                                           [sealed(bodies)])
        self.assertEqual([r["kind"] for r in out if r["kind"] == "opcode_table"], ["opcode_table"])
        sent = messages(out, "client_to_server")
        self.assertEqual([(m["wire_opcode"], m["opcode"]) for m in sent],
                         [("0x138b", "0xca"), ("0x0070", "0x70")])

    def test_login_server_client_opcodes_are_not_renamed(self):
        # the login server's 52-byte handshake (IVs at the same windows), and no opcode table ever comes
        login = struct.pack("<H", 52) + bytes.fromhex("010001000000010030") + CLIENT_IV + SERVER_IV + bytes(35)
        decoder, out = self.run_connection([login + server_sealed(REPLIES[:2])],
                                           [sealed([game_body(0x2e7, length=6), game_body(0x70, length=8)])])
        sent = messages(out, "client_to_server")
        self.assertEqual([(m["opcode"], m["opcode_source"]) for m in sent],
                         [("0x2e7", "login_server_not_renamed"), ("0x70", "unmapped_range")])

    def test_live_decoding_never_searches_without_a_handshake(self):
        decoder, out = self.run_connection([], [sealed(BODIES)])
        self.assertEqual(messages(out, "client_to_server"), [])
        self.assertEqual(decoder.client.status, "no_key")

    def test_offline_header_search_decrypts_a_mid_connection_stream(self):
        decoder, out = self.run_connection([], [sealed(BODIES)], decoder=ConnectionDecoder(header_search=True))
        self.assertEqual(decoder.client.key_source, "header_search")
        self.assertEqual(len(messages(out, "client_to_server")), len(BODIES))

    def test_a_frame_length_below_two_ends_decoding(self):
        decoder, out = self.run_connection([HANDSHAKE], [b"\x01\x00\x01\x00rest"])
        self.assertEqual(decoder.client.status, "not_game_framing")

    def test_the_8913_ping_text_gives_no_messages(self):
        decoder, out = self.run_connection([], [b"ping\n" * 220])   # reads as one 3614-byte frame
        self.assertEqual(messages(out, "client_to_server"), [])

    def test_tls_is_recorded_with_its_server_name(self):
        from traffic.tests.helpers import tls_client_hello

        decoder, out = self.run_connection([], [tls_client_hello("api.nexon.test")])
        self.assertEqual([r for r in out if r["kind"] == "tls_client_hello"][0]["sni"], "api.nexon.test")
        self.assertEqual(decoder.client.status, "tls")

    def test_a_header_off_the_iv_chain_stops_decryption(self):
        wire = bytearray(sealed(BODIES))
        second = 4 + len(BODIES[0])
        wire[second] ^= 0xFF   # w0 of frame 1; keep the length by changing w1 the same way
        wire[second + 2] ^= 0xFF
        decoder, out = self.run_connection([HANDSHAKE], [bytes(wire)])
        self.assertEqual([r["kind"] for r in out], ["handshake", "message", "decode_notice"])
        self.assertEqual(decoder.client.status, "iv_desync")


class ProxyEndToEndTest(unittest.TestCase):
    """A fake game server and client on loopback, the proxy between them."""

    def run_session(self, policy_rules=None):
        tmp = Path(tempfile.mkdtemp())
        policy = None
        if policy_rules is not None:
            (tmp / "policy.json").write_text(json.dumps({"default": "allow", "rules": policy_rules}))
            policy = load_policy(tmp / "policy.json")
        received = bytearray()

        async def game_server(reader, writer):
            writer.write(HANDSHAKE)
            await writer.drain()
            while data := await reader.read(4096):
                received.extend(data)
            writer.write(server_sealed(REPLIES))
            await writer.drain()
            writer.close()

        async def main():
            server = await asyncio.start_server(game_server, "127.0.0.1", 0)
            address = server.sockets[0].getsockname()[:2]
            recorder = Recorder(tmp / "proxy.jsonl")
            proxy = GameProxy(recorder, policy=policy, resolve=lambda sock: address,
                              owner=lambda client: {"pid": 7, "name": "MapleStory.exe"})
            listener = await proxy.serve("127.0.0.1", 0)
            reader, writer = await asyncio.open_connection(*listener.sockets[0].getsockname()[:2])
            got = b""
            try:
                got = await reader.readexactly(len(HANDSHAKE))
                writer.write(sealed(BODIES))
                await writer.drain()
                writer.write_eof()
                got += await reader.read()
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            writer.close()
            await asyncio.sleep(0.05)
            listener.close()
            server.close()
            recorder.close()
            return got

        got = asyncio.run(main())
        records = [json.loads(line) for line in (tmp / "proxy.jsonl").read_text().splitlines()]
        return got, bytes(received), records, tmp / "proxy.jsonl"

    def test_bytes_pass_unchanged_and_both_directions_are_decrypted(self):
        got, received, records, path = self.run_session()
        self.assertEqual(got, HANDSHAKE + server_sealed(REPLIES))
        self.assertEqual(received, sealed(BODIES))
        self.assertEqual([bytes.fromhex(m["body_hex"]) for m in messages(records, "client_to_server")], BODIES)
        self.assertEqual([bytes.fromhex(m["body_hex"]) for m in messages(records, "server_to_client")],
                         REPLIES)
        opened = next(r for r in records if r["kind"] == "connection_open")
        self.assertEqual(opened["process"]["name"], "MapleStory.exe")
        closed = next(r for r in records if r["kind"] == "connection_close")
        self.assertEqual(closed["bytes"], {"client_to_server": len(received),
                                           "server_to_client": len(got)})
        sent = b"".join(bytes.fromhex(r["hex"]) for r in records
                        if r["kind"] == "data" and r["direction"] == "client_to_server")
        self.assertEqual(sent, received)
        text = report(path)
        self.assertIn("client_to_server: 6 messages, decrypting, key handshake, cipher aes_ofb", text)
        self.assertIn("server_to_client: 4 messages, decrypting, key handshake, cipher subtract_iv0", text)
        again = path.with_name("again.jsonl")
        decode_recording(path, again)
        kept = lambda f: [(r["direction"], r["body_hex"]) for r in map(json.loads, f.read_text().splitlines())
                          if r["kind"] == "message"]
        self.assertEqual(kept(again), kept(path))

    def test_a_drop_rule_refuses_the_connection(self):
        got, received, records, _ = self.run_session([
            {"id": "no-game", "action": "drop", "match": {"process": {"name": "MapleStory.exe"}}},
        ])
        self.assertEqual((got, received), (b"", b""))
        refused = next(r for r in records if r["kind"] == "connection_refused")
        self.assertEqual(refused["decision"]["rule_id"], "no-game")
        self.assertFalse(any(r["kind"] == "connection_open" for r in records))

    def test_a_message_rule_is_recorded_but_never_enforced(self):
        _, received, records, _ = self.run_session([
            {"id": "big", "action": "drop", "match": {"protocol": "maplestory_game",
                                                      "size": {"min": 15}}},
        ])
        self.assertEqual(received, sealed(BODIES))
        decided = [r for r in messages(records, "client_to_server") if "decision" in r]
        self.assertEqual([r["length"] for r in decided], [15, 16, 17])
        self.assertEqual({r["decision"]["enforced"] for r in decided}, {False})


if __name__ == "__main__":
    unittest.main()


class NflogCaptureTest(unittest.TestCase):
    def test_the_other_packets_pcap_is_readable(self):
        from traffic.pcap import read_packets
        from traffic.tests.helpers import ipv4_udp

        packet = ipv4_udp("172.16.1.215", "222.122.222.69", 50000, 9000, b"hello")
        tlvs = struct.pack("<HH", 8, 1) + bytes(4)                      # a non-payload TLV first
        tlvs += struct.pack("<HH", 4 + len(packet), 9) + packet
        tlvs += bytes(-len(tlvs) % 4)
        record = bytes([2, 0, 0, 7]) + tlvs
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "other.pcap"
            path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 239)
                             + struct.pack("<IIII", 1_700_000_000, 0, len(record), len(record)) + record)
            packets = read_packets([path]).packets
        self.assertEqual([(p.protocol, p.dst, p.dport, p.payload) for p in packets],
                         [("udp", "222.122.222.69", 9000, b"hello")])


class ProtocolNamesTest(unittest.TestCase):
    def test_names_need_the_direction_and_the_real_opcode(self):
        from traffic.protocol import name_of

        self.assertEqual(name_of("client_to_server", 0x181), ("mini_room_action", "confirmed"))
        self.assertEqual(name_of("server_to_client", 0x181), (None, None))
        self.assertEqual(name_of("client_to_server", None), (None, None))

    def test_shifted_text_is_revealed(self):
        from traffic.protocol import reveal_shifted_text

        self.assertEqual(reveal_shifted_text(bytes(b << 1 for b in b"2026|Zrie") + b"\x01"), "2026|Zrie.")


class ProxyStopTest(unittest.TestCase):
    """Stopping never cuts an open game connection (2026-11-15 13:21: that dropped the game to its login screen)."""

    def test_a_stop_lets_open_connections_finish_and_takes_no_new_ones(self):
        async def main():
            async def echo(reader, writer):
                while data := await reader.read(100):
                    writer.write(data)
                    await writer.drain()
                writer.close()

            server = await asyncio.start_server(echo, "127.0.0.1", 0)
            address = server.sockets[0].getsockname()[:2]
            tmp = Path(tempfile.mkdtemp())
            recorder = Recorder(tmp / "proxy.jsonl")
            proxy = GameProxy(recorder, resolve=lambda sock: address, owner=lambda client: {})
            stop = asyncio.Event()
            said = []
            runner = asyncio.ensure_future(proxy.serve_until_stopped("127.0.0.1", 0, stop, say=said.append))
            while not said:
                await asyncio.sleep(0.01)
            port = int(said[0].split()[1].rsplit(":", 1)[1]) if ":0 " not in said[0] else None
            return server, recorder, proxy, stop, runner, said

        async def scenario(second_stop):
            server, recorder, proxy, stop, runner, said = await main()
            reader, writer = await asyncio.open_connection(*proxy.listen_address)
            writer.write(b"one")
            self.assertEqual(await reader.readexactly(3), b"one")
            stop.set()
            await asyncio.sleep(0.05)
            writer.write(b"two")                                   # still forwarded after the stop
            self.assertEqual(await reader.readexactly(3), b"two")
            with self.assertRaises(OSError):                       # no new connections
                await asyncio.open_connection(*proxy.listen_address)
            self.assertFalse(runner.done())
            if second_stop:
                stop.set()
                self.assertEqual(await asyncio.wait_for(runner, 2), 1)   # one connection left to cut
            else:
                writer.close()
                self.assertEqual(await asyncio.wait_for(runner, 2), 0)
            server.close()
            recorder.close()
            return said

        said = asyncio.run(scenario(second_stop=False))
        self.assertTrue(any(text.startswith("DRAINING 1") for text in said))
        asyncio.run(scenario(second_stop=True))


class FailSafeTest(unittest.TestCase):
    def test_a_decoder_error_stops_decoding_not_forwarding(self):
        import traffic.proxy as proxy_module

        class Broken(ConnectionDecoder):
            def feed(self, *args):
                raise RuntimeError("boom")

        original = proxy_module.ConnectionDecoder
        proxy_module.ConnectionDecoder = Broken
        try:
            got, received, records, _ = ProxyEndToEndTest.run_session(self)
        finally:
            proxy_module.ConnectionDecoder = original
        self.assertEqual(got, HANDSHAKE + server_sealed(REPLIES))
        self.assertEqual(received, sealed(BODIES))
        notices = [r for r in records if r["kind"] == "decode_notice"]
        self.assertEqual({r["status"] for r in notices}, {"decoder_error"})
        self.assertTrue(any(r["kind"] == "connection_close" for r in records))

    def test_a_failed_recording_write_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            recorder = Recorder(Path(tmp) / "r.jsonl")
            recorder.handle.close()   # every later write fails like a full disk
            recorder.write({"kind": "data"})
            recorder.write({"kind": "data"})
            self.assertTrue(recorder.failed)

    def test_two_fitting_handshake_windows_wait_for_the_second_frame(self):
        decoder = ConnectionDecoder()
        decoder.feed("server_to_client", HANDSHAKE, 0)
        # a second window with the client IV's high half: both fit frame 0's header, only one fits frame 1
        decoder.handshake += bytes([0x11, 0x22]) + CLIENT_IV[2:]
        out = decoder.feed("client_to_server", sealed(BODIES), 1)
        self.assertEqual(decoder.client.key_source, "handshake")
        self.assertEqual(len(messages(out, "client_to_server")), len(BODIES))


class ClientOriginsLayoutTest(unittest.TestCase):
    def test_fixed_length_counts_helpers_and_byte_runs(self):
        import importlib.util

        path = Path(__file__).resolve().parents[2] / "analysis" / "client-origins.py"
        spec = importlib.util.spec_from_file_location("client_origins", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fields = ["u8", {"via": "0x2a9ec10", "fields": ["u32"]}, "u32", "bytes[4]"]
        self.assertEqual(module.fixed_size(fields), 2 + 1 + 4 + 4 + 4)
        self.assertIsNone(module.fixed_size(["u32", "str"]))
        self.assertEqual(module.flat(fields), ["u8", "<0x2a9ec10:", "u32", ">", "u32", "bytes[4]"])


class SendersReportTest(unittest.TestCase):
    def test_sends_are_grouped_by_server_and_module(self):
        import contextlib
        import io
        import sys as _sys

        log = (
            "16:16:05.616 pid=7 MapleStory.exe   network  audit flags=0x1008 rule=10001 gen=1 status=0x0 "
            "value=0x3b send tcp 166.117.144.41:8558 socket:[1] #1 len=59 caller=MapleStory.exe+0x4c0aa61 data=00\n"
            "16:16:06.000 pid=7 MapleStory.exe   network  audit flags=0x1008 rule=10001 gen=1 status=0x0 "
            "value=0x10 send tcp 13.158.249.224:443 socket:[2] #1 len=16 caller=grap-communicator64.aes+0x10 data=00\n"
            "16:16:07.000 pid=8 nexon_client.exe network  audit flags=0x1008 rule=10001 gen=1 status=0x0 "
            "value=0x5 send tcp 35.165.11.5:8913 socket:[3] #1 len=5 data=00\n")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "senders.log"
            path.write_text(log)
            import importlib.util

            script = Path(__file__).resolve().parents[2] / "analysis" / "senders-report.py"
            spec = importlib.util.spec_from_file_location("senders_report", script)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            out = io.StringIO()
            argv, _sys.argv = _sys.argv, ["senders-report.py", str(path)]
            try:
                with contextlib.redirect_stdout(out):
                    module.main()
            finally:
                _sys.argv = argv
        text = out.getvalue()
        self.assertIn("game server :8558/tcp", text)
        self.assertIn("MapleStory.exe .themida", text)
        self.assertIn("grap-communicator64.aes", text)
        self.assertIn("no module (code outside every loaded module)", text)


class PurposeTest(unittest.TestCase):
    def test_every_named_message_has_a_purpose_and_groups_do_not_overlap(self):
        from traffic.protocol import NAMES, PURPOSE, purpose_of

        self.assertEqual([k for k in NAMES if k not in PURPOSE], [])
        self.assertEqual(purpose_of("server_to_client", 0x452)[0], "world")
        self.assertEqual(purpose_of("client_to_server", 0x76)[0], "identity")
        self.assertEqual(purpose_of("client_to_server", 0x999), (None, None))

    def test_decoded_messages_carry_their_purpose(self):
        decoder, out = ConnectionDecoderTest.run_connection(self, [HANDSHAKE + server_sealed(REPLIES)], [])
        self.assertTrue(all("purpose" in m for m in messages(out, "server_to_client")))
