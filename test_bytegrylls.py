#!/usr/bin/env python3
"""
Test suite for ByteGrylls.py.

Uses only the standard library (unittest, unittest.mock) to match the project's
zero-dependency philosophy. Run with:

    python -m unittest test_bytegrylls -v

Raw-socket paths (ping/traceroute) are exercised by monkeypatching socket.socket
and select.select inside the ByteGrylls module, so these tests need no root/
Administrator privileges and never touch the real network.
"""

import contextlib
import io
import os
import socket
import struct
import threading
import time
import unittest
from unittest import mock

import ByteGrylls as bg
from ByteGrylls import ByteGrylls, _valid_port


def _icmp_header(icmp_type, icmp_id, seq, checksum=0):
    return struct.pack("bbHHh", icmp_type, 0, checksum, icmp_id, seq)


def _icmp_payload():
    return struct.pack("d", time.time())


def build_echo_reply(icmp_type, icmp_id, seq, ipv6=False):
    """A wire-format Echo Reply (or any other simple ICMP message) as raw sockets deliver it."""
    packet = _icmp_header(icmp_type, icmp_id, seq) + _icmp_payload()
    if ipv6:
        return packet
    return b"\x00" * 20 + packet  # fake 20-byte outer IPv4 header, content unused by the parser


def build_time_exceeded(orig_id, orig_seq, icmp_type=11, ipv6=False):
    """A Time Exceeded / Destination Unreachable message quoting our original echo request."""
    if ipv6:
        inner_ip_header = b"\x00" * 40
    else:
        inner_ip_header = b"\x45" + b"\x00" * 19  # version=4, IHL=5 (20 bytes), rest unused
    quoted_request = _icmp_header(8, orig_id, orig_seq)
    outer_header = struct.pack("bb", icmp_type, 0) + b"\x00" * 6
    body = outer_header + inner_ip_header + quoted_request
    if ipv6:
        return body
    return b"\x00" * 20 + body


class FakeIcmpSocket:
    """Stand-in for a raw ICMP socket: serves canned packets, records what was sent."""

    def __init__(self, packets=None):
        self._packets = list(packets or [])
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))
        return len(data)

    def recvfrom(self, bufsize):
        if not self._packets:
            raise BlockingIOError("no data queued")
        return self._packets.pop(0)

    def has_pending(self):
        return bool(self._packets)

    def setsockopt(self, *args, **kwargs):
        pass

    def bind(self, *args, **kwargs):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


def fake_select_for(*fake_sockets):
    """select.select() replacement: instantly 'ready' if the fake socket has a queued packet."""
    def _select(rlist, wlist, xlist, timeout):
        for s in rlist:
            if s in fake_sockets and s.has_pending():
                return ([s], [], [])
        return ([], [], [])
    return _select


class PairedSocketFactory:
    """socket.socket() replacement for traceroute(): pairs its two calls-per-hop to one fake."""

    def __init__(self, per_hop_packets):
        self._queues = list(per_hop_packets)
        self._call_count = 0
        self._current = None
        self.created = []

    def __call__(self, *args, **kwargs):
        if self._call_count % 2 == 0:
            packets = self._queues.pop(0) if self._queues else []
            self._current = FakeIcmpSocket(packets)
            self.created.append(self._current)
        self._call_count += 1
        return self._current


@contextlib.contextmanager
def captured_stdout():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        yield buf


class TestChecksum(unittest.TestCase):
    def test_known_vector(self):
        # RFC 1071 worked example: 0x0001 0xf203 0xf4f5 0xf6f7 -> checksum 0x220d
        data = bytes.fromhex("0001f203f4f5f6f7")
        self.assertEqual(ByteGrylls._checksum(data), 0x220D)

    def test_self_verifying(self):
        # Folding the computed checksum back into the data and recomputing must yield 0.
        data = b"\x08\x00\x00\x00\x12\x34\x00\x01hello!!!"
        chksum = ByteGrylls._checksum(data)
        with_checksum = data[:2] + struct.pack("<H", socket.htons(chksum)) + data[4:]
        self.assertEqual(ByteGrylls._checksum(with_checksum), 0)


class TestValidPort(unittest.TestCase):
    def test_accepts_boundary_values(self):
        self.assertEqual(_valid_port("1"), 1)
        self.assertEqual(_valid_port("65535"), 65535)
        self.assertEqual(_valid_port("8080"), 8080)

    def test_rejects_out_of_range(self):
        for bad in ("0", "-1", "65536", "999999"):
            with self.assertRaises(Exception):
                _valid_port(bad)

    def test_rejects_non_integer(self):
        with self.assertRaises(Exception):
            _valid_port("not-a-port")


class TestParseDnsName(unittest.TestCase):
    def test_uncompressed_name(self):
        data = b"\x03www\x07example\x03com\x00TAIL"
        name, offset = ByteGrylls._parse_dns_name(data, 0)
        self.assertEqual(name, "www.example.com")
        self.assertEqual(offset, len(data) - 4)  # stops right before "TAIL"

    def test_compressed_pointer(self):
        # Question section holds the full name at offset 12; an answer name at offset 30
        # is just a 2-byte pointer back to it.
        base = b"\x00" * 12 + b"\x03www\x07example\x03com\x00"
        pointer = struct.pack("!H", 0xC000 | 12)
        data = base + pointer + b"REST"
        name, offset = ByteGrylls._parse_dns_name(data, len(base))
        self.assertEqual(name, "www.example.com")
        self.assertEqual(offset, len(base) + 2)  # advances only past the 2-byte pointer


class TestDnsQuery(unittest.TestCase):
    """Exercises dns_query() end-to-end via a mocked UDP socket, so no real network is touched."""

    TXN_ID = b"\x12\x34"  # dns_query() hardcodes transaction_id = 0x1234

    def _run_query(self, response_bytes, record_type="A"):
        fake = mock.Mock()
        fake.recvfrom.return_value = (response_bytes, ("8.8.8.8", 53))
        fake.__enter__ = mock.Mock(return_value=fake)
        fake.__exit__ = mock.Mock(return_value=False)
        with mock.patch("ByteGrylls.socket.socket", return_value=fake):
            with captured_stdout() as out:
                result = ByteGrylls.dns_query("example.com", record_type=record_type)
        return result, out.getvalue()

    def _rr(self, name_ptr_offset, rtype, rdata, ttl=60):
        return (
            struct.pack("!H", 0xC000 | name_ptr_offset)
            + struct.pack("!HHIH", rtype, 1, ttl, len(rdata))
            + rdata
        )

    def _header_and_question(self, ancount):
        header = self.TXN_ID + struct.pack("!HHHHH", 0x8180, 1, ancount, 0, 0)
        qname = b"\x07example\x03com\x00"
        question = qname + struct.pack("!H", 1) + struct.pack("!H", 1)
        return header + question, 12  # question name starts at offset 12

    def test_resolves_simple_a_record(self):
        base, qoffset = self._header_and_question(ancount=1)
        response = base + self._rr(qoffset, rtype=1, rdata=socket.inet_aton("93.184.216.34"))
        result, output = self._run_query(response)
        self.assertEqual(result, "93.184.216.34")
        self.assertIn("Resolved", output)

    def test_skips_opt_record_before_a_record(self):
        # This is the exact bug scenario: an EDNS0 OPT pseudo-record (class != IN, no fixed
        # meaning for the "last 4 bytes" of the packet) precedes the real A record.
        base, qoffset = self._header_and_question(ancount=2)
        opt_rr = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)  # root name + OPT (type 41)
        a_rr = self._rr(qoffset, rtype=1, rdata=socket.inet_aton("192.0.2.7"))
        response = base + opt_rr + a_rr
        result, _ = self._run_query(response)
        self.assertEqual(result, "192.0.2.7")

    def test_follows_cname_to_a_record(self):
        base, qoffset = self._header_and_question(ancount=2)
        cname_target = b"\x03cdn\x07example\x03com\x00"
        cname_rr = (
            struct.pack("!H", 0xC000 | qoffset)
            + struct.pack("!HHIH", 5, 1, 60, len(cname_target))
            + cname_target
        )
        # The A record's owner name points at the CNAME's target, deep inside the packet.
        cname_target_offset = len(base) + 2 + 10
        a_rr = self._rr(cname_target_offset, rtype=1, rdata=socket.inet_aton("192.0.2.8"))
        response = base + cname_rr + a_rr
        result, _ = self._run_query(response)
        self.assertEqual(result, "192.0.2.8")

    def test_resolves_aaaa_record(self):
        base, qoffset = self._header_and_question(ancount=1)
        rdata = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        response = base + self._rr(qoffset, rtype=28, rdata=rdata)
        result, _ = self._run_query(response, record_type="AAAA")
        self.assertEqual(result, "2001:db8::1")

    def test_zero_answers_returns_none(self):
        base, _ = self._header_and_question(ancount=0)
        result, output = self._run_query(base)
        self.assertIsNone(result)
        self.assertIn("0 A-records", output)

    def test_mismatched_transaction_id_rejected(self):
        response = b"\xff\xff" + struct.pack("!HHHHH", 0x8180, 0, 0, 0, 0)
        result, output = self._run_query(response)
        self.assertIsNone(result)
        self.assertIn("did not match the query", output)


class TestResolve(unittest.TestCase):
    def test_prefers_ipv4_by_default(self):
        with mock.patch("ByteGrylls.socket.getaddrinfo") as mocked:
            mocked.return_value = [(socket.AF_INET, None, None, None, ("203.0.113.1", 0))]
            ip, family = ByteGrylls._resolve("example.com")
        self.assertEqual((ip, family), ("203.0.113.1", socket.AF_INET))
        self.assertEqual(mocked.call_args_list[0].args[2], socket.AF_INET)

    def test_falls_back_to_ipv6_when_no_a_record(self):
        def side_effect(host, port, family):
            if family == socket.AF_INET:
                raise socket.gaierror("no A record")
            return [(socket.AF_INET6, None, None, None, ("2001:db8::5", 0, 0, 0))]

        with mock.patch("ByteGrylls.socket.getaddrinfo", side_effect=side_effect):
            ip, family = ByteGrylls._resolve("v6only.example.com")
        self.assertEqual((ip, family), ("2001:db8::5", socket.AF_INET6))

    def test_prefer_ipv6_flips_order(self):
        with mock.patch("ByteGrylls.socket.getaddrinfo") as mocked:
            mocked.return_value = [(socket.AF_INET6, None, None, None, ("2001:db8::1", 0, 0, 0))]
            ByteGrylls._resolve("example.com", prefer_ipv6=True)
        self.assertEqual(mocked.call_args_list[0].args[2], socket.AF_INET6)

    def test_raises_when_both_families_fail(self):
        with mock.patch("ByteGrylls.socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            with self.assertRaises(socket.gaierror):
                ByteGrylls._resolve("does-not-exist.invalid")


class TestPingMatching(unittest.TestCase):
    def setUp(self):
        self.icmp_id = os.getpid() & 0xFFFF
        self.tool = ByteGrylls()

    def _run_ping(self, packets, count=1, timeout=2.0):
        fake = FakeIcmpSocket(packets)
        with mock.patch("ByteGrylls.socket.socket", return_value=fake), \
             mock.patch("ByteGrylls.select.select", side_effect=fake_select_for(fake)):
            with captured_stdout() as out:
                self.tool.ping("192.0.2.1", count=count, timeout=timeout)
        return fake, out.getvalue()

    def test_ignores_wrong_id_and_matches_correct_reply(self):
        packets = [
            (build_echo_reply(0, self.icmp_id + 1, 1), ("192.0.2.1", 0)),  # wrong id
            (build_echo_reply(8, self.icmp_id, 1), ("192.0.2.1", 0)),      # echo request, not reply
            (build_echo_reply(0, self.icmp_id, 1), ("192.0.2.1", 0)),      # the real reply
        ]
        _, output = self._run_ping(packets)
        self.assertIn("icmp_seq=1", output)
        self.assertIn("1 packets transmitted, 1 received, 0.0% packet loss", output)

    def test_times_out_with_no_matching_reply(self):
        packets = [(build_echo_reply(0, self.icmp_id + 1, 1), ("192.0.2.1", 0))]
        _, output = self._run_ping(packets, timeout=0.05)
        self.assertIn("Request timeout for icmp_seq 1", output)
        self.assertIn("1 packets transmitted, 0 received, 100.0% packet loss", output)
        self.assertNotIn("rtt min/avg/max", output)

    def test_reuses_one_socket_across_packets(self):
        packets = [
            (build_echo_reply(0, self.icmp_id, 1), ("192.0.2.1", 0)),
            (build_echo_reply(0, self.icmp_id, 2), ("192.0.2.1", 0)),
        ]
        socket_ctor = mock.Mock(return_value=FakeIcmpSocket(packets))
        with mock.patch("ByteGrylls.socket.socket", socket_ctor), \
             mock.patch("ByteGrylls.select.select",
                         side_effect=lambda rlist, w, x, t: (rlist, [], [])):
            with captured_stdout():
                self.tool.ping("192.0.2.1", count=2, timeout=2.0)
        self.assertEqual(socket_ctor.call_count, 1)


class TestTracerouteMatching(unittest.TestCase):
    def setUp(self):
        self.icmp_id = os.getpid() & 0xFFFF
        self.tool = ByteGrylls()

    def _run_traceroute(self, per_hop_packets, max_hops=None, timeout=2.0):
        factory = PairedSocketFactory(per_hop_packets)
        max_hops = max_hops if max_hops is not None else len(per_hop_packets)
        with mock.patch("ByteGrylls.socket.socket", side_effect=factory), \
             mock.patch("ByteGrylls.select.select",
                         side_effect=lambda rlist, w, x, t, f=factory: fake_select_for(f._current)(rlist, w, x, t)):
            with captured_stdout() as out:
                self.tool.traceroute("192.0.2.1", max_hops=max_hops, timeout=timeout)
        return out.getvalue()

    def test_intermediate_hop_ignores_stray_packet_then_matches(self):
        hop1_packets = [
            (build_time_exceeded(self.icmp_id + 1, 1), ("198.51.100.1", 0)),  # wrong id
            (build_time_exceeded(self.icmp_id, 1), ("198.51.100.2", 0)),      # real hop reply
        ]
        hop2_packets = [(build_echo_reply(0, self.icmp_id, 2), ("192.0.2.1", 0))]
        output = self._run_traceroute([hop1_packets, hop2_packets])
        self.assertIn(" 1  198.51.100.2", output)
        self.assertIn(" 2  192.0.2.1", output)
        self.assertIn("Target reached successfully!", output)

    def test_destination_unreachable_is_flagged(self):
        packets = [(build_time_exceeded(self.icmp_id, 1, icmp_type=3), ("198.51.100.9", 0))]
        output = self._run_traceroute([packets])
        self.assertIn("198.51.100.9", output)
        self.assertIn("(Destination Unreachable)", output)

    def test_hop_with_no_reply_prints_timeout(self):
        output = self._run_traceroute([[]], timeout=0.05)
        self.assertIn(" 1  * * * (Request Timed Out)", output)


class TestNetcat(unittest.TestCase):
    def _start_listener(self, port, received):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(3.0)

        def accept_once():
            conn, _ = srv.accept()
            conn.settimeout(3.0)
            received.append(conn.recv(1024))
            conn.close()
            srv.close()

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        return thread

    def test_client_sends_data_to_listener(self):
        port = 0
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()

        received = []
        thread = self._start_listener(port, received)
        time.sleep(0.1)  # let the listener start accepting

        with captured_stdout() as out:
            ok = ByteGrylls.netcat_client("127.0.0.1", port, timeout=2.0, data=b"hello-bytegrylls")
        thread.join(timeout=3.0)

        self.assertTrue(ok)
        self.assertEqual(received, [b"hello-bytegrylls"])
        self.assertIn("Sent 16 bytes", out.getvalue())

    def test_unreachable_port_reports_failure(self):
        # Nothing is listening on this loopback port. Depending on the host's network stack,
        # this surfaces as an immediate refusal or (in some virtualized/sandboxed networks) a
        # timeout - either is a correct "connection failed" outcome, so accept both.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()

        with captured_stdout() as out:
            ok = ByteGrylls.netcat_client("127.0.0.1", port, timeout=0.5)
        self.assertFalse(ok)
        self.assertIn("[-]", out.getvalue())


if __name__ == "__main__":
    unittest.main()
