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
from ByteGrylls import ByteGrylls, _valid_port, _parse_ports


def _icmp_header(icmp_type, icmp_id, seq, checksum=0):
    return struct.pack("BBHHh", icmp_type, 0, checksum, icmp_id, seq)


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

    def _run_query(self, response_bytes, record_type="A", query_input="example.com"):
        fake = mock.Mock()
        fake.recvfrom.return_value = (response_bytes, ("8.8.8.8", 53))
        fake.__enter__ = mock.Mock(return_value=fake)
        fake.__exit__ = mock.Mock(return_value=False)
        with mock.patch("ByteGrylls.socket.socket", return_value=fake):
            with captured_stdout() as out:
                result = ByteGrylls.dns_query(query_input, record_type=record_type)
        return result, out.getvalue()

    def _rr(self, name_ptr_offset, rtype, rdata, ttl=60):
        return (
            struct.pack("!H", 0xC000 | name_ptr_offset)
            + struct.pack("!HHIH", rtype, 1, ttl, len(rdata))
            + rdata
        )

    def _header_and_question(self, ancount, qname_str="example.com", qtype=1):
        header = self.TXN_ID + struct.pack("!HHHHH", 0x8180, 1, ancount, 0, 0)
        qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in qname_str.split(".")) + b"\x00"
        question = qname + struct.pack("!H", qtype) + struct.pack("!H", 1)
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

    def test_resolves_ptr_record(self):
        base, qoffset = self._header_and_question(ancount=1, qname_str="7.2.0.192.in-addr.arpa", qtype=12)
        ptr_name = b"\x04host\x07example\x03com\x00"
        response = base + self._rr(qoffset, rtype=12, rdata=ptr_name)
        result, output = self._run_query(response, record_type="PTR", query_input="192.0.2.7")
        self.assertEqual(result, "host.example.com")
        self.assertIn("Resolved", output)

    def test_ptr_query_with_invalid_ip_fails_cleanly(self):
        # Regression test: _reverse_dns_name() used to be called before the try/except, so a
        # non-IP argument to `dns -x` raised an uncaught OSError instead of a normal [-] message.
        with captured_stdout() as out:
            result = ByteGrylls.dns_query("not-an-ip-address", record_type="PTR")
        self.assertIsNone(result)
        self.assertIn("not a valid IPv4 or IPv6 address", out.getvalue())

    def test_query_timeout_reported_cleanly(self):
        fake = mock.Mock()
        fake.recvfrom.side_effect = socket.timeout("timed out")
        fake.__enter__ = mock.Mock(return_value=fake)
        fake.__exit__ = mock.Mock(return_value=False)
        with mock.patch("ByteGrylls.socket.socket", return_value=fake):
            with captured_stdout() as out:
                result = ByteGrylls.dns_query("example.com")
        self.assertIsNone(result)
        self.assertIn("DNS Query failed", out.getvalue())


class TestReverseDnsName(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(ByteGrylls._reverse_dns_name("192.0.2.7"), "7.2.0.192.in-addr.arpa")

    def test_ipv6(self):
        # RFC 3596's own worked example for 2001:db8::1.
        expected = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        self.assertEqual(ByteGrylls._reverse_dns_name("2001:db8::1"), expected)


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

    def test_permission_error_reports_cleanly(self):
        with mock.patch("ByteGrylls.socket.socket", side_effect=PermissionError("raw sockets need admin")):
            with captured_stdout() as out:
                self.tool.ping("192.0.2.1", count=2, timeout=2.0)
        self.assertIn("PERMISSION ERROR", out.getvalue())
        # No packets ever left the (nonexistent) socket, so there's nothing to summarize.
        self.assertNotIn("packets transmitted", out.getvalue())


class TestPingIPv6(unittest.TestCase):
    """The is_ipv6 branch: no outer IP header on the wire, type 128/129, kernel-filled checksum."""

    def setUp(self):
        self.icmp_id = os.getpid() & 0xFFFF
        self.tool = ByteGrylls()

    def _run_ping(self, packets, timeout=2.0):
        fake = FakeIcmpSocket(packets)
        # prefer_ipv6=True makes _resolve() try AF_INET6 first, matching this mock (which
        # doesn't discriminate by the requested family, so an IPv4-first attempt would also
        # "succeed" and silently defeat the point of these IPv6-path tests).
        with mock.patch("ByteGrylls.socket.getaddrinfo",
                         return_value=[(socket.AF_INET6, None, None, None, ("2001:db8::1", 0, 0, 0))]), \
             mock.patch("ByteGrylls.socket.socket", return_value=fake), \
             mock.patch("ByteGrylls.select.select", side_effect=fake_select_for(fake)):
            with captured_stdout() as out:
                self.tool.ping("v6host.example.com", count=1, timeout=timeout, prefer_ipv6=True)
        return fake, out.getvalue()

    def test_matches_ipv6_echo_reply(self):
        packets = [(build_echo_reply(129, self.icmp_id, 1, ipv6=True), ("2001:db8::1", 0, 0, 0))]
        fake, output = self._run_ping(packets)
        self.assertIn("icmp_seq=1", output)
        # ICMPv6 checksums are left for the kernel to fill in, unlike ICMPv4's hand-computed one.
        sent_header = fake.sent[0][0][:8]
        _, _, sent_checksum, _, _ = struct.unpack("BBHHh", sent_header)
        self.assertEqual(sent_checksum, 0)

    def test_reports_when_platform_lacks_icmpv6(self):
        with mock.patch("ByteGrylls.socket.getaddrinfo",
                         return_value=[(socket.AF_INET6, None, None, None, ("2001:db8::1", 0, 0, 0))]):
            had_attr = hasattr(socket, "IPPROTO_ICMPV6")
            saved = getattr(socket, "IPPROTO_ICMPV6", None)
            if had_attr:
                del socket.IPPROTO_ICMPV6
            try:
                with captured_stdout() as out:
                    self.tool.ping("v6host.example.com", count=1, timeout=1.0, prefer_ipv6=True)
            finally:
                if had_attr:
                    socket.IPPROTO_ICMPV6 = saved
        self.assertIn("not supported", out.getvalue())


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

    def test_permission_error_reports_cleanly(self):
        with mock.patch("ByteGrylls.socket.socket", side_effect=PermissionError("raw sockets need admin")):
            with captured_stdout() as out:
                self.tool.traceroute("192.0.2.1", max_hops=3, timeout=1.0)
        self.assertIn("PERMISSION ERROR", out.getvalue())


class TestTracerouteIPv6(unittest.TestCase):
    """The is_ipv6 branch: no outer IP header, type 128/129/3/1, fixed 40-byte inner IPv6 header."""

    def setUp(self):
        self.icmp_id = os.getpid() & 0xFFFF
        self.tool = ByteGrylls()

    def _run_traceroute(self, per_hop_packets, timeout=2.0):
        factory = PairedSocketFactory(per_hop_packets)
        with mock.patch("ByteGrylls.socket.getaddrinfo",
                         return_value=[(socket.AF_INET6, None, None, None, ("2001:db8::1", 0, 0, 0))]), \
             mock.patch("ByteGrylls.socket.socket", side_effect=factory), \
             mock.patch("ByteGrylls.select.select",
                         side_effect=lambda rlist, w, x, t, f=factory: fake_select_for(f._current)(rlist, w, x, t)):
            with captured_stdout() as out:
                self.tool.traceroute("v6host.example.com", max_hops=len(per_hop_packets), timeout=timeout,
                                      prefer_ipv6=True)
        return out.getvalue()

    def test_matches_ipv6_time_exceeded_then_reaches_target(self):
        # ICMPv6 Time Exceeded is type 3 (ICMPv4 uses 11) - see traceroute()'s per-family branch.
        hop1 = [(build_time_exceeded(self.icmp_id, 1, icmp_type=3, ipv6=True), ("2001:db8::fe", 0, 0, 0))]
        hop2 = [(build_echo_reply(129, self.icmp_id, 2, ipv6=True), ("2001:db8::1", 0, 0, 0))]
        output = self._run_traceroute([hop1, hop2])
        self.assertIn("2001:db8::fe", output)
        self.assertIn("2001:db8::1", output)
        self.assertIn("Target reached successfully!", output)

    def test_reports_when_platform_lacks_icmpv6(self):
        with mock.patch("ByteGrylls.socket.getaddrinfo",
                         return_value=[(socket.AF_INET6, None, None, None, ("2001:db8::1", 0, 0, 0))]):
            saved = socket.IPV6_UNICAST_HOPS
            del socket.IPV6_UNICAST_HOPS
            try:
                with captured_stdout() as out:
                    self.tool.traceroute("v6host.example.com", max_hops=1, timeout=1.0, prefer_ipv6=True)
            finally:
                socket.IPV6_UNICAST_HOPS = saved
        self.assertIn("not supported", out.getvalue())


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


class TestNetcatUdp(unittest.TestCase):
    def test_client_sends_datagram_to_listener(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.settimeout(3.0)

        received = []

        def recv_once():
            data, _ = srv.recvfrom(1024)
            received.append(data)
            srv.close()

        thread = threading.Thread(target=recv_once, daemon=True)
        thread.start()
        time.sleep(0.1)  # let the listener start receiving

        with captured_stdout() as out:
            ok = ByteGrylls.netcat_client("127.0.0.1", port, timeout=0.3, data=b"hello-udp", udp=True)
        thread.join(timeout=3.0)

        self.assertTrue(ok)
        self.assertEqual(received, [b"hello-udp"])
        self.assertIn("Sent 9 byte", out.getvalue())

    def test_closed_port_reports_failure_or_no_reply(self):
        # UDP is connectionless: whether a closed port surfaces as an ICMP-driven connection
        # error or a plain timeout depends on the host's network stack, so accept either -
        # same tolerance TestNetcat.test_unreachable_port_reports_failure uses for TCP.
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()

        with captured_stdout() as out:
            ok = ByteGrylls.netcat_client("127.0.0.1", port, timeout=0.5, data=b"probe", udp=True)
        output = out.getvalue()
        if ok:
            self.assertIn("No reply received", output)
        else:
            self.assertIn("appears closed", output)


def _wait_for(buf, needle, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if needle in buf.getvalue():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {needle!r} in captured output")


class TestNetcatListen(unittest.TestCase):
    """Exercises netcat_listen() itself (not just a hand-rolled stand-in server)."""

    def _free_port(self, sock_type):
        probe = socket.socket(socket.AF_INET, sock_type)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        return port

    def test_tcp_listener_logs_received_data(self):
        port = self._free_port(socket.SOCK_STREAM)
        with captured_stdout() as out:
            thread = threading.Thread(target=ByteGrylls.netcat_listen, args=("127.0.0.1", port), daemon=True)
            thread.start()
            _wait_for(out, "Listening for incoming connections")

            with socket.create_connection(("127.0.0.1", port), timeout=2.0) as client:
                client.sendall(b"hi-tcp-listener")

            _wait_for(out, "Received Data")

        output = out.getvalue()
        self.assertIn("Incoming connection established", output)
        self.assertIn("hi-tcp-listener", output)

    def test_tcp_listener_reports_empty_connection(self):
        port = self._free_port(socket.SOCK_STREAM)
        with captured_stdout() as out:
            thread = threading.Thread(target=ByteGrylls.netcat_listen, args=("127.0.0.1", port), daemon=True)
            thread.start()
            _wait_for(out, "Listening for incoming connections")

            socket.create_connection(("127.0.0.1", port), timeout=2.0).close()

            _wait_for(out, "closed with no data")

        self.assertIn("closed with no data", out.getvalue())

    def test_udp_listener_logs_received_datagram(self):
        port = self._free_port(socket.SOCK_DGRAM)
        with captured_stdout() as out:
            thread = threading.Thread(
                target=ByteGrylls.netcat_listen, args=("127.0.0.1", port), kwargs={"udp": True}, daemon=True
            )
            thread.start()
            _wait_for(out, "Listening for incoming datagrams")

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(b"hi-udp-listener", ("127.0.0.1", port))

            _wait_for(out, "Received Data")

        output = out.getvalue()
        self.assertIn("Datagram received", output)
        self.assertIn("hi-udp-listener", output)


class TestMainCli(unittest.TestCase):
    """Exercises main()'s argparse wiring end-to-end: flags -> the method args each command gets."""

    def _run_main(self, argv):
        with mock.patch.object(bg.sys, "argv", ["ByteGrylls.py"] + argv), \
             mock.patch.object(bg.sys.stdin, "isatty", return_value=True):
            bg.main()

    def test_version_flag_prints_and_exits_cleanly(self):
        with captured_stdout() as out, self.assertRaises(SystemExit) as ctx:
            self._run_main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn(bg.__version__, out.getvalue())

    def test_no_args_prints_help_and_exits_cleanly(self):
        with captured_stdout() as out, self.assertRaises(SystemExit) as ctx:
            self._run_main([])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("usage", out.getvalue().lower())

    def test_nc_dispatches_parsed_args(self):
        with mock.patch.object(bg.ByteGrylls, "netcat_client") as mocked:
            self._run_main(["nc", "example.com", "443", "-t", "1.5", "-d", "hello"])
        mocked.assert_called_once_with("example.com", 443, 1.5, b"hello", False)

    def test_nc_udp_flag_is_passed_through(self):
        with mock.patch.object(bg.ByteGrylls, "netcat_client") as mocked:
            self._run_main(["nc", "example.com", "53", "-u"])
        self.assertTrue(mocked.call_args.args[4])

    def test_listen_dispatches_parsed_args(self):
        with mock.patch.object(bg.ByteGrylls, "netcat_listen") as mocked:
            self._run_main(["listen", "0.0.0.0", "4444", "-u"])
        mocked.assert_called_once_with("0.0.0.0", 4444, True)

    def test_scan_parses_port_ranges_before_dispatch(self):
        with mock.patch.object(bg.ByteGrylls, "port_scan") as mocked:
            self._run_main(["scan", "10.0.0.5", "22,80,1000-1002", "-w", "10"])
        mocked.assert_called_once_with("10.0.0.5", [22, 80, 1000, 1001, 1002], 1.0, 10)

    def test_dns_reverse_flag_maps_to_ptr_record_type(self):
        with mock.patch.object(bg.ByteGrylls, "dns_query") as mocked:
            self._run_main(["dns", "8.8.8.8", "-x"])
        mocked.assert_called_once_with("8.8.8.8", "8.8.8.8", 3.0, "PTR")

    def test_dns_ipv6_flag_maps_to_aaaa_record_type(self):
        with mock.patch.object(bg.ByteGrylls, "dns_query") as mocked:
            self._run_main(["dns", "example.com", "-6"])
        mocked.assert_called_once_with("example.com", "8.8.8.8", 3.0, "AAAA")

    def test_ping_dispatches_parsed_args(self):
        with mock.patch.object(bg.ByteGrylls, "ping") as mocked:
            self._run_main(["ping", "8.8.8.8", "-c", "2", "-6"])
        mocked.assert_called_once_with("8.8.8.8", 2, 2.0, True)

    def test_traceroute_dispatches_parsed_args(self):
        with mock.patch.object(bg.ByteGrylls, "traceroute") as mocked:
            self._run_main(["traceroute", "8.8.8.8", "-m", "5"])
        mocked.assert_called_once_with("8.8.8.8", 5, 2.0, False)

    def test_invalid_port_exits_with_usage_error(self):
        with captured_stdout(), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                self._run_main(["nc", "1.1.1.1", "99999"])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_nc_falls_back_to_piped_stdin(self):
        # sys.stdin.buffer is a read-only property on the real stdin object, so the whole
        # sys.stdin reference is swapped out rather than patching its attributes individually.
        fake_stdin = mock.Mock()
        fake_stdin.isatty.return_value = False
        fake_stdin.buffer = io.BytesIO(b"piped-bytes")
        with mock.patch.object(bg.ByteGrylls, "netcat_client") as mocked, \
             mock.patch.object(bg.sys, "stdin", fake_stdin), \
             mock.patch.object(bg.sys, "argv", ["ByteGrylls.py", "nc", "1.1.1.1", "80"]):
            bg.main()
        mocked.assert_called_once_with("1.1.1.1", 80, 3.0, b"piped-bytes", False)


class TestPortScan(unittest.TestCase):
    def test_reports_open_and_closed_ports(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        open_port = srv.getsockname()[1]

        closed_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed_srv.bind(("127.0.0.1", 0))
        closed_port = closed_srv.getsockname()[1]
        closed_srv.close()

        try:
            with captured_stdout() as out:
                ByteGrylls.port_scan("127.0.0.1", [open_port, closed_port], timeout=0.5)
        finally:
            srv.close()

        output = out.getvalue()
        self.assertIn(f"[+] {open_port}/tcp open", output)
        self.assertNotIn(f"[+] {closed_port}/tcp open", output)
        self.assertIn(f"1/2 open -> {open_port}", output)


class TestParsePorts(unittest.TestCase):
    def test_parses_comma_list(self):
        self.assertEqual(_parse_ports("22,80,443"), [22, 80, 443])

    def test_parses_range(self):
        self.assertEqual(_parse_ports("1000-1003"), [1000, 1001, 1002, 1003])

    def test_parses_mixed_and_dedupes(self):
        self.assertEqual(_parse_ports("22,20-22,80"), [22, 20, 21, 80])

    def test_rejects_inverted_range(self):
        with self.assertRaises(Exception):
            _parse_ports("100-50")

    def test_rejects_empty(self):
        with self.assertRaises(Exception):
            _parse_ports("")


if __name__ == "__main__":
    unittest.main()
