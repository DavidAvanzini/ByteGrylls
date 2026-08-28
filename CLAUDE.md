# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ByteGrylls is a single-file, pure-Python (stdlib only, zero pip dependencies) network diagnostic
tool. It reimplements the basics of `nc`, `dig`/`nslookup`, `ping`, and `traceroute` for use on
locked-down/air-gapped hosts where those utilities aren't installed and can't be. Everything lives
in [ByteGrylls.py](ByteGrylls.py) — there is no package structure, build step, or test suite.

## Running it

```bash
python3 ByteGrylls.py --version
python3 ByteGrylls.py                                             # prints help
python3 ByteGrylls.py nc <host> <port> [-t/--timeout] [-d/--data TEXT]  # TCP port test (client mode);
                                                                   # -d sends a literal string, or pipe stdin
python3 ByteGrylls.py listen [host] <port>                        # TCP listener (server mode)
python3 ByteGrylls.py dns <domain> [-s/--server] [-t/--timeout] [-6/--ipv6]  # raw UDP A/AAAA query
python3 ByteGrylls.py ping <host> [-c/--count] [-t/--timeout] [-6/--ipv6]    # raw ICMP echo — needs root/Administrator
python3 ByteGrylls.py traceroute <host> [-m/--max-hops] [-t/--timeout] [-6/--ipv6]  # raw ICMP TTL trace — needs root/Administrator
```

`ping` and `traceroute` build raw ICMP sockets and will fail with a `PermissionError` message
unless run elevated (`sudo` on Linux/macOS, Administrator PowerShell/CMD on Windows). `nc`,
`listen`, and `dns` are unprivileged. `nc`/`listen` ports are validated to 1-65535 by argparse
(`_valid_port`) before any socket call.

There is no linter or formatter configured in this repo. Unit tests live in
[test_bytegrylls.py](test_bytegrylls.py) (stdlib `unittest`, no dependencies):

```bash
python -m unittest test_bytegrylls -v
```

`ping`/`traceroute`/`dns_query` are tested by monkeypatching `socket.socket` (and `select.select`
for the ICMP tests) inside the `ByteGrylls` module, so the suite needs no root/Administrator
privileges and never touches the real network or binds a real raw socket — see `FakeIcmpSocket`,
`PairedSocketFactory`, and `fake_select_for()` in the test file if extending this coverage.
`nc`/`listen` are tested against real loopback sockets on ephemeral ports instead, since that
needs no elevation either. When touching `ping`/`traceroute` manually against a live host, note
that some virtualized/NAT'd networks silently drop ICMP Time Exceeded replies, and some drop RST
on closed loopback ports — if `traceroute` times out on every hop but `ping` to the same host
succeeds, or a "connection refused" test times out instead, that's very likely the network, not
the code.

## Architecture

All logic sits in one class, `ByteGrylls`, in [ByteGrylls.py](ByteGrylls.py), with each diagnostic
as an independent static/instance method — there's no shared session or connection state between
commands. `main()` wires a `argparse` subparser per command straight to the matching method; adding
a new subcommand means adding both a method on the class and a subparser block in `main()`.

Things worth understanding before touching the ICMP/DNS code, since they're built from raw
protocol bytes rather than a library:

- **`_checksum()`** implements the Internet checksum (RFC 1071), used by `ping()`/`traceroute()`
  only for ICMPv4 — both hand-pack an 8-byte ICMP Echo Request header (`struct.pack("bbHHh", ...)`)
  using `os.getpid() & 0xFFFF` as the ICMP identifier and the sequence number (loop index for
  `ping`, TTL for `traceroute`), all in **native byte order** (no `!`/`!H` prefix) except the
  checksum field, which is explicitly `socket.htons()`'d — since ByteGrylls both sends and parses
  its own replies with this same native-order format, it's internally consistent even though it
  doesn't match the network-byte-order convention other tools use.
- **`_resolve()`** wraps `socket.getaddrinfo()` to resolve a host to `(ip, address_family)`, trying
  IPv4 first and falling back to IPv6 (or the reverse, when `prefer_ipv6=True` from the `-6` flag).
  `ping()`/`traceroute()` branch on the returned family for the ICMP protocol/type numbers, socket
  options, and address-tuple shape (IPv6 raw sockets need a 4-tuple `(ip, port, flowinfo, scopeid)`
  and, unlike IPv4 raw sockets, deliver only the ICMPv6 payload with no IP header prepended — see
  `icmp_header_offset` in both methods). ICMPv6 checksums are left as 0 for the kernel to fill in
  from the pseudo-header, since RFC 4443 raw sockets compute it automatically where supported;
  IPv6 raw ICMP is best-effort and platform-dependent (guarded with `hasattr()` checks against
  missing `socket.IPPROTO_ICMPV6`/`IPV6_UNICAST_HOPS`, since Windows support is inconsistent).
- **`ping()`**/**`traceroute()`** match incoming ICMP packets against the identifier+sequence they
  sent before accepting them as the probe's reply, so unrelated ICMP traffic on the host is
  ignored rather than misattributed. `traceroute()` distinguishes Echo Reply / Time Exceeded /
  Destination Unreachable by ICMP `type`; for Time Exceeded/Unreachable it digs past the outer
  ICMP header **and** the quoted inner IP header to find the original echo request's id/sequence
  (see the `inner_icmp_offset` calculation — IPv6's inner header is assumed to be a fixed 40 bytes
  with no extension headers).
- **`dns_query()`** hand-builds a DNS query packet (12-byte header + QNAME/QTYPE/QCLASS, type 1
  for A or 28 for AAAA) over raw UDP to port 53 rather than using a resolver library, so it can
  query an arbitrary DNS server directly and bypass the OS resolver. `_parse_dns_name()` follows
  DNS name-compression pointers (the `0xC0` high bits) so the response's question/answer sections
  can be walked RR-by-RR — this matters because real resolvers commonly interleave CNAME or EDNS0
  OPT records before the A/AAAA record, so the answer can't be assumed to be at a fixed offset.

`netcat_listen()` runs a blocking `accept()` loop with a 1-second socket timeout specifically so
`KeyboardInterrupt` (Ctrl+C) gets a chance to interrupt cleanly on Windows/PowerShell, which
doesn't deliver signals to a socket call blocked with no timeout the way POSIX does. `main()`
wraps command dispatch in a top-level `except KeyboardInterrupt` (exit code 130) as a fallback for
commands that don't already handle it themselves (`ping`/`traceroute` catch it internally so they
can still print their summary/partial trace before returning).

`netcat_client()` sends `-d/--data` (or piped stdin, when `-d` is omitted and stdin isn't a TTY)
after connecting, then makes one best-effort `recv()` attempt to print a reply before closing.
