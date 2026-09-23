# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ByteGrylls is a single-file, pure-Python (stdlib only, zero pip dependencies) network diagnostic
tool. It reimplements the basics of `nc`, `dig`/`nslookup`, `ping`, `traceroute`, and a port
scanner for use on locked-down/air-gapped hosts where those utilities aren't installed and can't
be. Everything lives in [ByteGrylls.py](ByteGrylls.py) — there is no package structure or build
step.

## Running it

```bash
python3 ByteGrylls.py --version
python3 ByteGrylls.py                                             # prints help
python3 ByteGrylls.py nc <host> <port> [-t/--timeout] [-d/--data TEXT] [-u/--udp]  # TCP/UDP port test (client mode);
                                                                   # -d sends a literal string, or pipe stdin
python3 ByteGrylls.py listen [host] <port> [-u/--udp]             # TCP/UDP listener (server mode)
python3 ByteGrylls.py dns <domain> [-s/--server] [-t/--timeout] [-6/--ipv6] [-x/--reverse]  # raw UDP A/AAAA/PTR query
python3 ByteGrylls.py scan <host> <ports> [-t/--timeout] [-w/--workers]  # concurrent TCP port sweep; ports is
                                                                   # a comma list and/or dash ranges, e.g. "22,80,1000-1010"
python3 ByteGrylls.py ping <host> [-c/--count] [-t/--timeout] [-6/--ipv6]    # raw ICMP echo — needs root/Administrator
python3 ByteGrylls.py traceroute <host> [-m/--max-hops] [-t/--timeout] [-6/--ipv6]  # raw ICMP TTL trace — needs root/Administrator
```

`ping` and `traceroute` build raw ICMP sockets and will fail with a `PermissionError` message
unless run elevated (`sudo` on Linux/macOS, Administrator PowerShell/CMD on Windows). `nc`,
`listen`, `dns`, and `scan` are unprivileged. `nc`/`listen`/`scan` ports are validated to 1-65535
by argparse (`_valid_port`, and `_parse_ports` for `scan`'s comma/range syntax) before any socket
call.

There is no linter or formatter configured in this repo. Unit tests live in
[test_bytegrylls.py](test_bytegrylls.py) (stdlib `unittest`, ~60 tests, no dependencies):

```bash
python -m unittest test_bytegrylls -v
```

Coverage spans every subcommand, both address families for `ping`/`traceroute`, and `main()`'s
argparse wiring itself:

- `ping`/`traceroute` (IPv4 **and** IPv6) are tested by monkeypatching `socket.socket` (and
  `select.select`) inside the `ByteGrylls` module with `FakeIcmpSocket`/`PairedSocketFactory`/
  `fake_select_for()`, so the suite needs no root/Administrator privileges and never touches the
  real network. **Gotcha when extending the IPv6 tests**: `_resolve()` tries IPv4 before IPv6 by
  default, so a `socket.getaddrinfo` mock that returns the same IPv6 tuple regardless of the
  requested `family` argument will make the *IPv4* attempt "succeed" first and silently produce an
  `is_ipv6 == False` test that never exercises the code you meant to test — pass `prefer_ipv6=True`
  to `ping()`/`traceroute()` in these tests so `_resolve()` tries `AF_INET6` first. Also remember
  ICMPv6 reuses different type numbers than ICMPv4 for the same concept (Echo Request/Reply are
  128/129 not 8/0; Time Exceeded is 3 not 11; Destination Unreachable is 1 not 3) — `build_time_exceeded()`'s
  default `icmp_type=11` is the IPv4 value and must be overridden for IPv6 packets.
- `dns_query()` (A/AAAA/PTR, including the CNAME-chain and OPT-before-A regression scenarios) is
  tested the same way, via a mocked UDP socket.
- `netcat_listen()` (TCP and UDP) is tested by running it in a daemon thread against a real
  loopback socket and polling captured stdout for its log lines — it's an infinite loop, so the
  test never joins the thread, just asserts on output and lets the daemon thread die with the
  process.
- `main()` is tested by patching `sys.argv` and mocking the `ByteGrylls` method each subcommand
  calls, then asserting on the exact args argparse produced — this is what catches wiring
  mistakes (wrong arg order, a flag not threaded through) that per-method tests can't see. Note:
  `sys.stdin.buffer` is a read-only property on the real stdin object, so the stdin-piping test
  replaces `sys.stdin` wholesale with a `Mock` rather than patching its attributes.
- `nc`/`scan` are tested against real loopback sockets on ephemeral ports instead, since that also
  needs no elevation.

When touching `ping`/`traceroute` manually against a live host, note that some virtualized/NAT'd
networks silently drop ICMP Time Exceeded replies, and some drop RST on closed loopback ports — if
`traceroute` times out on every hop but `ping` to the same host succeeds, or a "connection refused"
test times out instead, that's very likely the network, not the code.

## Architecture

All logic sits in one class, `ByteGrylls`, in [ByteGrylls.py](ByteGrylls.py), with each diagnostic
as an independent static/instance method — there's no shared session or connection state between
commands. `main()` wires a `argparse` subparser per command straight to the matching method; adding
a new subcommand means adding both a method on the class and a subparser block in `main()`.

Things worth understanding before touching the ICMP/DNS code, since they're built from raw
protocol bytes rather than a library:

- **`_checksum()`** implements the Internet checksum (RFC 1071), used by `ping()`/`traceroute()`
  only for ICMPv4 — both hand-pack an 8-byte ICMP Echo Request header (`struct.pack("BBHHh", ...)`)
  using `os.getpid() & 0xFFFF` as the ICMP identifier and the sequence number (loop index for
  `ping`, TTL for `traceroute`), all in **native byte order** (no `!`/`!H` prefix) except the
  checksum field, which is explicitly `socket.htons()`'d — since ByteGrylls both sends and parses
  its own replies with this same native-order format, it's internally consistent even though it
  doesn't match the network-byte-order convention other tools use. The type/code fields use `B`
  (unsigned byte), not `b`: ICMPv6 Echo Request/Reply are types 128/129, which overflow a signed
  byte's -128..127 range and raised `struct.error` on every real ping/traceroute attempt until the
  IPv6 test coverage below caught it — the ICMPv4 types (0/8/3/11) fit either way, which is why it
  went unnoticed on the well-exercised IPv4 path.
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
  for A, 28 for AAAA, 12 for PTR) over raw UDP to port 53 rather than using a resolver library, so
  it can query an arbitrary DNS server directly and bypass the OS resolver. For PTR queries the
  QNAME isn't the input hostname but `_reverse_dns_name()`'s in-addr.arpa/ip6.arpa encoding of it
  (octets reversed for IPv4, nibbles reversed for IPv6); that call is wrapped in its own
  `try/except OSError` (`_reverse_dns_name()` raises `OSError` via `inet_pton()` when the argument
  parses as neither an IPv4 nor IPv6 address) so `dns -x <non-ip>` prints a clean `[-]` message
  instead of an uncaught traceback — it deliberately isn't folded into the main `except Exception`
  below it, since that one only wraps the socket I/O and runs after this name is already needed
  for the query packet. The answer parser treats rtype 12 specially since PTR rdata is itself a
  (possibly compressed) DNS name, not a fixed-width address — it re-enters `_parse_dns_name()` at
  the rdata offset rather than slicing raw bytes. `_parse_dns_name()` follows DNS name-compression
  pointers (the `0xC0` high bits) so the response's question/answer sections can be walked RR-by-RR
  — this matters because real resolvers commonly interleave CNAME or EDNS0 OPT records before the
  record we want, so the answer can't be assumed to be at a fixed offset.
- **`port_scan()`** sweeps a list/range of TCP ports (parsed by the `_parse_ports` argparse type,
  which accepts comma-separated values and `start-end` ranges) using a
  `concurrent.futures.ThreadPoolExecutor` over the same `socket.create_connection` probe `nc`
  uses, capped at `-w/--workers` concurrent connection attempts so a wide range doesn't take
  `timeout × port_count` to finish serially.

`netcat_listen()` runs a blocking `accept()`/`recvfrom()` loop with a 1-second socket timeout
specifically so `KeyboardInterrupt` (Ctrl+C) gets a chance to interrupt cleanly on
Windows/PowerShell, which doesn't deliver signals to a socket call blocked with no timeout the way
POSIX does. `main()` wraps command dispatch in a top-level `except KeyboardInterrupt` (exit code
130) as a fallback for commands that don't already handle it themselves (`ping`/`traceroute` catch
it internally so they can still print their summary/partial trace before returning).

`netcat_client()` sends `-d/--data` (or piped stdin, when `-d` is omitted and stdin isn't a TTY)
after connecting, then makes one best-effort `recv()` attempt to print a reply before closing. In
UDP mode (`-u/--udp`) it `connect()`s the UDP socket before sending purely so that a subsequent
`recv()` can surface an OS-level connection error if an ICMP Port Unreachable comes back — Linux
raises `ConnectionRefusedError` for this, Windows raises `ConnectionResetError` for the same
condition, so both are caught to report the port as closed; a plain timeout with neither is
reported as "open or filtered" since UDP gives no other way to tell them apart without an
application-level reply.
