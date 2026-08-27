# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ByteGrylls is a single-file, pure-Python (stdlib only, zero pip dependencies) network diagnostic
tool. It reimplements the basics of `nc`, `dig`/`nslookup`, `ping`, and `traceroute` for use on
locked-down/air-gapped hosts where those utilities aren't installed and can't be. Everything lives
in [ByteGrylls.py](ByteGrylls.py) — there is no package structure, build step, or test suite.

## Running it

```bash
python3 ByteGrylls.py                                    # prints help
python3 ByteGrylls.py nc <host> <port> [-t/--timeout]     # TCP port test (client mode)
python3 ByteGrylls.py listen [host] <port>                # TCP listener (server mode)
python3 ByteGrylls.py dns <domain> [-s/--server] [-t/--timeout]   # raw UDP A-record query
python3 ByteGrylls.py ping <host> [-c/--count] [-t/--timeout]     # raw ICMP echo — needs root/Administrator
python3 ByteGrylls.py traceroute <host> [-m/--max-hops] [-t/--timeout]  # raw ICMP TTL trace — needs root/Administrator
```

`ping` and `traceroute` build raw ICMP sockets and will fail with a `PermissionError` message
unless run elevated (`sudo` on Linux/macOS, Administrator PowerShell/CMD on Windows). `nc`,
`listen`, and `dns` are unprivileged.

There is no linter, formatter, or test suite configured in this repo. Verify changes by running
the relevant subcommand manually (e.g. `python3 ByteGrylls.py nc 1.1.1.1 443`).

## Architecture

All logic sits in one class, `ByteGrylls`, in [ByteGrylls.py](ByteGrylls.py), with each diagnostic
as an independent static/instance method — there's no shared session or connection state between
commands. `main()` wires a `argparse` subparser per command straight to the matching method; adding
a new subcommand means adding both a method on the class and a subparser block in `main()`.

Two things worth understanding before touching the ICMP/DNS code, since they're built from raw
protocol bytes rather than a library:

- **`_checksum()`** implements the Internet checksum (RFC 1071) and is shared by `ping()` and
  `traceroute()` — both hand-pack an 8-byte ICMP Echo Request header (`struct.pack("bbHHh", ...)`)
  using `os.getpid() & 0xFFFF` as the ICMP identifier and the loop index as the sequence number,
  then read back raw socket data starting at byte offset 20 (skipping the IPv4 header) to reach the
  ICMP header at bytes 20-28.
- **`dns_query()`** hand-builds a DNS query packet (12-byte header + QNAME/QTYPE/QCLASS) over raw
  UDP to port 53 rather than using a resolver library, so it can query an arbitrary DNS server
  directly and bypass the OS resolver.

`netcat_listen()` runs a blocking `accept()` loop with a 1-second socket timeout specifically so
`KeyboardInterrupt` (Ctrl+C) gets a chance to interrupt cleanly on Windows/PowerShell, which
doesn't deliver signals to a socket call blocked with no timeout the way POSIX does.

## Known issues to fix

These were identified in review and are not yet fixed — treat them as the current priority list
when working in this file:

- **`ping()`** ([ByteGrylls.py:147-194](ByteGrylls.py#L147-L194)) and **`traceroute()`**
  ([ByteGrylls.py:198-249](ByteGrylls.py#L198-L249)) read whatever arrives next on the raw ICMP
  socket and treat it as the reply to the just-sent probe — neither checks the ICMP identifier or
  sequence number against what was sent, so unrelated ICMP traffic on the host can be misattributed
  as the RTT/hop for the current probe. `traceroute()` additionally never checks the ICMP `type`
  field (should distinguish Time Exceeded / Echo Reply / Destination Unreachable), so a non-hop
  ICMP packet can be misreported as reaching the target.
- **`ping()`** opens and closes a brand-new raw socket per packet inside the send loop
  ([ByteGrylls.py:159](ByteGrylls.py#L159)) instead of reusing one socket across the whole run.
- **`dns_query()`** ([ByteGrylls.py:81-118](ByteGrylls.py#L81-L118)) resolves the A record by
  slicing the *last 4 bytes* of the raw UDP response instead of parsing the answer resource record
  structure. This breaks as soon as the response includes additional/authority records (e.g. an
  EDNS0 OPT record, which most real resolvers add) or a CNAME before the A record.
- No global `KeyboardInterrupt` handling for `ping`/`traceroute`/`nc` — only `netcat_listen()`
  catches it internally; the others will raise a raw traceback on Ctrl+C.
- `ping` has no end-of-run summary (packets sent/received, loss %, min/avg/max RTT).
- `dns`, `ping`, and `traceroute` are IPv4-only (`socket.gethostbyname`, `AF_INET`,
  `IPPROTO_ICMP`); IPv6 is not supported by any of them. `nc`/`listen` incidentally accept IPv6
  via `socket.create_connection`, but this isn't documented.
- `nc` only tests connectivity — there's no way to send a payload or pipe stdin through the
  connection.
- No port-range validation on `nc`/`listen` (`argparse` accepts any int, including out-of-range
  values).
- No `--version` flag / version constant.
