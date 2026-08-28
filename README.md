<p align="center">
  <img src="ByteGryllsLogo.png" alt="ByteGrylls logo" width="480">
</p>

# ByteGrylls

**Survival-ready pure Python network diagnostic tool. Zero external dependencies.**

ByteGrylls reimplements the everyday basics of `nc`, `dig`/`nslookup`, `ping`, and `traceroute`
using nothing but the Python 3 standard library. One `.py` file, no `pip install`, no compiler,
no admin rights to *set up* (some commands still need elevated privileges to *run*, see below).

## Why

You're on a locked-down jump box, a hardened bastion host, an air-gapped server, or a client
machine where you can't reach a package index and can't install anything — but Python 3 is
already there (it usually is). You still need to answer basic questions:

- Is this port even open?
- Can I stand up a quick listener to catch a callback or test a firewall rule?
- Is DNS resolving the way I expect, against a specific resolver?
- Is the host up at all?
- Where does the path break?

Netcat, `dig`, and traceroute utilities may simply not be installed, and you may have no way to
install them. ByteGrylls sidesteps that: copy one file over (scp, a paste into a text editor, a
`curl`, a `git clone` if you have connectivity at all) and run it with the interpreter that's
already sitting there.

## Requirements

- Python 3.6+ (standard library only — nothing to `pip install`)
- Works on Linux, macOS, and Windows (CMD or PowerShell)
- `ping` and `traceroute` build raw ICMP sockets, so those two subcommands need elevated
  privileges: `sudo` on Linux/macOS, an **Administrator** PowerShell/CMD on Windows. `nc`,
  `listen`, and `dns` are unprivileged and work as a normal user everywhere.

## Getting it onto the target machine

Any of these works, pick whatever the environment allows:

```bash
# You have git connectivity
git clone <repo-url>

# You only have raw HTTP(S) access
curl -O https://.../ByteGrylls.py

# You have neither: open ByteGrylls.py in your editor, copy its contents,
# and paste it into a new file on the target via your existing session
# (SSH, RDP clipboard, console redirection, etc.)
```

Then just run it — no build step, no virtualenv, no dependencies to resolve:

```bash
python3 ByteGrylls.py
```

Running it with no arguments prints the full help.

## Commands

| Command      | What it does                                        | Privileges needed          |
|--------------|------------------------------------------------------|-----------------------------|
| `nc`         | Test whether a TCP port is open, optionally send data | None                        |
| `listen`     | Open a local TCP listener (server mode)               | None                        |
| `dns`        | Resolve an A or AAAA record via raw UDP DNS query      | None                        |
| `ping`       | Send raw ICMP Echo Requests (IPv4 or IPv6)             | root/sudo or Administrator  |
| `traceroute` | Trace the route to a host via increasing TTL (IPv4/IPv6) | root/sudo or Administrator |

---

### `nc` — test a TCP port (Netcat client mode)

Use it exactly like you'd use `nc -zv` to check if something is listening — or, with `-d` or
piped stdin, to actually send something once connected.

```bash
python3 ByteGrylls.py nc 1.1.1.1 443
python3 ByteGrylls.py nc internal-db.corp.local 5432 --timeout 5
```

```
[*] Connecting to TCP 1.1.1.1:443...
[+] Successfully connected to 1.1.1.1:443 in 18.42 ms
```

If the port is closed or filtered:

```
[*] Connecting to TCP 10.0.0.5:9999...
[-] Error: Connection to 10.0.0.5:9999 timed out.
```

Send a literal string or a raw HTTP request, then print any reply:

```bash
python3 ByteGrylls.py nc example.com 80 -d "GET / HTTP/1.0\r\n\r\n"
echo "hello" | python3 ByteGrylls.py nc 127.0.0.1 4444
```

Flags:
- `-t / --timeout` — connection timeout in seconds (default `3.0`)
- `-d / --data` — literal text to send after connecting (falls back to piped stdin if omitted)

---

### `listen` — open a local TCP listener (Netcat server mode)

Useful for confirming outbound connectivity from another host, catching a reverse-shell test
during an authorized pentest, or verifying a firewall/NAT rule lets traffic through.

```bash
python3 ByteGrylls.py listen 0.0.0.0 4444
```

```
[*] Binding TCP socket listener on 0.0.0.0:4444...
[+] Listening for incoming connections... (Press Ctrl+C to abort)
[+] Incoming connection established from 192.168.1.42:53291
[Received Data]: hello from the other host
```

It keeps listening and logs each new connection as it happens, so you can test more than one
client without restarting it. Press `Ctrl+C` to stop.

The bind host is optional and defaults to `0.0.0.0` (all interfaces):

```bash
python3 ByteGrylls.py listen 4444              # binds 0.0.0.0:4444
python3 ByteGrylls.py listen 127.0.0.1 4444     # binds loopback only
```

---

### `dns` — raw UDP A/AAAA lookup

Handy when you want to query a *specific* resolver directly (bypassing whatever the OS is
configured to use) and `dig`/`nslookup` aren't installed.

```bash
python3 ByteGrylls.py dns example.com
python3 ByteGrylls.py dns internal-app.corp.local --server 10.0.0.1
python3 ByteGrylls.py dns example.com -6
```

```
[*] Querying DNS record A for 'example.com' via server 8.8.8.8...
[+] Resolved: example.com -> 93.184.216.34 (24.11 ms)
```

Flags:
- `-s / --server` — DNS server to query (default `8.8.8.8`)
- `-t / --timeout` — query timeout in seconds (default `3.0`)
- `-6 / --ipv6` — query the AAAA record instead of A

---

### `ping` — raw ICMP Echo Request

Requires raw sockets, so run it elevated.

```bash
# Linux / macOS
sudo python3 ByteGrylls.py ping google.com -c 5

# Windows PowerShell (run as Administrator)
python3 ByteGrylls.py ping google.com -c 5
```

```
[*] PING google.com (142.250.72.14):
 64 bytes from 142.250.72.14: icmp_seq=1 rtt=14.88 ms
 64 bytes from 142.250.72.14: icmp_seq=2 rtt=13.02 ms
 64 bytes from 142.250.72.14: icmp_seq=3 rtt=15.61 ms

--- google.com ping statistics ---
3 packets transmitted, 3 received, 0.0% packet loss
rtt min/avg/max = 13.02/14.50/15.61 ms
```

Flags:
- `-c / --count` — number of Echo Requests to send (default `4`)
- `-t / --timeout` — reply timeout in seconds per packet (default `2.0`)
- `-6 / --ipv6` — prefer IPv6 when the host resolves to both families (best-effort; platform support
  for raw ICMPv6 sockets varies)

Without the right privileges you'll get a clear message instead of a stack trace:

```
[-] PERMISSION ERROR: ICMP Ping requires root/administrator privileges for raw sockets.
```

---

### `traceroute` — trace the route to a host

Same privilege requirement as `ping`, same reason (raw ICMP sockets).

```bash
# Linux / macOS
sudo python3 ByteGrylls.py traceroute 8.8.8.8 -m 15

# Windows PowerShell (run as Administrator)
python3 ByteGrylls.py traceroute 8.8.8.8 -m 15
```

```
[*] Traceroute to 8.8.8.8 (8.8.8.8), max 15 hops:
  1  192.168.1.1  1.21 ms
  2  10.10.0.1  8.44 ms
  3  * * * (Request Timed Out)
  4  8.8.8.8  19.03 ms
[+] Target reached successfully!
```

Flags:
- `-m / --max-hops` — maximum TTL to probe out to (default `30`)
- `-t / --timeout` — reply timeout in seconds per hop (default `2.0`)
- `-6 / --ipv6` — prefer IPv6 when the host resolves to both families (best-effort; platform support
  for raw ICMPv6 sockets varies)

A hop that answers with ICMP Destination Unreachable (rather than expiring in transit) is flagged
so it isn't mistaken for a normal hop:

```
  7  203.0.113.9  22.4 ms (Destination Unreachable)
```

---

## Testing

Unit tests ([test_bytegrylls.py](test_bytegrylls.py)) use only the standard library `unittest`
module — nothing to install:

```bash
python -m unittest test_bytegrylls -v
```

The `ping`/`traceroute`/`dns` tests run against mocked sockets, so the suite needs no root/
Administrator privileges and never touches the real network.

## Full help

```bash
python3 ByteGrylls.py --version
python3 ByteGrylls.py --help
python3 ByteGrylls.py <command> --help
```

## License

MIT — see [LICENSE](LICENSE).
