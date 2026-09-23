#!/usr/bin/env python3
"""
ByteGrylls - Pure Python Network Diagnostic Tool
No external dependencies. Powered strictly by Python 3 standard library.
"""

import argparse
import concurrent.futures
import os
import select
import socket
import struct
import sys
import time

__version__ = "1.2.1"


class ByteGrylls:
    """
    Core engine for network diagnostics:
    Simulates Netcat (TCP/UDP), DNS resolution, ICMP Ping, and ICMP Traceroute.
    """

    # --- 1. NETCAT & PORT TESTING ---

    @staticmethod
    def netcat_client(host: str, port: int, timeout: float = 3.0, data: bytes = None, udp: bool = False) -> bool:
        """Connects to a remote TCP port, or sends a UDP datagram, optionally sending data and printing any reply (Netcat client mode)."""
        if udp:
            print(f"[*] Sending UDP datagram to {host}:{port}...")
            start_time = time.time()
            try:
                dest_ip, family = ByteGrylls._resolve(host)
                with socket.socket(family, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    dest_addr = (dest_ip, port, 0, 0) if family == socket.AF_INET6 else (dest_ip, port)
                    # Connecting a UDP socket lets a subsequent recv() surface ECONNREFUSED if the
                    # kernel sees an ICMP Port Unreachable come back, giving a real "closed" signal.
                    s.connect(dest_addr)
                    s.send(data or b"")
                    elapsed = (time.time() - start_time) * 1000
                    print(f"[+] Sent {len(data or b'')} byte(s) to {host}:{port} in {elapsed:.2f} ms")
                    try:
                        reply = s.recv(4096)
                        if reply:
                            print(f"[Received Data]: {reply.decode(errors='replace')}")
                    except socket.timeout:
                        print("[*] No reply received (UDP is connectionless - open and filtered ports look identical without one).")
                    except ConnectionError:
                        # Linux surfaces this as ConnectionRefusedError; Windows surfaces the same
                        # ICMP Port Unreachable as ConnectionResetError - both mean "closed".
                        print(f"[-] {host}:{port} appears closed (ICMP port unreachable received).")
                        return False
                return True
            except socket.gaierror:
                print(f"[-] Cannot resolve host: {host}")
            except Exception as e:
                print(f"[-] UDP send error: {e}")
            return False

        print(f"[*] Connecting to TCP {host}:{port}...")
        start_time = time.time()
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                elapsed = (time.time() - start_time) * 1000
                print(f"[+] Successfully connected to {host}:{port} in {elapsed:.2f} ms")
                if data:
                    s.sendall(data)
                    print(f"[*] Sent {len(data)} bytes.")
                    try:
                        s.settimeout(timeout)
                        reply = s.recv(4096)
                        if reply:
                            print(f"[Received Data]: {reply.decode(errors='replace')}")
                    except socket.timeout:
                        pass
                return True
        except socket.timeout:
            print(f"[-] Error: Connection to {host}:{port} timed out.")
        except ConnectionRefusedError:
            print(f"[-] Error: Connection refused by {host}:{port}.")
        except Exception as e:
            print(f"[-] Connection error: {e}")
        return False

    @staticmethod
    def netcat_listen(host: str, port: int, udp: bool = False):
        """Opens a local TCP or UDP socket and listens for incoming data (Netcat server mode)."""
        proto = "UDP" if udp else "TCP"
        print(f"[*] Binding {proto} socket listener on {host}:{port}...", flush=True)
        try:
            sock_type = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
            with socket.socket(socket.AF_INET, sock_type) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                # Short timeout allows Python to intercept KeyboardInterrupt on PowerShell/Windows
                s.settimeout(1.0)

                if udp:
                    print("[+] Listening for incoming datagrams... (Press Ctrl+C to abort)", flush=True)
                    while True:
                        try:
                            dgram, addr = s.recvfrom(4096)
                        except socket.timeout:
                            continue
                        print(f"[+] Datagram received from {addr[0]}:{addr[1]}", flush=True)
                        if dgram:
                            print(f"[Received Data]: {dgram.decode(errors='replace')}", flush=True)
                    return

                s.listen(5)
                print("[+] Listening for incoming connections... (Press Ctrl+C to abort)", flush=True)

                while True:
                    try:
                        conn, addr = s.accept()
                    except socket.timeout:
                        continue

                    print(f"[+] Incoming connection established from {addr[0]}:{addr[1]}", flush=True)
                    try:
                        conn.settimeout(5.0)
                        data = conn.recv(1024)
                        if data:
                            print(f"[Received Data]: {data.decode(errors='replace')}", flush=True)
                        else:
                            print(f"[*] Connection from {addr[0]}:{addr[1]} closed with no data.", flush=True)
                    except socket.timeout:
                        print(f"[-] No data received from {addr[0]}:{addr[1]} within timeout.", flush=True)
                    finally:
                        conn.close()
        except KeyboardInterrupt:
            print("\n[*] Listener stopped by user.")
        except Exception as e:
            print(f"[-] Listener error: {e}")

    # --- 2. NATIVE DNS QUERY ---

    @staticmethod
    def _parse_dns_name(data: bytes, offset: int):
        """Reads a (possibly compressed) DNS name starting at offset; returns (name, offset_after_name)."""
        labels = []
        jumped_from = None
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if jumped_from is None:
                    jumped_from = offset + 2
                offset = pointer
                continue
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
        return ".".join(labels), (jumped_from if jumped_from is not None else offset)

    @staticmethod
    def _reverse_dns_name(ip: str) -> str:
        """Builds the in-addr.arpa/ip6.arpa QNAME used for a PTR (reverse DNS) query."""
        try:
            packed = socket.inet_pton(socket.AF_INET, ip)
            return ".".join(str(b) for b in reversed(packed)) + ".in-addr.arpa"
        except OSError:
            packed = socket.inet_pton(socket.AF_INET6, ip)
            nibbles = []
            for byte in reversed(packed):
                nibbles.append(f"{byte & 0xF:x}")
                nibbles.append(f"{byte >> 4:x}")
            return ".".join(nibbles) + ".ip6.arpa"

    @staticmethod
    def dns_query(hostname: str, dns_server: str = "8.8.8.8", timeout: float = 3.0, record_type: str = "A"):
        """Performs a raw UDP DNS query (A, AAAA, or PTR) without third-party DNS libraries."""
        qtype_val = {"A": 1, "AAAA": 28, "PTR": 12}[record_type]
        if record_type == "PTR":
            try:
                query_name = ByteGrylls._reverse_dns_name(hostname)
            except OSError:
                print(f"[-] '{hostname}' is not a valid IPv4 or IPv6 address for a PTR query.")
                return None
            print(f"[*] Querying DNS record PTR for '{hostname}' ({query_name}) via server {dns_server}...")
        else:
            query_name = hostname
            print(f"[*] Querying DNS record {record_type} for '{hostname}' via server {dns_server}...")

        # Construct DNS Header (12 bytes)
        # Transaction ID, Flags (Standard query with recursion), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        transaction_id = 0x1234
        flags = 0x0100
        header = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0)

        # Construct Question Section (qname + qtype + qclass)
        qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in query_name.split(".")) + b"\x00"
        qtype = struct.pack("!H", qtype_val)
        qclass = struct.pack("!H", 1)  # Class IN (Internet)

        query_packet = header + qname + qtype + qclass

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                start_time = time.time()
                s.sendto(query_packet, (dns_server, 53))
                response, _ = s.recvfrom(1024)
                elapsed = (time.time() - start_time) * 1000

                if len(response) < 12 or response[:2] != struct.pack("!H", transaction_id):
                    print("[-] DNS response did not match the query (unexpected reply?).")
                    return None

                ancount = struct.unpack("!H", response[6:8])[0]
                if ancount == 0:
                    print(f"[-] DNS server returned 0 {record_type}-records for {hostname}.")
                    return None

                # Walk past the echoed question, then each answer RR, to find a matching record
                # rather than assuming it's at a fixed offset - real responses commonly interleave
                # CNAME/OPT records before or instead of the record we want.
                offset = 12
                _, offset = ByteGrylls._parse_dns_name(response, offset)
                offset += 4  # skip QTYPE + QCLASS

                resolved = None
                for _ in range(ancount):
                    _, offset = ByteGrylls._parse_dns_name(response, offset)
                    rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", response[offset:offset + 10])
                    offset += 10
                    rdata_start = offset
                    offset += rdlength
                    if resolved is None and rclass == 1:
                        if rtype == 1 and rdlength == 4:
                            resolved = socket.inet_ntoa(response[rdata_start:offset])
                        elif rtype == 28 and rdlength == 16:
                            resolved = socket.inet_ntop(socket.AF_INET6, response[rdata_start:offset])
                        elif rtype == 12:
                            # PTR rdata is itself a (possibly compressed) DNS name.
                            resolved, _ = ByteGrylls._parse_dns_name(response, rdata_start)

                if resolved:
                    print(f"[+] Resolved: {hostname} -> {resolved} ({elapsed:.2f} ms)")
                    return resolved

                print(f"[-] DNS server returned no usable {record_type}-record for {hostname}.")
        except Exception as e:
            print(f"[-] DNS Query failed: {e}")
        return None

    # --- 3. ICMP HELPERS ---

    @staticmethod
    def _checksum(source_string: bytes) -> int:
        """Calculates the Internet Checksum required for raw ICMPv4 headers."""
        count_to = (len(source_string) // 2) * 2
        sum_val = 0
        count = 0
        while count < count_to:
            this_val = source_string[count + 1] * 256 + source_string[count]
            sum_val += this_val
            sum_val &= 0xFFFFFFFF
            count += 2

        if count_to < len(source_string):
            sum_val += source_string[len(source_string) - 1]
            sum_val &= 0xFFFFFFFF

        sum_val = (sum_val >> 16) + (sum_val & 0xFFFF)
        sum_val += (sum_val >> 16)
        answer = ~sum_val
        answer &= 0xFFFF
        answer = answer >> 8 | (answer << 8 & 0xFF00)
        return answer

    @staticmethod
    def _resolve(host: str, prefer_ipv6: bool = False):
        """Resolves host to (ip_string, address_family), trying one family then falling back to the other."""
        families = (socket.AF_INET6, socket.AF_INET) if prefer_ipv6 else (socket.AF_INET, socket.AF_INET6)
        last_error = None
        for family in families:
            try:
                return socket.getaddrinfo(host, None, family)[0][4][0], family
            except socket.gaierror as e:
                last_error = e
        raise last_error

    # --- 4. ICMP PING ---

    def ping(self, dest_host: str, count: int = 4, timeout: float = 2.0, prefer_ipv6: bool = False):
        """Sends raw ICMP Echo Requests (Ping). Requires root/admin privileges."""
        try:
            dest_ip, family = self._resolve(dest_host, prefer_ipv6)
        except socket.gaierror:
            print(f"[-] Cannot resolve host: {dest_host}")
            return

        is_ipv6 = family == socket.AF_INET6
        if is_ipv6 and not hasattr(socket, "IPPROTO_ICMPV6"):
            print("[-] IPv6 ping is not supported by the socket module on this platform.")
            return

        print(f"[*] PING {dest_host} ({dest_ip}):")

        icmp_proto = socket.IPPROTO_ICMPV6 if is_ipv6 else socket.IPPROTO_ICMP
        echo_request_type, echo_reply_type = (128, 129) if is_ipv6 else (8, 0)
        # IPv6 raw sockets deliver only the ICMPv6 payload; IPv4 raw sockets include the IP header.
        icmp_header_offset = 0 if is_ipv6 else 20
        dest_addr = (dest_ip, 1, 0, 0) if is_ipv6 else (dest_ip, 1)
        icmp_id = os.getpid() & 0xFFFF

        sent = 0
        rtts = []

        try:
            with socket.socket(family, socket.SOCK_RAW, icmp_proto) as s:
                for i in range(count):
                    sequence = i + 1

                    header = struct.pack("BBHHh", echo_request_type, 0, 0, icmp_id, sequence)
                    data = struct.pack("d", time.time())
                    if not is_ipv6:
                        # ICMPv6 checksums are computed by the kernel from the IPv6 pseudo-header;
                        # ICMPv4 has no such header, so it must be computed here.
                        chksum = self._checksum(header + data)
                        header = struct.pack("BBHHh", echo_request_type, 0, socket.htons(chksum), icmp_id, sequence)
                    packet = header + data

                    sent += 1
                    start_time = time.time()
                    s.sendto(packet, dest_addr)

                    deadline = start_time + timeout
                    while True:
                        remaining = deadline - time.time()
                        if remaining <= 0:
                            print(f" Request timeout for icmp_seq {sequence}")
                            break
                        ready = select.select([s], [], [], remaining)
                        if not ready[0]:
                            print(f" Request timeout for icmp_seq {sequence}")
                            break

                        recv_packet, addr = s.recvfrom(1024)
                        time_received = time.time()
                        icmp_header = recv_packet[icmp_header_offset:icmp_header_offset + 8]
                        if len(icmp_header) < 8:
                            continue
                        type_val, _, _, resp_id, resp_seq = struct.unpack("BBHHh", icmp_header)
                        if type_val != echo_reply_type or resp_id != icmp_id or resp_seq != sequence:
                            continue  # unrelated ICMP traffic on the host - keep waiting for our own reply

                        rtt = (time_received - start_time) * 1000
                        rtts.append(rtt)
                        print(f" 64 bytes from {addr[0]}: icmp_seq={sequence} rtt={rtt:.2f} ms")
                        break
        except PermissionError:
            print("[-] PERMISSION ERROR: ICMP Ping requires root/administrator privileges for raw sockets.")
        except KeyboardInterrupt:
            print("\n[*] Ping aborted by user.")
        except Exception as e:
            print(f"[-] Ping error: {e}")

        if sent:
            received = len(rtts)
            loss_pct = (sent - received) / sent * 100
            print(f"\n--- {dest_host} ping statistics ---")
            print(f"{sent} packets transmitted, {received} received, {loss_pct:.1f}% packet loss")
            if rtts:
                print(f"rtt min/avg/max = {min(rtts):.2f}/{sum(rtts) / len(rtts):.2f}/{max(rtts):.2f} ms")

    # --- 5. ICMP TRACEROUTE ---

    def traceroute(self, dest_host: str, max_hops: int = 30, timeout: float = 2.0, prefer_ipv6: bool = False):
        """Executes a traceroute by incrementally increasing the IP Time-To-Live (TTL)."""
        try:
            dest_ip, family = self._resolve(dest_host, prefer_ipv6)
        except socket.gaierror:
            print(f"[-] Cannot resolve host: {dest_host}")
            return

        is_ipv6 = family == socket.AF_INET6
        if is_ipv6 and not (hasattr(socket, "IPPROTO_ICMPV6") and hasattr(socket, "IPV6_UNICAST_HOPS")):
            print("[-] IPv6 traceroute is not supported by the socket module on this platform.")
            return

        print(f"[*] Traceroute to {dest_host} ({dest_ip}), max {max_hops} hops:")

        if is_ipv6:
            icmp_proto = socket.IPPROTO_ICMPV6
            ttl_level, ttl_opt = socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS
            echo_request_type, echo_reply_type = 128, 129
            time_exceeded_type, dest_unreachable_type = 3, 1
            bind_addr, dest_addr = ("", 0, 0, 0), (dest_ip, 1, 0, 0)
        else:
            icmp_proto = socket.IPPROTO_ICMP
            ttl_level, ttl_opt = socket.IPPROTO_IP, socket.IP_TTL
            echo_request_type, echo_reply_type = 8, 0
            time_exceeded_type, dest_unreachable_type = 11, 3
            bind_addr, dest_addr = ("", 0), (dest_ip, 1)
        # IPv6 raw sockets deliver only the ICMPv6 payload; IPv4 raw sockets include the IP header.
        icmp_header_offset = 0 if is_ipv6 else 20
        icmp_id = os.getpid() & 0xFFFF

        try:
            for ttl in range(1, max_hops + 1):
                recv_socket = None
                send_socket = None
                try:
                    recv_socket = socket.socket(family, socket.SOCK_RAW, icmp_proto)
                    recv_socket.bind(bind_addr)

                    send_socket = socket.socket(family, socket.SOCK_RAW, icmp_proto)
                    send_socket.setsockopt(ttl_level, ttl_opt, ttl)

                    header = struct.pack("BBHHh", echo_request_type, 0, 0, icmp_id, ttl)
                    data = struct.pack("d", time.time())
                    if not is_ipv6:
                        chksum = self._checksum(header + data)
                        header = struct.pack("BBHHh", echo_request_type, 0, socket.htons(chksum), icmp_id, ttl)
                    packet = header + data

                    start_time = time.time()
                    send_socket.sendto(packet, dest_addr)

                    deadline = start_time + timeout
                    hop_addr, reached, unreachable = None, False, False
                    while True:
                        remaining = deadline - time.time()
                        if remaining <= 0:
                            break
                        ready = select.select([recv_socket], [], [], remaining)
                        if not ready[0]:
                            break

                        recv_packet, curr_addr = recv_socket.recvfrom(512)
                        if len(recv_packet) <= icmp_header_offset:
                            continue
                        icmp_type = recv_packet[icmp_header_offset]

                        if icmp_type == echo_reply_type:
                            icmp_header = recv_packet[icmp_header_offset:icmp_header_offset + 8]
                            if len(icmp_header) < 8:
                                continue
                            _, _, _, resp_id, resp_seq = struct.unpack("BBHHh", icmp_header)
                            if resp_id != icmp_id or resp_seq != ttl:
                                continue  # unrelated ICMP traffic - keep waiting for our own probe's reply
                            hop_addr, reached = curr_addr[0], True
                            break

                        if icmp_type in (time_exceeded_type, dest_unreachable_type):
                            # The probe we sent is quoted after the outer ICMP header and an inner IP
                            # header, so skip past both to reach our original id/sequence.
                            inner_offset = icmp_header_offset + 8
                            if is_ipv6:
                                inner_icmp_offset = inner_offset + 40  # fixed IPv6 header, no extension headers assumed
                            else:
                                if len(recv_packet) <= inner_offset:
                                    continue
                                inner_ip_header_len = (recv_packet[inner_offset] & 0x0F) * 4
                                inner_icmp_offset = inner_offset + inner_ip_header_len
                            inner_header = recv_packet[inner_icmp_offset:inner_icmp_offset + 8]
                            if len(inner_header) < 8:
                                continue
                            _, _, _, resp_id, resp_seq = struct.unpack("BBHHh", inner_header)
                            if resp_id != icmp_id or resp_seq != ttl:
                                continue  # unrelated ICMP traffic - keep waiting for our own probe's reply
                            hop_addr = curr_addr[0]
                            unreachable = icmp_type == dest_unreachable_type
                            break

                        # Anything else is unrelated ICMP traffic - keep waiting for our own probe's reply.

                    if hop_addr is None:
                        print(f" {ttl:2d}  * * * (Request Timed Out)")
                        continue

                    elapsed = (time.time() - start_time) * 1000
                    suffix = " (Destination Unreachable)" if unreachable else ""
                    print(f" {ttl:2d}  {hop_addr}  {elapsed:.2f} ms{suffix}")

                    if reached or hop_addr == dest_ip:
                        print("[+] Target reached successfully!")
                        break

                except PermissionError:
                    print("[-] PERMISSION ERROR: Traceroute requires root/administrator privileges for raw sockets.")
                    break
                except OSError as e:
                    print(f"[-] Traceroute error: {e}")
                    break
                finally:
                    if recv_socket:
                        recv_socket.close()
                    if send_socket:
                        send_socket.close()
        except KeyboardInterrupt:
            print("\n[*] Traceroute aborted by user.")

    # --- 6. PORT SCANNER ---

    @staticmethod
    def port_scan(host: str, ports, timeout: float = 1.0, max_workers: int = 100):
        """Sweeps a list of TCP ports on a host concurrently, reporting which are open."""
        print(f"[*] Scanning TCP {host} across {len(ports)} port(s)...")

        def _probe(port):
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return True
            except OSError:
                return False

        open_ports = []
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as pool:
                futures = {pool.submit(_probe, port): port for port in ports}
                for future in concurrent.futures.as_completed(futures):
                    port = futures[future]
                    if future.result():
                        print(f"[+] {port}/tcp open")
                        open_ports.append(port)
        except KeyboardInterrupt:
            print("\n[*] Scan aborted by user.")

        open_ports.sort()
        summary = f" -> {', '.join(str(p) for p in open_ports)}" if open_ports else ""
        print(f"\n[*] Scan complete: {len(open_ports)}/{len(ports)} open{summary}")


# --- CLI INTERFACE WITH CONTEXTUAL HELP ---

def _valid_port(value: str) -> int:
    """argparse type validator ensuring a value is a usable TCP port number (1-65535)."""
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port: '{value}' is not an integer")
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"invalid port: {port} (must be between 1 and 65535)")
    return port


def _parse_ports(value: str) -> list:
    """argparse type validator: parses a comma-separated list of ports and/or dash ranges (e.g. '22,80,1000-1010')."""
    ports = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, _, end_s = part.partition("-")
            start, end = _valid_port(start_s), _valid_port(end_s)
            if start > end:
                raise argparse.ArgumentTypeError(f"invalid port range: '{part}' (start must be <= end)")
            ports.extend(range(start, end + 1))
        else:
            ports.append(_valid_port(part))
    if not ports:
        raise argparse.ArgumentTypeError("no ports specified")
    seen = set()
    unique_ports = []
    for p in ports:
        if p not in seen:
            seen.add(p)
            unique_ports.append(p)
    return unique_ports


def main():
    # Force line-buffered stdout so log lines (e.g. "listen" connections) appear
    # immediately instead of waiting on Python's block-buffering in PowerShell/Windows.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    parser = argparse.ArgumentParser(
        prog="ByteGrylls",
        description="ByteGrylls: Survival-ready pure Python network diagnostic tool (Zero external dependencies).",
        epilog="Examples:\n"
               "  python3 ByteGrylls.py nc 1.1.1.1 80\n"
               "  python3 ByteGrylls.py nc 1.1.1.1 80 -d \"GET / HTTP/1.0\\r\\n\\r\\n\"\n"
               "  python3 ByteGrylls.py nc 8.8.8.8 53 -u -d \"ping\"\n"
               "  python3 ByteGrylls.py listen 0.0.0.0 4444\n"
               "  python3 ByteGrylls.py listen 0.0.0.0 5353 -u\n"
               "  python3 ByteGrylls.py dns example.com --server 8.8.8.8\n"
               "  python3 ByteGrylls.py dns example.com -6\n"
               "  python3 ByteGrylls.py dns 8.8.8.8 -x\n"
               "  python3 ByteGrylls.py scan 10.0.0.5 22,80,443\n"
               "  python3 ByteGrylls.py scan 10.0.0.5 1-1024 -t 0.5\n"
               "  sudo python3 ByteGrylls.py ping google.com -c 5\n"
               "  sudo python3 ByteGrylls.py traceroute 8.8.8.8 -m 15\n\n"
               "Author: David Avanzini\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--version", action="version", version=f"ByteGrylls {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available diagnostic commands")

    # Netcat Client Subcommand
    nc_parser = subparsers.add_parser("nc", help="Test TCP/UDP port connection (Netcat client mode)")
    nc_parser.add_argument("host", type=str, help="Target host IPv4 or domain name")
    nc_parser.add_argument("port", type=_valid_port, help="Target port number (1-65535)")
    nc_parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Connection timeout in seconds (default: 3.0)")
    nc_parser.add_argument("-d", "--data", type=str, default=None,
                            help="Literal text to send after connecting (defaults to piped stdin, if any)")
    nc_parser.add_argument("-u", "--udp", action="store_true", help="Use UDP instead of TCP")

    # Netcat Listen Subcommand
    listen_parser = subparsers.add_parser("listen", help="Open a local TCP/UDP socket listener (Netcat server mode)")
    listen_parser.add_argument("host", type=str, nargs="?", default="0.0.0.0", help="Binding IP address (default: 0.0.0.0)")
    listen_parser.add_argument("port", type=_valid_port, help="Listening port number (1-65535)")
    listen_parser.add_argument("-u", "--udp", action="store_true", help="Use UDP instead of TCP")

    # DNS Query Subcommand
    dns_parser = subparsers.add_parser("dns", help="Perform native DNS lookup via UDP")
    dns_parser.add_argument("domain", type=str, help="Domain name to resolve (or IP address with -x/--reverse)")
    dns_parser.add_argument("-s", "--server", type=str, default="8.8.8.8", help="DNS server IPv4 address (default: 8.8.8.8)")
    dns_parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Query timeout in seconds (default: 3.0)")
    dns_parser.add_argument("-6", "--ipv6", action="store_true", help="Query AAAA (IPv6) instead of A (IPv4)")
    dns_parser.add_argument("-x", "--reverse", action="store_true",
                             help="Reverse lookup: treat the argument as an IP and query its PTR record")

    # Port Scanner Subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a range of TCP ports on a host (Port scanner mode)")
    scan_parser.add_argument("host", type=str, help="Target host IPv4/IPv6 or domain name")
    scan_parser.add_argument("ports", type=_parse_ports,
                              help="Ports to scan: comma-separated list and/or ranges, e.g. '22,80,443' or '1-1024'")
    scan_parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Per-port connection timeout in seconds (default: 1.0)")
    scan_parser.add_argument("-w", "--workers", type=int, default=100, help="Maximum concurrent probes (default: 100)")

    # ICMP Ping Subcommand
    ping_parser = subparsers.add_parser("ping", help="Send ICMP Echo Requests (Requires Root/Sudo)")
    ping_parser.add_argument("host", type=str, help="Target host IPv4 or domain name")
    ping_parser.add_argument("-c", "--count", type=int, default=4, help="Number of packets to send (default: 4)")
    ping_parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Packet reply timeout in seconds (default: 2.0)")
    ping_parser.add_argument("-6", "--ipv6", action="store_true", help="Prefer IPv6 when the host resolves to both families")

    # ICMP Traceroute Subcommand
    trace_parser = subparsers.add_parser("traceroute", help="Trace IP packet route (Requires Root/Sudo)")
    trace_parser.add_argument("host", type=str, help="Target host IPv4 or domain name")
    trace_parser.add_argument("-m", "--max-hops", type=int, default=30, help="Maximum number of hops (default: 30)")
    trace_parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Hop reply timeout in seconds (default: 2.0)")
    trace_parser.add_argument("-6", "--ipv6", action="store_true", help="Prefer IPv6 when the host resolves to both families")

    # Display general help if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    tool = ByteGrylls()

    try:
        if args.command == "nc":
            if args.data is not None:
                data = args.data.encode()
            elif not sys.stdin.isatty():
                data = sys.stdin.buffer.read()
            else:
                data = None
            tool.netcat_client(args.host, args.port, args.timeout, data, args.udp)
        elif args.command == "listen":
            tool.netcat_listen(args.host, args.port, args.udp)
        elif args.command == "dns":
            record_type = "PTR" if args.reverse else ("AAAA" if args.ipv6 else "A")
            tool.dns_query(args.domain, args.server, args.timeout, record_type)
        elif args.command == "scan":
            tool.port_scan(args.host, args.ports, args.timeout, args.workers)
        elif args.command == "ping":
            tool.ping(args.host, args.count, args.timeout, args.ipv6)
        elif args.command == "traceroute":
            tool.traceroute(args.host, args.max_hops, args.timeout, args.ipv6)
    except KeyboardInterrupt:
        print("\n[*] Aborted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
