#!/usr/bin/env python3
"""
ByteGrylls - Pure Python Network Diagnostic Tool
No external dependencies. Powered strictly by Python 3 standard library.
"""

import argparse
import os
import select
import socket
import struct
import sys
import time


class ByteGrylls:
    """
    Core engine for network diagnostics:
    Simulates Netcat (TCP/UDP), DNS resolution, ICMP Ping, and ICMP Traceroute.
    """

    # --- 1. NETCAT & PORT TESTING ---

    @staticmethod
    def netcat_client(host: str, port: int, timeout: float = 3.0) -> bool:
        """Connects to a remote TCP port to test availability (Netcat client mode)."""
        print(f"[*] Connecting to TCP {host}:{port}...")
        start_time = time.time()
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                elapsed = (time.time() - start_time) * 1000
                print(f"[+] Successfully connected to {host}:{port} in {elapsed:.2f} ms")
                return True
        except socket.timeout:
            print(f"[-] Error: Connection to {host}:{port} timed out.")
        except ConnectionRefusedError:
            print(f"[-] Error: Connection refused by {host}:{port}.")
        except Exception as e:
            print(f"[-] Connection error: {e}")
        return False

    @staticmethod
    def netcat_listen(host: str, port: int):
        """Opens a local TCP socket and listens for incoming connections (Netcat server mode)."""
        print(f"[*] Binding TCP socket listener on {host}:{port}...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                s.listen(1)
                print("[+] Listening for incoming connections... (Press Ctrl+C to abort)")
                conn, addr = s.accept()
                with conn:
                    print(f"[+] Incoming connection established from {addr[0]}:{addr[1]}")
                    data = conn.recv(1024)
                    print(f"[Received Data]: {data.decode(errors='replace')}")
        except KeyboardInterrupt:
            print("\n[*] Listener stopped by user.")
        except Exception as e:
            print(f"[-] Listener error: {e}")

    # --- 2. NATIVE DNS QUERY ---

    @staticmethod
    def dns_query(hostname: str, dns_server: str = "8.8.8.8", timeout: float = 3.0):
        """Performs a raw UDP DNS A-record query without third-party DNS libraries."""
        print(f"[*] Querying DNS record A for '{hostname}' via server {dns_server}...")

        # Construct DNS Header (12 bytes)
        # Transaction ID, Flags (Standard query with recursion), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        transaction_id = 0x1234
        flags = 0x0100
        header = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0)

        # Construct Question Section (qname + qtype + qclass)
        qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in hostname.split(".")) + b"\x00"
        qtype = struct.pack("!H", 1)   # Type A (IPv4)
        qclass = struct.pack("!H", 1)  # Class IN (Internet)

        query_packet = header + qname + qtype + qclass

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                start_time = time.time()
                s.sendto(query_packet, (dns_server, 53))
                response, _ = s.recvfrom(1024)
                elapsed = (time.time() - start_time) * 1000

                # Basic parsing of answer count (ANCOUNT)
                ancount = struct.unpack("!H", response[6:8])[0]
                if ancount > 0:
                    # Extracts the last 4 bytes corresponding to the returned IPv4 address
                    ip_bytes = response[-4:]
                    ip_str = socket.inet_ntoa(ip_bytes)
                    print(f"[+] Resolved: {hostname} -> {ip_str} ({elapsed:.2f} ms)")
                    return ip_str
                else:
                    print(f"[-] DNS server returned 0 A-records for {hostname}.")
        except Exception as e:
            print(f"[-] DNS Query failed: {e}")
        return None

    # --- 3. ICMP HELPER ---

    @staticmethod
    def _checksum(source_string: bytes) -> int:
        """Calculates the Internet Checksum required for raw ICMP headers."""
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

    # --- 4. ICMP PING ---

    def ping(self, dest_host: str, count: int = 4, timeout: float = 2.0):
        """Sends raw ICMP Echo Requests (Ping). Requires root/admin privileges."""
        try:
            dest_ip = socket.gethostbyname(dest_host)
        except socket.gaierror:
            print(f"[-] Cannot resolve host: {dest_host}")
            return

        print(f"[*] PING {dest_host} ({dest_ip}):")

        for i in range(count):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                    s.settimeout(timeout)

                    # Build ICMP Echo Request header (Type 8, Code 0)
                    header = struct.pack("bbHHh", 8, 0, 0, os.getpid() & 0xFFFF, i + 1)
                    data = struct.pack("d", time.time())

                    # Calculate and pack valid checksum
                    chksum = self._checksum(header + data)
                    header = struct.pack("bbHHh", 8, 0, socket.htons(chksum), os.getpid() & 0xFFFF, i + 1)
                    packet = header + data

                    s.sendto(packet, (dest_ip, 1))

                    start_time = time.time()
                    ready = select.select([s], [], [], timeout)
                    if not ready[0]:
                        print(f" Request timeout for icmp_seq {i+1}")
                        continue

                    recv_packet, addr = s.recvfrom(1024)
                    time_received = time.time()

                    # Unpack ICMP header from payload offset
                    icmp_header = recv_packet[20:28]
                    type_val, _, _, _, sequence = struct.unpack("bbHHh", icmp_header)

                    if type_val == 0:  # Echo Reply
                        rtt = (time_received - start_time) * 1000
                        print(f" 64 bytes from {addr[0]}: icmp_seq={sequence} rtt={rtt:.2f} ms")

            except PermissionError:
                print("[-] PERMISSION ERROR: ICMP Ping requires root/administrator privileges for raw sockets.")
                break
            except Exception as e:
                print(f"[-] Ping error: {e}")

    # --- 5. ICMP TRACEROUTE ---

    def traceroute(self, dest_host: str, max_hops: int = 30, timeout: float = 2.0):
        """Executes a traceroute by incrementally increasing the IP Time-To-Live (TTL)."""
        try:
            dest_ip = socket.gethostbyname(dest_host)
        except socket.gaierror:
            print(f"[-] Cannot resolve host: {dest_host}")
            return

        print(f"[*] Traceroute to {dest_host} ({dest_ip}), max {max_hops} hops:")

        for ttl in range(1, max_hops + 1):
            recv_socket = None
            send_socket = None
            try:
                recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                recv_socket.settimeout(timeout)
                recv_socket.bind(("", 0))

                send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

                header = struct.pack("bbHHh", 8, 0, 0, os.getpid() & 0xFFFF, ttl)
                data = struct.pack("d", time.time())
                chksum = self._checksum(header + data)
                header = struct.pack("bbHHh", 8, 0, socket.htons(chksum), os.getpid() & 0xFFFF, ttl)
                packet = header + data

                start_time = time.time()
                send_socket.sendto(packet, (dest_ip, 1))

                try:
                    _, curr_addr = recv_socket.recvfrom(512)
                    elapsed = (time.time() - start_time) * 1000
                    curr_addr = curr_addr[0]
                except socket.timeout:
                    print(f" {ttl:2d}  * * * (Request Timed Out)")
                    continue

                print(f" {ttl:2d}  {curr_addr}  {elapsed:.2f} ms")

                if curr_addr == dest_ip:
                    print("[+] Target reached successfully!")
                    break

            except PermissionError:
                print("[-] PERMISSION ERROR: Traceroute requires root/administrator privileges for raw sockets.")
                break
            finally:
                if recv_socket:
                    recv_socket.close()
                if send_socket:
                    send_socket.close()


# --- CLI INTERFACE WITH CONTEXTUAL HELP ---

def main():
    parser = argparse.ArgumentParser(
        prog="ByteGrylls",
        description="ByteGrylls: Survival-ready pure Python network diagnostic tool (Zero external dependencies).",
        epilog="Examples:\n"
               "  python3 byte_grylls.py nc 1.1.1.1 80\n"
               "  python3 byte_grylls.py listen 0.0.0.0 4444\n"
               "  python3 byte_grylls.py dns example.com --server 8.8.8.8\n"
               "  sudo python3 byte_grylls.py ping google.com -c 5\n"
               "  sudo python3 byte_grylls.py traceroute 8.8.8.8 -m 15\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", help="Available diagnostic commands")

    # Netcat Client Subcommand
    nc_parser = subparsers.add_parser("nc", help="Test TCP port connection (Netcat client mode)")
    nc_parser.add_argument("host", type=str, help="Target host IPv4 or domain name")
    nc_parser.add_argument("port", type=int, help="Target TCP port number")
    nc_parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Connection timeout in seconds (default: 3.0)")

    # Netcat Listen Subcommand
    listen_parser = subparsers.add_parser("listen", help="Open a local TCP socket listener (Netcat server mode)")
    listen_parser.add_argument("host", type=str, nargs="?", default="0.0.0.0", help="Binding IP address (default: 0.0.0.0)")
    listen_parser.add_argument("port", type=int, help="Listening TCP port number")

    # DNS Query Subcommand
    dns_parser = subparsers.add_parser("dns", help="Perform native DNS IPv4 lookup via UDP")
    dns_parser.add_argument("domain", type=str, help="Domain name to resolve")
    dns_parser.add_argument("-s", "--server", type=str, default="8.8.8.8", help="DNS server IPv4 address (default: 8.8.8.8)")
    dns_parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Query timeout in seconds (default: 3.0)")

    # ICMP Ping Subcommand
    ping_parser = subparsers.add_parser("ping", help="Send ICMP Echo Requests (Requires Root/Sudo)")
    ping_parser.add_argument("host", type=str, help="Target host IPv4 or domain name")
    ping_parser.add_argument("-c", "--count", type=int, default=4, help="Number of packets to send (default: 4)")
    ping_parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Packet reply timeout in seconds (default: 2.0)")

    # ICMP Traceroute Subcommand
    trace_parser = subparsers.add_parser("traceroute", help="Trace IP packet route (Requires Root/Sudo)")
    trace_parser.add_argument("host", type=str, help="Target host IPv4 or domain name")
    trace_parser.add_argument("-m", "--max-hops", type=int, default=30, help="Maximum number of hops (default: 30)")
    trace_parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Hop reply timeout in seconds (default: 2.0)")

    # Display general help if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    tool = ByteGrylls()

    if args.command == "nc":
        tool.netcat_client(args.host, args.port, args.timeout)
    elif args.command == "listen":
        tool.netcat_listen(args.host, args.port)
    elif args.command == "dns":
        tool.dns_query(args.domain, args.server, args.timeout)
    elif args.command == "ping":
        tool.ping(args.host, args.count, args.timeout)
    elif args.command == "traceroute":
        tool.traceroute(args.host, args.max_hops, args.timeout)


if __name__ == "__main__":
    main()