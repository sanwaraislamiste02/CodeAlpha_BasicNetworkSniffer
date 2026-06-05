#!/usr/bin/env python
# coding: utf-8

# In[ ]:


#!/usr/bin/env python3
import argparse
import datetime
import sys
import os

# ── Dependency check ─────────────────────────────────────────────────────────
try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw, wrpcap, get_if_list
    )
except ImportError:
    sys.exit("[ERROR] scapy is not installed. Run:  pip install scapy")

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ""
    class Style:
        RESET_ALL = BRIGHT = DIM = ""

# ── Privilege check ───────────────────────────────────────────────────────────
if os.name == "nt":
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        sys.exit("[ERROR] Administrative privileges required. Please run Command Prompt as Administrator.")
elif os.geteuid() != 0:
    sys.exit("[ERROR] Please run as root:  sudo python3 network_sniffer.py")

# ── Packet counter ────────────────────────────────────────────────────────────
stats = {
    "total": 0, "tcp": 0, "udp": 0, "icmp": 0,
    "arp": 0, "dns": 0, "ipv6": 0, "other": 0
}
captured_packets = []

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def timestamp() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def fmt_payload(raw_bytes: bytes, max_len: int = 64) -> str:
    """Return a safe ASCII + hex preview of raw payload bytes."""
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in raw_bytes[:max_len])
    hex_part   = raw_bytes[:max_len].hex()
    truncated  = "…" if len(raw_bytes) > max_len else ""
    return f"  ASCII : {ascii_part}{truncated}\n  HEX   : {hex_part}{truncated}"


def separator(char: str = "─", width: int = 70) -> str:
    return Fore.WHITE + Style.DIM + char * width


# ─────────────────────────────────────────────────────────────────────────────
# Protocol handlers
# ─────────────────────────────────────────────────────────────────────────────

def handle_tcp(pkt, src_ip: str, dst_ip: str):
    stats["tcp"] += 1
    tcp = pkt[TCP]
    flags = tcp.sprintf("%flags%")
    service = _guess_service(tcp.sport, tcp.dport)

    print(f"{Fore.GREEN}[TCP]{Style.RESET_ALL}  "
          f"{Fore.CYAN}{src_ip}:{tcp.sport}{Style.RESET_ALL} "
          f"→ {Fore.YELLOW}{dst_ip}:{tcp.dport}{Style.RESET_ALL}  "
          f"flags={Fore.MAGENTA}{flags}{Style.RESET_ALL}  "
          f"seq={tcp.seq}  ack={tcp.ack}  win={tcp.window}  "
          f"{Fore.WHITE}[{service}]{Style.RESET_ALL}")

    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw])
        print(f"  {Fore.WHITE}Payload ({len(payload)} bytes):{Style.RESET_ALL}")
        print(fmt_payload(payload))


def handle_udp(pkt, src_ip: str, dst_ip: str):
    stats["udp"] += 1
    udp = pkt[UDP]
    service = _guess_service(udp.sport, udp.dport)
    print(f"{Fore.BLUE}[UDP]{Style.RESET_ALL}  "
          f"{Fore.CYAN}{src_ip}:{udp.sport}{Style.RESET_ALL} "
          f"→ {Fore.YELLOW}{dst_ip}:{udp.dport}{Style.RESET_ALL}  "
          f"len={udp.len}  {Fore.WHITE}[{service}]{Style.RESET_ALL}")

    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            print(f"  {Fore.MAGENTA}DNS Query:{Style.RESET_ALL} {qname}")
        stats["dns"] += 1

    elif pkt.haslayer(Raw):
        payload = bytes(pkt[Raw])
        print(f"  {Fore.WHITE}Payload ({len(payload)} bytes):{Style.RESET_ALL}")
        print(fmt_payload(payload))


def handle_icmp(pkt, src_ip: str, dst_ip: str):
    stats["icmp"] += 1
    icmp = pkt[ICMP]
    icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Unreachable",
                  11: "Time Exceeded", 5: "Redirect"}
    type_str = icmp_types.get(icmp.type, f"Type {icmp.type}")
    print(f"{Fore.RED}[ICMP]{Style.RESET_ALL}  "
          f"{Fore.CYAN}{src_ip}{Style.RESET_ALL} "
          f"→ {Fore.YELLOW}{dst_ip}{Style.RESET_ALL}  "
          f"type={Fore.MAGENTA}{type_str}{Style.RESET_ALL}  code={icmp.code}")


def handle_arp(pkt):
    stats["arp"] += 1
    arp = pkt[ARP]
    op = "REQUEST" if arp.op == 1 else "REPLY"
    print(f"{Fore.YELLOW}[ARP]{Style.RESET_ALL}   "
          f"{Fore.CYAN}{arp.psrc} ({arp.hwsrc}){Style.RESET_ALL} "
          f"→ {Fore.YELLOW}{arp.pdst}{Style.RESET_ALL}  "
          f"op={Fore.MAGENTA}{op}{Style.RESET_ALL}")


def handle_other(pkt):
    stats["other"] += 1
    summary = pkt.summary()
    print(f"{Fore.WHITE}[???]{Style.RESET_ALL}   {summary[:120]}")


# ─────────────────────────────────────────────────────────────────────────────
# Service guesser
# ─────────────────────────────────────────────────────────────────────────────

_PORT_MAP = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 27017: "MongoDB",
}

def _guess_service(sport: int, dport: int) -> str:
    return _PORT_MAP.get(dport) or _PORT_MAP.get(sport) or "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Main callback
# ─────────────────────────────────────────────────────────────────────────────

def packet_callback(pkt, save_enabled=False):
    stats["total"] += 1
    if save_enabled:
        captured_packets.append(pkt)

    ts = timestamp()
    print(f"\n{separator()}\n{Fore.WHITE}#{stats['total']:>4}  {ts}{Style.RESET_ALL}")

    try:
        # ── IPv4 ──────────────────────────────────────────────────────────
        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst
            ttl, size = ip.ttl, len(pkt)
            print(f"  IP   src={src_ip}  dst={dst_ip}  TTL={ttl}  size={size}B  "
                  f"proto={ip.proto}")

            if pkt.haslayer(TCP):
                handle_tcp(pkt, src_ip, dst_ip)
            elif pkt.haslayer(UDP):
                handle_udp(pkt, src_ip, dst_ip)
            elif pkt.haslayer(ICMP):
                handle_icmp(pkt, src_ip, dst_ip)
            else:
                handle_other(pkt)

        # ── IPv6 ──────────────────────────────────────────────────────────
        elif pkt.haslayer(IPv6):
            stats["ipv6"] += 1
            ip6 = pkt[IPv6]
            src_ip, dst_ip = ip6.src, ip6.dst
            print(f"  IPv6 src={src_ip}  dst={dst_ip}  hlim={ip6.hlim}")

            if pkt.haslayer(TCP):
                handle_tcp(pkt, src_ip, dst_ip)
            elif pkt.haslayer(UDP):
                handle_udp(pkt, src_ip, dst_ip)
            else:
                handle_other(pkt)

        # ── ARP ───────────────────────────────────────────────────────────
        elif pkt.haslayer(ARP):
            handle_arp(pkt)

        # ── Other ─────────────────────────────────────────────────────────
        else:
            handle_other(pkt)

    except Exception as exc:
        print(f"{Fore.RED}[PARSE ERROR]{Style.RESET_ALL} {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

def print_summary():
    print(f"\n{separator('═')}")
    print(f"{Fore.WHITE}{Style.BRIGHT}   CAPTURE SUMMARY{Style.RESET_ALL}")
    print(separator())
    print(f"  {'Total packets':<20}: {stats['total']}")
    print(f"  {'TCP':<20}: {stats['tcp']}")
    print(f"  {'UDP':<20}: {stats['udp']}")
    print(f"  {'ICMP':<20}: {stats['icmp']}")
    print(f"  {'ARP':<20}: {stats['arp']}")
    print(f"  {'DNS (via UDP)':<20}: {stats['dns']}")
    print(f"  {'IPv6':<20}: {stats['ipv6']}")
    print(f"  {'Other':<20}: {stats['other']}")
    print(separator("═"))


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer — CodeAlpha Cybersecurity Task 1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  sudo python3 network_sniffer.py
  sudo python3 network_sniffer.py --count 100 --filter "tcp port 80"
  sudo python3 network_sniffer.py --iface eth0 --save capture.pcap
  sudo python3 network_sniffer.py --list-ifaces
"""
    )
    parser.add_argument("--iface",  "-i", default=None,
                        help="Network interface to sniff on (default: all)")
    parser.add_argument("--count",  "-c", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--filter", "-f", default=None,
                        help="BPF filter string (e.g. 'tcp', 'udp port 53', 'host 1.1.1.1')")
    parser.add_argument("--save",   "-s", default=None,
                        help="Save captured packets to a .pcap file")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="List available network interfaces and exit")

    # FIX: Safely parse arguments whether run from standard terminal or inside Jupyter/IPython
    if any('jupyter' in arg or 'ipykernel' in arg for arg in sys.argv):
        args = parser.parse_args([]) # Clean fallback empty list to prevent Jupyter flag hijacking
    else:
        args = parser.parse_args()

    if args.list_ifaces:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  {iface}")
        sys.exit(0)

    # ── Banner ───────────────────────────────────────────────────────────
    print(f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════╗
║         BASIC NETWORK SNIFFER — CodeAlpha Internship Task 1          ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
  Interface : {args.iface or 'ALL'}
  BPF Filter: {args.filter or 'none'}
  Packet cap: {args.count if args.count else 'unlimited'}
  Save to   : {args.save or 'not saving'}
  Press Ctrl+C to stop.
""")

    # ── Sniff ────────────────────────────────────────────────────────────
    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            count=args.count,
            prn=lambda p: packet_callback(p, save_enabled=bool(args.save)),
            store=False, 
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Sniffing stopped by user.{Style.RESET_ALL}")
    except PermissionError:
        sys.exit(f"{Fore.RED}[ERROR] Permission denied. Run with elevated administrative privileges.{Style.RESET_ALL}")
    except Exception as exc:
        sys.exit(f"{Fore.RED}[ERROR] {exc}{Style.RESET_ALL}")

    # ── Save .pcap ───────────────────────────────────────────────────────
    if args.save and captured_packets:
        wrpcap(args.save, captured_packets)
        print(f"{Fore.GREEN}[✓] Saved {len(captured_packets)} packets to '{args.save}'{Style.RESET_ALL}")

    print_summary()



if __name__ == "__main__":
    main() 


# In[ ]:




