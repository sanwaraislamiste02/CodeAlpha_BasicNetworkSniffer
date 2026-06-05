# CodeAlpha_Network_Sniffer

A robust, terminal-based **Network Sniffer** application developed during my Cybersecurity Internship at **CodeAlpha** (Task 1). This tool captures real-time network packets, extracts layered protocol metadata, and formats raw application payloads for deep packet inspection.

## Main Features
- **Multi-Protocol Deep Parsing:** Supports IPv4, IPv6, TCP, UDP, ICMP, and ARP packets.
- **Payload Inspection:** Automatically decodes raw packet data into side-by-side **HEX** and **ASCII** views.
- **Traffic Logging:** Prints granular metrics including packet index sequence, timestamps, source/destination IPs, ports, TTL, window sizes, and flags.
- **Stability & Scale:** Benchmarked and verified to handle continuous high-volume capture loads over **9,000+ packets** without performance drops.
- **Post-Session Summaries:** Generates an organized traffic matrix detailing total packet breakdowns by protocol upon stopping.

## Built With
- **Python 3.13**
- **Scapy** (Core Packet Crafting & Sniffing Engine)
- **Colorama** (Terminal Interface Formatting)
