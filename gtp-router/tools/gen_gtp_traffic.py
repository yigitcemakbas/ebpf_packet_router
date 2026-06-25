#!/usr/bin/env python3
"""
gen_gtp_traffic.py — Scapy-based GTP-U traffic generator for XDP router testing.

Usage (root required for raw socket send):
    # Send 10 GTP-U packets with TEID=0xDEAD on eth0
    sudo python3 gen_gtp_traffic.py --iface eth0 --teid 0xDEAD --count 10

    # Vary inner UE IP to exercise ueip_map lookup
    sudo python3 gen_gtp_traffic.py --iface eth0 --teid 0x1234 \
        --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \
        --inner-src 10.1.0.1 --inner-dst 10.1.0.2 \
        --count 100 --pps 50

Install:
    pip install scapy
"""

import argparse
import time
import struct
import sys

try:
    from scapy.all import (
        Ether, IP, UDP, Raw, sendp, conf, get_if_hwaddr
    )
except ImportError:
    sys.exit("scapy not found — pip install scapy")



def build_gtpu_header(teid: int, payload_len: int,
                      has_optional: bool = False) -> bytes:
    """
    Build an 8-byte GTP-U G-PDU header.

    Wire format (8 bytes mandatory):
      Flags (1B) | MsgType=0xFF (1B) | Length (2B) | TEID (4B)

    Flags:
      Version=1 (bits 7-5 = 001)
      PT=1      (bit 4)
      E=S=PN=0  (bits 2-0, no optional header)
    """
    flags    = 0x30          # 0b0011_0000: Version=1, PT=1, E=S=PN=0
    msg_type = 0xFF          # G-PDU
    # GTP length = total length of GTP payload + 8-byte GTP header
    # but the Length field itself excludes the mandatory 8 bytes of GTP hdr,
    # so: length = payload_len  (inner IP)
    length   = payload_len
    header   = struct.pack("!BBHI", flags, msg_type, length, teid)
    return header


def craft_gtpu_packet(
    src_mac: str, dst_mac: str,
    outer_src_ip: str, outer_dst_ip: str,
    inner_src_ip: str, inner_dst_ip: str,
    teid: int,
    payload: bytes = b"\x00" * 64,
) -> bytes:
    # Return a complete Ethernet frame carrying a GTP-U G-PDU.

   
    inner_ip = IP(src=inner_src_ip, dst=inner_dst_ip) / Raw(load=payload)
    inner_bytes = bytes(inner_ip)

    gtp_hdr = build_gtpu_header(teid, len(inner_bytes))

    # Build the UDP payload manually so scapy doesn't try to layer GTP
    udp_payload = gtp_hdr + inner_bytes

    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=outer_src_ip, dst=outer_dst_ip, ttl=64)
        / UDP(sport=2152, dport=2152)
        / Raw(load=udp_payload)
    )
    return pkt



def main():
    ap = argparse.ArgumentParser(description="GTP-U traffic generator")
    ap.add_argument("--iface",      default="eth0",       help="Egress interface")
    ap.add_argument("--teid",       default="0xDEAD",     help="GTP-U TEID (hex or dec)")
    ap.add_argument("--src-ip",     default="192.168.1.1",help="Outer source IP")
    ap.add_argument("--dst-ip",     default="192.168.1.2",help="Outer destination IP")
    ap.add_argument("--inner-src",  default="10.1.0.1",   help="Inner (UE) source IP")
    ap.add_argument("--inner-dst",  default="10.1.0.2",   help="Inner (UE) dest IP")
    ap.add_argument("--count",      default=10, type=int,  help="Packets to send")
    ap.add_argument("--pps",        default=10, type=float,help="Packets per second")
    ap.add_argument("--dst-mac",    default=None,          help="Override destination MAC")
    ap.add_argument("--payload-len",default=64, type=int,  help="Inner payload bytes")
    args = ap.parse_args()

    teid = int(args.teid, 0)
    iface = args.iface

    src_mac = get_if_hwaddr(iface)
    dst_mac = args.dst_mac or "ff:ff:ff:ff:ff:ff"   # broadcast default

    interval = 1.0 / args.pps if args.pps > 0 else 0
    payload  = bytes(range(args.payload_len % 256)) * (args.payload_len // 256 + 1)
    payload  = payload[:args.payload_len]

    print(f"[gtp-gen] Interface : {iface}  TEID=0x{teid:08X}")
    print(f"          Outer IP  : {args.src_ip} → {args.dst_ip}")
    print(f"          Inner IP  : {args.inner_src} → {args.inner_dst}")
    print(f"          Count={args.count}  PPS={args.pps}")
    print()

    sent = 0
    for i in range(args.count):
        pkt = craft_gtpu_packet(
            src_mac=src_mac, dst_mac=dst_mac,
            outer_src_ip=args.src_ip, outer_dst_ip=args.dst_ip,
            inner_src_ip=args.inner_src, inner_dst_ip=args.inner_dst,
            teid=teid,
            payload=payload,
        )
        sendp(pkt, iface=iface, verbose=False)
        sent += 1
        if (i + 1) % 10 == 0 or (i + 1) == args.count:
            print(f"\r[gtp-gen] Sent {sent}/{args.count}", end="", flush=True)
        if interval:
            time.sleep(interval)

    print(f"\n[gtp-gen] Done. {sent} packets sent.")


if __name__ == "__main__":
    main()