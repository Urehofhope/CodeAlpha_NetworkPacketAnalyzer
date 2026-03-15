# CodeAlpha_NetworkPacketAnalyzer
# A Python packet analyzer built during CodeAlpha internship
#!/usr/bin/env python3

import socket
import struct
import textwrap
import argparse
import time
import sys
from datetime import datetime
from collections import defaultdict

SCAPY_AVAILABLE = False
try:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from scapy.packet import Packet, Raw
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.utils import wrpcap, rdpcap
        from scapy.sendrecv import sniff
        try:
            from scapy.layers.dns import DNS
        except Exception:
            DNS = None
    SCAPY_AVAILABLE = True
except Exception:
    pass


class C:
    RESET   = "\033[0m";  BOLD  = "\033[1m";  DIM   = "\033[2m"
    TCP     = "\033[38;5;81m";   UDP  = "\033[38;5;148m"
    ICMP    = "\033[38;5;208m";  ARP  = "\033[38;5;177m"
    DNS     = "\033[38;5;222m";  HTTP = "\033[38;5;119m"
    OTHER   = "\033[38;5;245m";  SRC  = "\033[38;5;159m"
    DST     = "\033[38;5;210m";  INFO = "\033[38;5;228m"
    PAYLOAD = "\033[38;5;187m";  HEADER = "\033[38;5;255m"
    ACCENT  = "\033[38;5;99m";   GOOD = "\033[38;5;84m"
    WARN    = "\033[38;5;196m";  LABEL = "\033[38;5;240m"

def col(text, c):  return f"{c}{text}{C.RESET}"
def bold(text):    return f"{C.BOLD}{text}{C.RESET}"


PROTO_COLOR = {
    "TCP": C.TCP, "UDP": C.UDP, "ICMP": C.ICMP,
    "ARP": C.ARP, "DNS": C.DNS, "HTTP": C.HTTP,
}

WELL_KNOWN_PORTS = {
    20:"FTP-data", 21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP",
    53:"DNS", 67:"DHCP-S", 68:"DHCP-C", 80:"HTTP", 110:"POP3",
    123:"NTP", 143:"IMAP", 161:"SNMP", 443:"HTTPS", 445:"SMB",
    465:"SMTPS", 587:"SMTP-TLS", 993:"IMAPS", 995:"POP3S",
    1433:"MSSQL", 3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL",
    5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
    27017:"MongoDB",
}

IP_PROTO_NAMES = {1:"ICMP", 6:"TCP", 17:"UDP", 47:"GRE", 50:"ESP", 89:"OSPF"}

def port_label(port):
    name = WELL_KNOWN_PORTS.get(port, "")
    return f"{port}{col(f'({name})', C.LABEL)}" if name else str(port)

def proto_tag(name):
    c = PROTO_COLOR.get(name, C.OTHER)
    return col(f"{name:<5}", c)


class Stats:
    def __init__(self):
        self.total       = 0
        self.by_proto    = defaultdict(int)
        self.by_src      = defaultdict(int)
        self.by_dst      = defaultdict(int)
        self.bytes_total = 0
        self.start_time  = time.time()

    def record(self, proto, src, dst, size):
        self.total += 1
        self.by_proto[proto] += 1
        self.by_src[src] += 1
        self.by_dst[dst] += 1
        self.bytes_total += size

    def elapsed(self):
        return time.time() - self.start_time

    def summary(self):
        elapsed = self.elapsed()
        rate  = self.total / elapsed if elapsed > 0 else 0
        brate = self.bytes_total / elapsed if elapsed > 0 else 0

        lines = [
            "",
            col("╔══════════════════════════════════════╗", C.ACCENT),
            col("║       CAPTURE SESSION SUMMARY         ║", C.ACCENT),
            col("╚══════════════════════════════════════╝", C.ACCENT),
            f"  {col('Duration   :', C.LABEL)} {elapsed:.1f}s",
            f"  {col('Packets    :', C.LABEL)} {bold(str(self.total))}",
            f"  {col('Total bytes:', C.LABEL)} {self.bytes_total:,} B",
            f"  {col('Pkt/sec    :', C.LABEL)} {rate:.1f}",
            f"  {col('Bps        :', C.LABEL)} {brate:,.0f}",
            "",
            col("  Protocol Breakdown:", C.HEADER),
        ]
        for proto, count in sorted(self.by_proto.items(), key=lambda x: -x[1]):
            bar_len = int((count / max(self.total, 1)) * 20)
            bar     = "█" * bar_len + "░" * (20 - bar_len)
            pct     = count / max(self.total, 1) * 100
            c       = PROTO_COLOR.get(proto, C.OTHER)
            lines.append(f"    {col(f'{proto:<8}', c)} {bar} "
                         f"{col(f'{count:>4}', C.INFO)} ({pct:4.1f}%)")

        lines.append("")
        lines.append(col("  Top Sources:", C.HEADER))
        for src, cnt in sorted(self.by_src.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"    {col(src, C.SRC):<50} {col(str(cnt), C.INFO)}")

        lines.append("")
        lines.append(col("  Top Destinations:", C.HEADER))
        for dst, cnt in sorted(self.by_dst.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"    {col(dst, C.DST):<50} {col(str(cnt), C.INFO)}")

        lines.append("")
        return "\n".join(lines)


def fmt_payload(raw: bytes, max_bytes: int = 96) -> str:
    snippet = raw[:max_bytes]
    try:
        text = snippet.decode("utf-8", errors="strict")
        printable = "".join(c if c.isprintable() else "·" for c in text)
    except UnicodeDecodeError:
        printable = " ".join(f"{b:02x}" for b in snippet)
    wrapped  = textwrap.fill(printable, width=72,
                             initial_indent="    ", subsequent_indent="    ")
    trailer  = f" … +{len(raw)-max_bytes}B" if len(raw) > max_bytes else ""
    return (f"\n{col('  ╰─ payload:', C.LABEL)}"
            f"{col(trailer, C.LABEL)}\n{col(wrapped, C.PAYLOAD)}")


class Pkt:
    __slots__ = ("ts","proto","src","dst","sport","dport",
                 "size","flags","extra","payload")

    def __init__(self, proto, src, dst, size,
                 sport=None, dport=None, flags="", extra="", payload=b""):
        self.ts      = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.proto   = proto
        self.src     = src
        self.dst     = dst
        self.size    = size
        self.sport   = sport
        self.dport   = dport
        self.flags   = flags
        self.extra   = extra
        self.payload = payload

    def render(self, stats: Stats, verbose: bool) -> str:
        stats.record(self.proto, self.src, self.dst, self.size)

        flag_col = (C.GOOD if "SYN" in self.flags and "ACK" not in self.flags else
                    C.WARN if "RST" in self.flags or "FIN" in self.flags else
                    C.INFO)
        flags_str = col(self.flags, flag_col) if self.flags else ""

        if self.sport is not None:
            addr = (f"{col(self.src, C.SRC)}:{col(port_label(self.sport), C.INFO)}"
                    f"  →  "
                    f"{col(self.dst, C.DST)}:{col(port_label(self.dport), C.INFO)}")
        else:
            addr = f"{col(self.src, C.SRC)}  →  {col(self.dst, C.DST)}"

        parts  = [p for p in [addr, flags_str, self.extra] if p]
        detail = "  ".join(parts)

        line = (f"{col(self.ts, C.DIM)}  "
                f"{col(f'#{stats.total:<5}', C.LABEL)}  "
                f"{proto_tag(self.proto)}  "
                f"{col(f'{self.size:>5}B', C.LABEL)}  "
                f"{detail}")

        if verbose and self.payload:
            line += fmt_payload(self.payload)
        return line


# ─────────────────────────────────────────────────────────────────────────────
#  DEMO PACKETS  (no root, no scapy)
# ─────────────────────────────────────────────────────────────────────────────
def make_demo_packets():
    return [
        Pkt("TCP",  "10.0.0.5",       "93.184.216.34", 60,
            sport=52341, dport=80,  flags="SYN",
            extra="seq=1000  win=65535"),
        Pkt("TCP",  "93.184.216.34",  "10.0.0.5",      60,
            sport=80, dport=52341, flags="SYN+ACK",
            extra="seq=5000  ack=1001  win=28960"),
        Pkt("TCP",  "10.0.0.5",       "93.184.216.34", 54,
            sport=52341, dport=80,  flags="ACK",
            extra="seq=1001  ack=5001"),
        Pkt("HTTP", "10.0.0.5",       "93.184.216.34", 174,
            sport=52341, dport=80,  flags="PSH+ACK",
            extra="seq=1001",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetScope/1.0\r\n\r\n"),
        Pkt("DNS",  "10.0.0.5",       "8.8.8.8",       72,
            sport=33445, dport=53, flags="",
            extra="QUERY  name=api.github.com.  type=A",
            payload=b"\x00\x01\x01\x00\x00\x01api\x06github\x03com\x00"),
        Pkt("DNS",  "8.8.8.8",        "10.0.0.5",      88,
            sport=53, dport=33445, flags="",
            extra=col("RESPONSE  name=api.github.com.  answers=1  IP=140.82.121.5", C.DNS)),
        Pkt("ICMP", "10.0.0.5",       "10.0.0.1",      84,
            extra="Echo-Request  id=1  seq=1"),
        Pkt("ICMP", "10.0.0.1",       "10.0.0.5",      84,
            extra="Echo-Reply    id=1  seq=1"),
        Pkt("ARP",  "10.0.0.5",       "10.0.0.1",      42,
            extra="REQUEST  who-has 10.0.0.1?  tell aa:bb:cc:dd:ee:05"),
        Pkt("ARP",  "10.0.0.1",       "10.0.0.5",      42,
            extra="REPLY    10.0.0.1 is-at ff:00:aa:bb:cc:01"),
        Pkt("TCP",  "10.0.0.5",       "140.82.121.5",  60,
            sport=55001, dport=443, flags="SYN",
            extra="seq=9000  win=65535"),
        Pkt("TCP",  "140.82.121.5",   "10.0.0.5",      60,
            sport=443, dport=55001, flags="SYN+ACK",
            extra="seq=20000  ack=9001"),
        Pkt("UDP",  "10.0.0.5",       "216.239.35.4",  76,
            sport=123, dport=123,
            extra="NTP request  len=48",
            payload=bytes(range(48))),
        Pkt("TCP",  "10.0.0.5",       "93.184.216.34", 54,
            sport=52341, dport=80,  flags="FIN+ACK",
            extra="seq=1265  ack=5200"),
        Pkt("TCP",  "93.184.216.34",  "10.0.0.5",      54,
            sport=80, dport=52341, flags="FIN+ACK",
            extra="seq=5200  ack=1266"),
        Pkt("TCP",  "10.0.0.5",       "93.184.216.34", 54,
            sport=52341, dport=80,  flags="ACK",
            extra="seq=1266  ack=5201"),
    ]


def demo_mode(verbose: bool):
    print(col("\n  ── DEMO MODE  (16 synthetic packets — no root needed) ──\n", C.INFO))
    stats = Stats()
    for pkt in make_demo_packets():
        time.sleep(0.12)
        print(pkt.render(stats, verbose))
    print(stats.summary())


# ─────────────────────────────────────────────────────────────────────────────
#  RAW SOCKET CAPTURE
# ─────────────────────────────────────────────────────────────────────────────
def parse_ip_header(data):
    if len(data) < 20:
        return None
    iph  = struct.unpack("!BBHHHBBH4s4s", data[:20])
    ihl  = (iph[0] & 0xF) * 4
    return ihl, iph[6], socket.inet_ntoa(iph[8]), socket.inet_ntoa(iph[9]), iph[5]

def parse_tcp_header(data):
    if len(data) < 20:
        return None
    t      = struct.unpack("!HHLLBBHHH", data[:20])
    offset = (t[4] >> 4) * 4
    f      = t[5]
    fnames = (["SYN"] if f & 0x02 else []) + \
             (["ACK"] if f & 0x10 else []) + \
             (["FIN"] if f & 0x01 else []) + \
             (["RST"] if f & 0x04 else []) + \
             (["PSH"] if f & 0x08 else [])
    return t[0], t[1], t[2], t[3], offset, "+".join(fnames), t[6]

def parse_udp_header(data):
    if len(data) < 8:
        return None
    u = struct.unpack("!HHHH", data[:8])
    return u[0], u[1], u[2]

def raw_socket_capture(count: int, verbose: bool, stats: Stats):
    print(col("\n  [raw socket mode — scapy not available]\n", C.WARN))
    try:
        if sys.platform == "win32":
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((socket.gethostbyname(socket.gethostname()), 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(0x0800))
    except PermissionError:
        print(col("  ✗ Root / Administrator privileges required.", C.WARN))
        sys.exit(1)

    n = 0
    try:
        while count == 0 or n < count:
            raw, _ = s.recvfrom(65535)
            start  = 14 if sys.platform != "win32" else 0
            data   = raw[start:]
            r = parse_ip_header(data)
            if not r:
                continue
            ihl, proto_num, src, dst, ttl = r
            proto_name = IP_PROTO_NAMES.get(proto_num, f"IP/{proto_num}")
            size = len(raw)
            n   += 1
            sport = dport = None
            flags = ""
            extra = f"ttl={ttl}"
            payload = b""

            if proto_num == 6:
                r2 = parse_tcp_header(data[ihl:])
                if r2:
                    sport, dport, seq, ack, off, flags, win = r2
                    extra   = f"seq={seq}  ack={ack}  win={win}  ttl={ttl}"
                    proto_name = "HTTP" if dport in (80,8080) or sport in (80,8080) else "TCP"
                    payload = data[ihl+off:]
            elif proto_num == 17:
                r2 = parse_udp_header(data[ihl:])
                if r2:
                    sport, dport, ulen = r2
                    extra = f"len={ulen}  ttl={ttl}"
                    proto_name = "DNS" if dport == 53 or sport == 53 else "UDP"
                    payload = data[ihl+8:]
            elif proto_num == 1 and len(data) > ihl:
                t = data[ihl]
                icmp_types = {0:"Echo-Reply", 8:"Echo-Request",
                              3:"Dest-Unreachable", 11:"Time-Exceeded"}
                extra = f"{icmp_types.get(t, f'type={t}')}  ttl={ttl}"

            pkt = Pkt(proto_name, src, dst, size, sport=sport, dport=dport,
                      flags=flags, extra=extra, payload=payload)
            print(pkt.render(stats, verbose))
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if sys.platform == "win32":
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except Exception:
            pass


def scapy_live_capture(iface, count, bpf_filter, verbose, save_file, stats):
    def handle(pkt):
        src = dst = "?"
        proto_name = "OTHER"
        sport = dport = None
        flags = extra = ""
        payload = b""
        size = len(pkt)

        if ARP in pkt:
            arp = pkt[ARP]
            proto_name = "ARP"
            src, dst   = arp.psrc, arp.pdst
            op  = "REQUEST" if arp.op == 1 else "REPLY"
            extra = f"{op}  {arp.hwsrc} → {arp.hwdst}"
        elif IP in pkt:
            ip  = pkt[IP]
            src, dst = ip.src, ip.dst
            if TCP in pkt:
                tcp = pkt[TCP]
                sport, dport = tcp.sport, tcp.dport
                fm = {"S":"SYN","A":"ACK","F":"FIN","R":"RST","P":"PSH"}
                flags = "+".join(v for k,v in fm.items() if k in str(tcp.flags))
                extra = f"seq={tcp.seq}  ack={tcp.ack}  win={tcp.window}  ttl={ip.ttl}"
                proto_name = ("HTTP" if dport in (80,8080) or sport in (80,8080)
                              else "TCP")
                if Raw in pkt:
                    payload = bytes(pkt[Raw])
            elif UDP in pkt:
                udp = pkt[UDP]
                sport, dport = udp.sport, udp.dport
                proto_name = "UDP"
                if DNS and DNS in pkt:
                    d = pkt[DNS]
                    kind  = "QUERY" if d.qr == 0 else "RESPONSE"
                    qname = ""
                    if d.qd:
                        try: qname = d.qd.qname.decode()
                        except: pass
                    extra = (f"{kind}  name={col(qname, C.DNS)}"
                             f"  answers={getattr(d,'ancount',0)}")
                    proto_name = "DNS"
                else:
                    extra = f"len={udp.len}  ttl={ip.ttl}"
                if Raw in pkt:
                    payload = bytes(pkt[Raw])
            elif ICMP in pkt:
                icmp = pkt[ICMP]
                proto_name = "ICMP"
                it = {0:"Echo-Reply", 3:"Dest-Unreachable",
                      8:"Echo-Request", 11:"Time-Exceeded"}
                extra = (f"{it.get(icmp.type, f'type={icmp.type}')}"
                         f"  code={icmp.code}  ttl={ip.ttl}")
            else:
                proto_name = IP_PROTO_NAMES.get(ip.proto, f"IP/{ip.proto}")

        p = Pkt(proto_name, src, dst, size, sport=sport, dport=dport,
                flags=flags, extra=extra, payload=payload)
        print(p.render(stats, verbose))

    captured = sniff(iface=iface, count=count or 0,
                     filter=bpf_filter or "", prn=handle,
                     store=bool(save_file))
    if save_file and captured:
        wrpcap(save_file, captured)
        print(col(f"\n  Saved {len(captured)} packets → {save_file}", C.GOOD))


def live_capture(iface, count, bpf_filter, verbose, save_file):
    stats = Stats()
    print(col(f"\n  Listening on {bold(iface or 'default')}  "
              f"bpf={bold(bpf_filter or 'none')}  "
              f"count={bold(str(count) if count else '∞')}\n", C.INFO))
    print(col("  Press Ctrl+C to stop.\n", C.DIM))
    try:
        if SCAPY_AVAILABLE:
            scapy_live_capture(iface, count, bpf_filter, verbose, save_file, stats)
        else:
            raw_socket_capture(count or 0, verbose, stats)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(col("\n  ✗ Permission denied — run as root / Administrator.", C.WARN))
        sys.exit(1)
    print(stats.summary())


# ─────────────────────────────────────────────────────────────────────────────
#  PROTOCOL EXPLAINERS
# ─────────────────────────────────────────────────────────────────────────────
PROTOCOL_EDUCATION = {
    "TCP": """
  TCP — Transmission Control Protocol  (RFC 793)
  ───────────────────────────────────────────────
  Layer  : Transport (Layer 4)
  Purpose: Reliable, ordered, error-checked delivery of byte streams.

  Header Fields:
    • Source / Dest Port (16-bit) — identifies the application endpoint
    • Sequence Number            — byte-position in the data stream
    • Acknowledgment Number      — next expected byte from the peer
    • Flags: SYN / ACK / FIN / RST / PSH / URG
    • Window Size                — flow control (bytes peer may send)
    • Checksum                   — data integrity

  3-Way Handshake (connection setup):
    Client  ──SYN──────►  Server
    Client  ◄──SYN+ACK──  Server
    Client  ──ACK──────►  Server    (ESTABLISHED)

  4-Step Teardown:
    Client  ──FIN──────►  Server
    Client  ◄──ACK──────  Server
    Client  ◄──FIN──────  Server
    Client  ──ACK──────►  Server    (CLOSED)

  Common Ports: 80 (HTTP), 443 (HTTPS), 22 (SSH), 25 (SMTP), 3306 (MySQL)
""",
    "UDP": """
  UDP — User Datagram Protocol  (RFC 768)
  ───────────────────────────────────────
  Layer  : Transport (Layer 4)
  Purpose: Fast, connectionless delivery — no handshake, no retransmit.

  Header (only 8 bytes):
    Source Port | Dest Port | Length | Checksum

  Use Cases: DNS, video/audio streaming, VoIP, online gaming, NTP
  Trade-off: Speed over reliability — the application handles errors.
""",
    "ICMP": """
  ICMP — Internet Control Message Protocol  (RFC 792)
  ─────────────────────────────────────────────────────
  Layer  : Network (Layer 3) — carried inside IP packets
  Purpose: Diagnostic and error reporting between network devices.

  Key Message Types:
    0  — Echo Reply         (ping response)
    3  — Destination Unreachable
    5  — Redirect
    8  — Echo Request       (ping)
    11 — Time Exceeded      (TTL expired → how traceroute works)

  Tools that use ICMP: ping, traceroute / tracert
""",
    "DNS": """
  DNS — Domain Name System  (RFC 1035)
  ─────────────────────────────────────
  Layer  : Application (Layer 7) over UDP port 53
  Purpose: Translates human-readable domain names into IP addresses.

  Record Types:
    A     — IPv4 address        AAAA  — IPv6 address
    MX    — Mail exchange       CNAME — Alias
    NS    — Name server         TXT   — Arbitrary text / SPF records

  Resolution Flow:
    App ──► Resolver ──► Root NS ──► TLD NS ──► Authoritative NS ──► IP

  Security:
    DNS is plaintext by default!
    DNSSEC adds signatures; DNS-over-TLS (853) and DNS-over-HTTPS (443)
    encrypt the queries.
""",
    "ARP": """
  ARP — Address Resolution Protocol  (RFC 826)
  ─────────────────────────────────────────────
  Layer  : Data-Link (Layer 2 / 2.5)
  Purpose: Maps IP addresses → MAC addresses within a local network.

  Flow (who has 192.168.1.1?):
    Host A broadcasts: "Who has 192.168.1.1?  Tell 192.168.1.10"
    Host B replies  : "192.168.1.1 is at aa:bb:cc:dd:ee:ff"
    Host A caches the result in its ARP table.

  Security Risk:
    ARP is stateless and unauthenticated — ARP Spoofing lets an attacker
    inject fake MAC entries, enabling Man-in-the-Middle (MITM) attacks.
    Mitigations: Dynamic ARP Inspection (DAI), static entries, port security.
""",
    "HTTP": """
  HTTP — HyperText Transfer Protocol  (RFC 7230)
  ───────────────────────────────────────────────
  Layer  : Application (Layer 7) over TCP port 80
  Purpose: Transfer of hypertext / web data between client and server.

  Request Format:
    METHOD  /path  HTTP/1.1
    Header: value
    <blank line>
    [body]

  Common Methods: GET  POST  PUT  DELETE  PATCH  HEAD  OPTIONS

  Status Codes:
    2xx — Success      (200 OK, 201 Created)
    3xx — Redirect     (301 Moved, 302 Found)
    4xx — Client Error (400 Bad Request, 401 Unauth, 403 Forbidden, 404)
    5xx — Server Error (500 Internal Error, 503 Unavailable)

  Security: HTTP is plaintext — use HTTPS (TLS) on port 443 for everything.
""",
}

BANNER = f"""
{col("╔════════════════════════════════════════════════════╗", C.ACCENT)}
{col("║", C.ACCENT)}  {bold(col("NetScope", C.HEADER))} — Network Packet Analyzer & Educator    {col("║", C.ACCENT)}
{col("╚════════════════════════════════════════════════════╝", C.ACCENT)}
  Protocols:  {col("TCP",C.TCP)}  {col("UDP",C.UDP)}  {col("ICMP",C.ICMP)}  {col("DNS",C.DNS)}  {col("ARP",C.ARP)}  {col("HTTP",C.HTTP)}
  Engine:     {"scapy" if SCAPY_AVAILABLE else "raw socket / struct (scapy not detected)"}
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope — Network Packet Analyzer & Educator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
Examples:
  python packet_analyzer.py --demo
  python packet_analyzer.py --demo -v
  python packet_analyzer.py --live -c 50 -v
  python packet_analyzer.py --live -i eth0 --bpf "tcp port 80" --save out.pcap
  python packet_analyzer.py --explain TCP
  python packet_analyzer.py --explain DNS
  python packet_analyzer.py --explain ARP
        """),
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo",    action="store_true",
                      help="Offline demo with synthetic packets (no root required)")
    mode.add_argument("--live",    action="store_true",
                      help="Live capture from a network interface (requires root/admin)")
    mode.add_argument("--explain", metavar="PROTO",
                      help="Protocol deep-dive: TCP UDP ICMP DNS ARP HTTP")

    p.add_argument("-i","--iface",  default=None,
                   help="Network interface, e.g. eth0 / wlan0 / en0")
    p.add_argument("-c","--count",  type=int, default=0,
                   help="Number of packets to capture then stop (0 = unlimited)")
    p.add_argument("--bpf",         default=None,
                   help="BPF filter string, e.g. 'tcp port 443'")
    p.add_argument("-v","--verbose",action="store_true",
                   help="Show payload bytes and additional layer headers")
    p.add_argument("--save",        default=None,
                   help="Save captured packets to a .pcap file (scapy required)")
    return p


def main():
    print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()

    if args.explain:
        key  = args.explain.upper()
        info = PROTOCOL_EDUCATION.get(key)
        if info:
            print(col(info, C.PAYLOAD))
        else:
            avail = ", ".join(PROTOCOL_EDUCATION)
            print(col(f"  No explainer for '{key}'. Available: {avail}", C.WARN))
        return

    if args.demo:
        demo_mode(args.verbose)
        return

    if args.live:
        live_capture(args.iface, args.count, args.bpf, args.verbose, args.save)


if __name__ == "__main__":
    main()
