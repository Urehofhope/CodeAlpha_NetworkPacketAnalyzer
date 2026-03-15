# Configuration constants for Network Packet Analyzer

# Well-known ports
WELL_KNOWN_PORTS = {
    'HTTP': 80,
    'HTTPS': 443,
    'FTP': 21,
    'SSH': 22,
    'TELNET': 23,
    'SMTP': 25,
    'DNS': 53,
    'DHCP': 67,
    'SNMP': 161,
    'HTTPS': 443,
}

# Protocol colors in HEX
PROTOCOL_COLORS = {
    'TCP': '#FF0000',   # Red
    'UDP': '#00FF00',   # Green
    'ICMP': '#0000FF',  # Blue
    'ARP': '#FFFF00',   # Yellow
    'IP': '#FF00FF',    # Magenta
}

# Protocol names
PROTOCOL_NAMES = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    2048: 'GRE',
    51: 'ESP',
    50: 'AH',
    132: 'SCTP',
}