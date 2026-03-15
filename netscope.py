import socket
import struct
from typing import Tuple, Optional, List

class NetworkPacketAnalyzer:
    """
    A class to analyze network packets.
    """

    def __init__(self, interface: str) -> None:
        """
        Initializes the packet analyzer with the specified interface.

        :param interface: The network interface to capture packets from.
        """
        self.interface = interface

    def capture_packets(self, num_packets: int) -> List[bytes]:
        """
        Captures packets from the specified network interface.

        :param num_packets: The number of packets to capture.
        :return: A list of captured packets in bytes.
        """
        packets = []
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) as s:
            s.bind((self.interface, 0))
            for _ in range(num_packets):
                packet = s.recv(65536)
                packets.append(packet)
        return packets

    def parse_packet(self, packet: bytes) -> Tuple[Optional[str], Optional[str]]:
        """
        Parses a single network packet and extracts the source and destination IP addresses.

        :param packet: The packet in bytes.
        :return: A tuple of source and destination IP addresses, or (None, None) if parsing fails.
        """
        try:
            eth_length = 14
            ip_header = packet[eth_length:eth_length + 20]
            ip_fields = struct.unpack('!BBHHHBBH4s4s', ip_header)
            src_ip = socket.inet_ntoa(ip_fields[8])
            dest_ip = socket.inet_ntoa(ip_fields[9])
            return src_ip, dest_ip
        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None, None

    def analyze_packets(self, packets: List[bytes]) -> None:
        """
        Analyzes a list of packets and prints their source and destination IP addresses.

        :param packets: The list of captured packets.
        """
        for packet in packets:
            src_ip, dest_ip = self.parse_packet(packet)
            if src_ip and dest_ip:
                print(f"Source IP: {src_ip}, Destination IP: {dest_ip}")
            else:
                print("Packet could not be parsed.")

if __name__ == '__main__':
    analyzer = NetworkPacketAnalyzer(interface='eth0')
    packets = analyzer.capture_packets(num_packets=10)
    analyzer.analyze_packets(packets)