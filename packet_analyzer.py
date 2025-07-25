#!/usr/bin/env python3
import os
import sys
import logging
import argparse
from datetime import datetime
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.inet6 import IPv6

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('packet_analyzer.log')
    ]
)
logger = logging.getLogger("PacketAnalyzer")

# Silence Scapy completely
conf.verb = 0
conf.warning_threshold = 0
conf.logLevel = logging.ERROR

class PacketAnalyzer:
    def __init__(self, interface, filter_exp=None, log_file=None):
        self.interface = interface
        self.filter_exp = filter_exp
        self.log_file = log_file
        self.packet_count = 0
        self.running = False
        self.socket = None
        
    def start_capture(self, packet_count=0):
        """Start continuous packet capture session"""
        logger.info(f"Starting continuous packet capture on {self.interface}...")
        if self.filter_exp:
            logger.info(f"Applying filter: '{self.filter_exp}'")
            
        self.running = True
        self.packet_count = packet_count
        
        try:
            # Create raw socket
            self.socket = conf.L2socket(iface=self.interface)
            
            # Continuous capture with no timeout
            sniff(
                opened_socket=self.socket,
                filter=self.filter_exp,
                prn=self.process_packet,
                store=False,
                count=packet_count if packet_count > 0 else 0,
                promisc=False,
                quiet=True
            )
        except PermissionError:
            logger.error("Permission denied. Try running with sudo.")
            sys.exit(1)
        except KeyboardInterrupt:
            logger.info("\nCapture stopped by user")
        except Exception as e:
            logger.error(f"Capture error: {str(e)}")
        finally:
            if self.socket:
                self.socket.close()
            self.running = False
            logger.info("Capture session ended")
            
    def process_packet(self, packet):
        """Process each captured packet"""
        try:
            if packet is None:
                return
                
            if IP in packet or IPv6 in packet:
                self.analyze_ip_packet(packet)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            
    def analyze_ip_packet(self, packet):
        """Analyze IP layer and its protocols"""
        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto
            elif IPv6 in packet:
                ip_src = packet[IPv6].src
                ip_dst = packet[IPv6].dst
                protocol = packet[IPv6].nh
            
            timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
            base_info = f"[{timestamp}] {ip_src} -> {ip_dst} | Proto: {protocol}"

            if TCP in packet:
                self.analyze_tcp(packet, base_info)
            elif UDP in packet:
                self.analyze_udp(packet, base_info)
            elif ICMP in packet:
                logger.info(f"{base_info} | ICMP Packet")
            elif protocol == 2:  # IGMP
                logger.info(f"{base_info} | IGMP Packet")
            else:
                logger.info(f"{base_info} | Unknown Protocol")
                
            if self.log_file:
                self.log_packet(packet)
        except Exception as e:
            logger.error(f"Error analyzing IP packet: {e}")

    def analyze_tcp(self, packet, base_info):
        """Enhanced TCP analysis with sequence numbers"""
        try:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            seq = packet[TCP].seq
            ack = packet[TCP].ack
            tcp_info = f"{base_info} | TCP {sport}->{dport} | Seq:{seq} Ack:{ack} Flags:{flags}"

            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                http_info = self.analyze_http(packet)
                logger.info(f"{tcp_info} | {http_info}")
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                logger.info(f"{tcp_info} | HTTPS Traffic")
            else:
                logger.info(tcp_info)
        except Exception as e:
            logger.error(f"Error analyzing TCP packet: {e}")
            
    def analyze_udp(self, packet, base_info):
        """Analyze UDP packets"""
        try:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            udp_info = f"{base_info} | UDP {sport} -> {dport}"

            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                if DNS in packet:
                    dns_info = self.analyze_dns(packet)
                    logger.info(f"{udp_info} | DNS: {dns_info}")
                else:
                    logger.info(f"{udp_info} | DNS Traffic")
            elif packet[UDP].dport == 1900:  # SSDP
                logger.info(f"{udp_info} | SSDP Traffic")
            else:
                logger.info(udp_info)
        except Exception as e:
            logger.error(f"Error analyzing UDP packet: {e}")
            
    def analyze_http(self, packet):
        """Enhanced HTTP analysis to show full requests"""
        try:
            if packet.haslayer(HTTPRequest):
                http = packet[HTTPRequest]
                method = http.Method.decode(errors='ignore')
                host = http.Host.decode(errors='ignore') if http.Host else "N/A"
                path = http.Path.decode(errors='ignore') if http.Path else "N/A"
                return f"HTTP Request: {method} {host}{path}"
            elif packet.haslayer(HTTPResponse):
                return f"HTTP Response: {packet[HTTPResponse].Status_Code.decode(errors='ignore')}"
            else:
                return "HTTP Data"
        except Exception as e:
            logger.error(f"Error analyzing HTTP: {e}")
            return "HTTP Analysis Failed"
        
    def analyze_dns(self, packet):
        """Extract DNS query information"""
        try:
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:  # DNS query
                query = dns_layer.qd.qname.decode(errors='ignore') if dns_layer.qd else "N/A"
                return f"Query: {query}"
            else:  # DNS response
                answers = [rr.rdata for rr in dns_layer.an if dns_layer.an]
                return f"Response: {', '.join(str(a) for a in answers)}" if answers else "Empty Response"
        except Exception as e:
            logger.error(f"Error analyzing DNS: {e}")
            return "DNS Analysis Failed"
            
    def log_packet(self, packet):
        """Log packet to file"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(f"{packet.summary()}\n")
        except Exception as e:
            logger.error(f"Error logging packet: {e}")

def main():
    # Redirect stderr to suppress any remaining warnings
    sys.stderr = open(os.devnull, 'w')
    
    parser = argparse.ArgumentParser(
        description="Enhanced Python Network Packet Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-i', '--interface',
        required=True,
        help="Network interface to capture on (use 'ip a' to check)"
    )
    parser.add_argument(
        '-f', '--filter',
        default=None,
        help="BPF filter expression (e.g., 'tcp port 80')"
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        help="Number of packets to capture (0 for unlimited)"
    )
    parser.add_argument(
        '-l', '--log',
        default=None,
        help="File to log packets to"
    )
    
    args = parser.parse_args()
    
    analyzer = PacketAnalyzer(
        interface=args.interface,
        filter_exp=args.filter,
        log_file=args.log
    )
    
    try:
        analyzer.start_capture(packet_count=args.count)
    except KeyboardInterrupt:
        logger.info("\nCapture stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
