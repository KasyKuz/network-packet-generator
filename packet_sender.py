import socket
import struct
import time
from collections import deque
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import Ether
import ipaddress
import subprocess
import platform
import re
import netifaces

class NetworkUtils:
    """Network utility functions for smart MAC detection"""
    
    @staticmethod
    def get_network_interfaces():
        """Get list of network interfaces using multiple methods"""
        interfaces = []
        try:
            # Method 1: Using netifaces (most reliable)
            interfaces = netifaces.interfaces()
            # Filter out loopback and virtual interfaces
            interfaces = [iface for iface in interfaces if iface != 'lo' and not iface.startswith('virbr')]
        except:
            try:
                # Method 2: Using scapy
                interfaces = [iface for iface in get_if_list() if iface != 'lo']
            except:
                try:
                    # Method 3: Using system commands
                    if platform.system().lower() == "windows":
                        result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                              capture_output=True, text=True)
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if 'Connected' in line:
                                parts = line.split()
                                if len(parts) > 3:
                                    interfaces.append(parts[-1])
                    else:
                        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if ': ' in line and 'LOOPBACK' not in line:
                                parts = line.split(': ')
                                if len(parts) > 1 and not parts[1].startswith('lo'):
                                    interfaces.append(parts[1].strip())
                except:
                    # Final fallback
                    interfaces = ["eth0", "wlan0", "ens33", "enp0s3"]
        
        return interfaces
    
    @staticmethod
    def get_interface_info(interface):
        """Get IP and netmask for selected interface using multiple methods"""
        try:
            # Method 1: Using netifaces
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                ip = ip_info['addr']
                netmask = ip_info['netmask']
                return ip, netmask
        except:
            try:
                # Method 2: Using system commands
                if platform.system().lower() == "windows":
                    result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                    # Parse output for the specific interface
                    lines = result.stdout.split('\n')
                    found_interface = False
                    for line in lines:
                        if interface in line:
                            found_interface = True
                        if found_interface and 'IPv4 Address' in line:
                            ip = line.split(':')[1].strip()
                        if found_interface and 'Subnet Mask' in line:
                            netmask = line.split(':')[1].strip()
                            return ip, netmask
                else:
                    result = subprocess.run(['ip', 'addr', 'show', interface], 
                                          capture_output=True, text=True)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'inet ' in line:
                            parts = line.strip().split()
                            ip_with_mask = parts[1]
                            ip = ip_with_mask.split('/')[0]
                            prefix = ip_with_mask.split('/')[1]
                            netmask = NetworkUtils.prefix_to_netmask(prefix)
                            return ip, netmask
            except Exception as e:
                print(f"Error getting interface info: {e}")
        
        return None, None
    
    @staticmethod
    def get_gateway_info(interface=None):
        """Get gateway IP using multiple methods"""
        try:
            # Method 1: Using netifaces
            gateways = netifaces.gateways()
            default_gateway = gateways['default']
            if netifaces.AF_INET in default_gateway:
                gateway_ip = default_gateway[netifaces.AF_INET][0]
                return gateway_ip
        except:
            try:
                # Method 2: Using system commands
                if platform.system().lower() == "windows":
                    result = subprocess.run(['route', 'print', '0.0.0.0'], 
                                          capture_output=True, text=True)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '0.0.0.0' in line and 'On-link' not in line:
                            parts = line.split()
                            if len(parts) > 2:
                                return parts[2]
                else:
                    result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                          capture_output=True, text=True)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'default via' in line:
                            parts = line.split()
                            return parts[2]
            except Exception as e:
                print(f"Error getting gateway info: {e}")
        
        return None

    @staticmethod
    def get_arp_table():
        """Get system ARP table using multiple methods"""
        arp_table = {}
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, encoding='utf-8', errors='ignore')
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'dynamic' in line.lower() or 'static' in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1].replace('-', ':')
                            if NetworkUtils.validate_mac(mac):
                                arp_table[ip] = mac
            else:
                # Linux/Mac - try multiple methods
                try:
                    # Method 1: arp -a
                    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[1].strip('()')
                            mac = parts[3]
                            if NetworkUtils.validate_mac(mac):
                                arp_table[ip] = mac
                except:
                    # Method 2: ip neighbor
                    result = subprocess.run(['ip', 'neighbor', 'show'], capture_output=True, text=True)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 5 and parts[3] == 'REACHABLE':
                            ip = parts[0]
                            mac = parts[4]
                            if NetworkUtils.validate_mac(mac):
                                arp_table[ip] = mac
        except Exception as e:
            print(f"Error reading ARP table: {e}")
        return arp_table
    
    @staticmethod
    def is_in_same_subnet(ip1, ip2, netmask):
        """Check if two IPs are in the same subnet"""
        try:
            network1 = ipaddress.IPv4Network(f"{ip1}/{netmask}", strict=False)
            network2 = ipaddress.IPv4Network(f"{ip2}/{netmask}", strict=False)
            return network1.network_address == network2.network_address
        except Exception as e:
            print(f"Error checking subnet: {e}")
            return False
    
    @staticmethod
    def validate_mac(mac):
        """Validate MAC address format"""
        if not mac or mac == "FF:FF:FF:FF:FF:FF":
            return True
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return re.match(mac_pattern, mac) is not None
    
    @staticmethod
    def calculate_optimal_mac(target_ip, interface_ip, netmask, gateway_ip, arp_table):
        """Calculate optimal MAC address based on network conditions"""
        
        if not target_ip or not interface_ip:
            return "FF:FF:FF:FF:FF:FF", "Не указан IP адрес назначения или источника"
        
        # 1. Check if target IP is in our subnet
        same_subnet = NetworkUtils.is_in_same_subnet(target_ip, interface_ip, netmask)
        
        if same_subnet:
            # 2. If in our subnet - check ARP table
            if target_ip in arp_table:
                return arp_table[target_ip], None  # Use target host MAC
            else:
                return "FF:FF:FF:FF:FF:FF", None  # Broadcast for ARP request
        else:
            # 3. If not in our subnet - use gateway MAC
            if gateway_ip and gateway_ip in arp_table:
                return arp_table[gateway_ip], None  # Use gateway MAC
            elif gateway_ip:
                return "FF:FF:FF:FF:FF:FF", None  # Broadcast for gateway ARP request
            else:
                # If gateway not specified but address in different network
                warning_msg = "Для межсетевой связи укажите шлюз по умолчанию"
                return "FF:FF:FF:FF:FF:FF", warning_msg
    
    @staticmethod
    def prefix_to_netmask(prefix):
        """Convert prefix length to netmask"""
        try:
            prefix = int(prefix)
            mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
            return '.'.join([str(mask >> (i << 3) & 0xff) for i in range(3, -1, -1)])
        except:
            return "255.255.255.0"

    @staticmethod
    def refresh_arp_table(target_ip):
        """Refresh ARP table (send ARP request)"""
        try:
            if target_ip:
                # Send ARP request to refresh table
                if platform.system().lower() == "windows":
                    subprocess.run(['arp', '-d', target_ip], capture_output=True)
                else:
                    subprocess.run(['arp', '-d', target_ip], capture_output=True)
                
                # Send ping to initiate ARP
                subprocess.run(['ping', '-n', '1', '-w', '1000', target_ip], 
                             capture_output=True)
                
                return True, "ARP-таблица обновлена"
        except Exception as e:
            return False, f"Error refreshing ARP: {e}"


class PacketSender:
    """Handles packet creation and sending logic"""
    
    def __init__(self):
        self.packet_queue = deque()
        self.is_sending_queue = False
    
    def get_default_gateway(self):
        """Automatically detect default gateway IP"""
        return NetworkUtils.get_gateway_info()

    def create_packet(self, ui_elements, current_transport_layer, interface):
        """Create packet from UI settings without sending it"""
        # Get Ethernet arguments if MAC addresses are specified
        ethernet_args = self.get_ethernet_args(ui_elements, interface)
        
        ip_args = self.get_ip_args(ui_elements)
        
        # Set protocol for IP header and get transport layer
        if current_transport_layer == "ICMP":
            ip_args["proto"] = 1
            args = self.get_icmp_args(ui_elements)
            next_layer = ICMP(**args)
            if hasattr(ui_elements, 'ICMPPayload') and ui_elements.ICMPPayload.text().strip():
                next_layer = next_layer / self.hex_string_to_bytes(ui_elements.ICMPPayload.text())
        elif current_transport_layer == "UDP":
            ip_args["proto"] = 17
            args = self.get_udp_args(ui_elements)
            next_layer = UDP(**args)
            if hasattr(ui_elements, 'UDPPayload') and ui_elements.UDPPayload.text().strip():
                next_layer = next_layer / self.hex_string_to_bytes(ui_elements.UDPPayload.text())
        elif current_transport_layer == "TCP":
            ip_args["proto"] = 6
            args = self.get_tcp_args(ui_elements)
            next_layer = TCP(**args)
            if hasattr(ui_elements, 'TCPPayload') and ui_elements.TCPPayload.text().strip():
                next_layer = next_layer / self.hex_string_to_bytes(ui_elements.TCPPayload.text())

        # Build packet with or without Ethernet layer
        if ethernet_args:
            ether_layer = Ether(**ethernet_args)
            ip_layer = IP(**ip_args)
            packet = ether_layer / ip_layer / next_layer
        else:
            ip_layer = IP(**ip_args)
            packet = ip_layer / next_layer
        
        packet_info = {
            'packet': packet,
            'type': current_transport_layer,
            'src': ip_args.get('src', 'auto'),
            'dst': ip_args.get('dst', 'auto'),
            'interface': interface
        }
        
        return packet_info

    def hex_string_to_bytes(self, hex_string):
        """Convert hex string to bytes, handling spaces and different formats"""
        try:
            # Remove spaces and convert to bytes
            hex_string = hex_string.replace(' ', '').replace(':', '')
            return bytes.fromhex(hex_string)
        except ValueError as e:
            return b''

    def send_single_packet(self, packet_info):
        """Send a single packet"""
        print("Sending single packet...")
        
        packet = packet_info['packet']
        interface = packet_info['interface']
        
        # Безопасное извлечение src и dst
        src = packet_info.get('src', 'unknown')
        dst = packet_info.get('dst', 'unknown')
        
        print(f"Sending packet via interface: {interface}")
        print(f"Source: {src}, Destination: {dst}")
        
        try:
            # Use sendp for Ethernet packets, send for IP packets
            if packet.haslayer(Ether):
                sendp(packet, iface=interface, verbose=0)
            else:
                send(packet, iface=interface, verbose=0)
            return True, "Packet sent successfully!"
        except Exception as e:
            error_msg = f"Error sending packet: {str(e)}"
            print(f"Error: {error_msg}")
            return False, error_msg
    def get_ethernet_args(self, ui_elements, interface):
        """Get Ethernet layer arguments with smart MAC detection"""
        ethernet_args = {}
        
        # Source MAC
        if hasattr(ui_elements, 'SourceMAC') and ui_elements.SourceMAC.text().strip():
            ethernet_args["src"] = ui_elements.SourceMAC.text().strip()
        else:
            # Auto-detect source MAC if not specified
            try:
                src_mac = get_if_hwaddr(interface)
                ethernet_args["src"] = src_mac
            except:
                pass
        
        # Smart destination MAC detection
        if hasattr(ui_elements, 'DestinationMAC') and ui_elements.DestinationMAC.text().strip():
            ethernet_args["dst"] = ui_elements.DestinationMAC.text().strip()
        else:
            # Use smart algorithm to determine destination MAC
            target_ip = ui_elements.DestinationIP.text().strip() if hasattr(ui_elements, 'DestinationIP') else ""
            interface_ip = ui_elements.SourceIP.text().strip() if hasattr(ui_elements, 'SourceIP') else ""
            
            if target_ip and interface_ip:
                # Get network settings from UI or auto-detect
                netmask = getattr(ui_elements, 'Netmask', None)
                gateway = getattr(ui_elements, 'Gateway', None)
                
                netmask_text = netmask.text().strip() if netmask and hasattr(netmask, 'text') and netmask.text().strip() else "255.255.255.0"
                gateway_text = gateway.text().strip() if gateway and hasattr(gateway, 'text') and gateway.text().strip() else self.get_default_gateway()
                
                # Get ARP table and calculate optimal MAC
                arp_table = NetworkUtils.get_arp_table()
                optimal_mac, warning = NetworkUtils.calculate_optimal_mac(
                    target_ip, interface_ip, netmask_text, gateway_text, arp_table
                )
                
                ethernet_args["dst"] = optimal_mac
                if warning:
                    print(f"Warning: {warning}")
            else:
                ethernet_args["dst"] = 'ff:ff:ff:ff:ff:ff'
        
        return ethernet_args

    def get_ip_args(self, ui_elements):
        """Get IP layer arguments"""
        ip_args = {}
        
        # Source IP
        if hasattr(ui_elements, 'SourceIP') and ui_elements.SourceIP.text().strip():
            ip_args["src"] = ui_elements.SourceIP.text().strip()
        else:
            # Automatic host IP detection
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip_args["src"] = s.getsockname()[0]
                s.close()
            except:
                ip_args["src"] = "127.0.0.1"
        
        # Destination IP
        if hasattr(ui_elements, 'DestinationIP') and ui_elements.DestinationIP.text().strip():
            ip_args["dst"] = ui_elements.DestinationIP.text().strip()
        else:
            ip_args["dst"] = "127.0.0.1"
        
        # Other optional fields
        optional_fields = {
            'ID': 'id', 'TTL': 'ttl', 'HeaderLen': 'ihl', 
            'PacketLen': 'len', 'FragmentationOffset': 'frag'
        }
        
        for ui_field, ip_field in optional_fields.items():
            if hasattr(ui_elements, ui_field) and ui_elements.__getattribute__(ui_field).text().strip():
                try:
                    ip_args[ip_field] = int(ui_elements.__getattribute__(ui_field).text())
                except ValueError:
                    pass
        
        # Header checksum (hex)
        if hasattr(ui_elements, 'HeaderChecksum') and ui_elements.HeaderChecksum.text().strip():
            try:
                ip_args["chksum"] = int(ui_elements.HeaderChecksum.text(), 16)
            except ValueError:
                pass
        
        return ip_args

    def get_icmp_args(self, ui_elements):
        """Get ICMP layer arguments"""
        icmp_args = {}

        # ICMP type
        if hasattr(ui_elements, 'ICMPTypes'):
            icmp_type = ui_elements.ICMPTypes.currentText()
            if icmp_type == "Echo Request":
                icmp_args['type'] = 8
            elif icmp_type == "Echo Reply":
                icmp_args['type'] = 0

        # Other optional fields
        optional_fields = {
            'ICMPCode': 'code', 'ICMPId': 'id', 'ICMPSeqNum': 'seq'
        }
        
        for ui_field, icmp_field in optional_fields.items():
            if hasattr(ui_elements, ui_field) and ui_elements.__getattribute__(ui_field).text().strip():
                try:
                    icmp_args[icmp_field] = int(ui_elements.__getattribute__(ui_field).text())
                except ValueError:
                    pass
        
        # ICMP checksum (hex)
        if hasattr(ui_elements, 'ICMPChecksum') and ui_elements.ICMPChecksum.text().strip():
            try:
                icmp_args["chksum"] = int(ui_elements.ICMPChecksum.text(), 16)
            except ValueError:
                pass

        return icmp_args

    def get_udp_args(self, ui_elements):
        """Get UDP layer arguments"""
        udp_args = {}

        # Optional fields
        optional_fields = {
            'UDPSrcPort': 'sport', 'UDPDstPort': 'dport', 'UDPLen': 'len'
        }
        
        for ui_field, udp_field in optional_fields.items():
            if hasattr(ui_elements, ui_field) and ui_elements.__getattribute__(ui_field).text().strip():
                try:
                    udp_args[udp_field] = int(ui_elements.__getattribute__(ui_field).text())
                except ValueError:
                    pass
        
        # UDP checksum (hex)
        if hasattr(ui_elements, 'UDPChecksum') and ui_elements.UDPChecksum.text().strip():
            try:
                udp_args["chksum"] = int(ui_elements.UDPChecksum.text(), 16)
            except ValueError:
                pass

        return udp_args

    def get_tcp_args(self, ui_elements):
        """Get TCP layer arguments"""
        tcp_args = {}

        # Optional fields
        optional_fields = {
            'TCPSrcPort': 'sport', 'TCPDstPort': 'dport', 'TCPSeqNum': 'seq',
            'TCPAckNum': 'ack', 'TCPDataOffset': 'dataofs', 'TCPWindowSize': 'window',
            'TCPUrgPtr': 'urgptr'
        }
        
        for ui_field, tcp_field in optional_fields.items():
            if hasattr(ui_elements, ui_field) and ui_elements.__getattribute__(ui_field).text().strip():
                try:
                    tcp_args[tcp_field] = int(ui_elements.__getattribute__(ui_field).text())
                except ValueError:
                    pass
        
        # TCP checksum (hex)
        if hasattr(ui_elements, 'TCPChecksum') and ui_elements.TCPChecksum.text().strip():
            try:
                tcp_args["chksum"] = int(ui_elements.TCPChecksum.text(), 16)
            except ValueError:
                pass

        # TCP flags
        flags = ""
        flag_checkboxes = {
            'TCPSYN': 'S', 'TCPFIN': 'F', 'TCPRST': 'R', 'TCPPUSH': 'P',
            'TCPACK': 'A', 'TCPURG': 'U', 'TCPECNEcho': 'E', 'TCPCWR': 'C'
        }
        
        for checkbox, flag in flag_checkboxes.items():
            if hasattr(ui_elements, checkbox) and ui_elements.__getattribute__(checkbox).isChecked():
                flags += flag
        
        tcp_args["flags"] = flags

        return tcp_args


# Simple test function to verify the module works
def main():
    """Test function for packet_sender module"""
    print("Testing NetworkUtils...")
    
    # Test getting network interfaces
    interfaces = NetworkUtils.get_network_interfaces()
    print(f"Available interfaces: {interfaces}")
    
    # Test getting ARP table
    arp_table = NetworkUtils.get_arp_table()
    print(f"ARP table entries: {len(arp_table)}")
    
    # Test subnet calculation
    result = NetworkUtils.is_in_same_subnet("192.168.1.10", "192.168.1.20", "255.255.255.0")
    print(f"Same subnet test: {result}")
    
    print("Packet sender module test completed successfully!")


if __name__ == "__main__":
    main()