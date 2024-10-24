from scapy.all import sniff, IP, TCP, UDP, Ether

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"IP Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}")

        # Check for TCP packets
        if TCP in packet:
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            print(f"TCP Packet: {tcp_src_port} -> {tcp_dst_port}")

        # Check for UDP packets
        elif UDP in packet:
            udp_src_port = packet[UDP].sport
            udp_dst_port = packet[UDP].dport
            print(f"UDP Packet: {udp_src_port} -> {udp_dst_port}")

def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # You can specify the interface you want to sniff on (e.g., 'eth0', 'wlan0')
    start_sniffing(interface=None)  # Use None for the default interface



