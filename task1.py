from scapy.all import sniff, IP, TCP #Scapy library for network packet manipulation to create, send, receive, and analyze network packets

def packet_callback(packet): # Called for each packet captured by sniffer
    if packet.haslayer(IP): # Checks if captured packet has an IP layer
        ip_src = packet[IP].src # Extracts source IP address from IP layer of packet
        ip_dst = packet[IP].dst # Extracts  destination IP address from IP layer of packet
        protocol = packet[IP].proto # Extracts protocol number from IP layer of packet, indicating the protocol used (ex: TCP, UDP...)
        print(f"IP Packet: Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}")
        
        if packet.haslayer(TCP): # Checks if captured packet has a TCP layer
            src_port = packet[TCP].sport # Extracts source port number from TCP layer of packet
            dst_port = packet[TCP].dport # Extracts destination port number from TCP layer of packet
            print(f"TCP Packet: Source Port: {src_port}, Destination Port: {dst_port}")
            print("\n")

# Start sniffing network traffic
print("Starting network sniffer... \n")
try:
    # Put in "iface=" the name of my network interface: Ethernet or Wi-Fi !!!
    sniff(prn=packet_callback, iface='Ethernet', store=0, count=100)
   # Initiates the packet sniffing process. It uses the sniff function from Scapy, specifying packet_callback as the callback function to handle captured packets. The iface parameter specifies the network interface to sniff on, in this case, it's set to 'Ethernet'. 
   # The store parameter is set to 0, which means it doesn't store packets in memory. The count parameter is the number of packets to sniff.
   
except KeyboardInterrupt: # Catches the KeyboardInterrupt exception, which is raised when the user interrupts the script (e.g., by pressing Ctrl+C)
    print("\nStopping network sniffer...") #Prints a message indicating that the network sniffer is stopping
