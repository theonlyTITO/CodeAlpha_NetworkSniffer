from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

print("-" * 50)
print("              Network Packet Sniffer")
print("-" * 50)



def packet_info(packet):


   
    
    if packet.haslayer(IP):
         

        time_now=datetime.now().strftime("%H:%M:%S")

        Source_IP=packet[IP].src
        Destination_IP=packet[IP].dst
        Protocol=packet[IP].proto


        Protocol_name=""
        if Protocol == 6:
            Protocol_name = "TCP"
        elif Protocol == 17:
            Protocol_name = "UDP"
        else:
            Protocol_name = "Other"

        print(f"Time: {time_now}")
        print(f"Source IP: {Source_IP}")
        print(f"Destination IP: {Destination_IP}")
        print(f"Protocol: {Protocol_name}")


        if packet.haslayer(TCP):
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")


        print("-" * 50)


sniff(prn=packet_info, count=10)
