#!/usr/bin/python
from scapy.all import *

# Interface to listen
ethernet = 'ens33'

# My starting sequence number
sequence=100

# Wait for an inbound syn
packets=sniff(filter="tcp[13]&0x02 != 0", count=1, iface=ethernet)
syn = packets[0]
my_ack = syn.getlayer("TCP").seq + 1
dest = syn.getlayer("IP").src
sport = syn.getlayer("TCP").dport
dport = syn.getlayer("TCP").sport

target = IP(dst=dest)
tcp_layer = TCP(sport=sport, dport=dport, ack=my_ack, seq=sequence, flags="S")
response = sr1(target/tcp_layer)
synack = response[0]
target = IP(dst=dest)
tcp_layer=TCP(sport=sport, dport=dport, ack=my_ack, seq=sequence+1, flags="A")
send(target/tcp_layer)
