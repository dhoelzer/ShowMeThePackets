#!/usr/bin/env python

##
#
#  Normal 3way TCP handshake over IPv6 and HTTP request.
# The payload for the HTTP request is split into two
# packets. This is later (see 3wayIPv6DHEV.py) used to
# test the Wireshark / Snort TCP reassembly routines
#
#  questions/comments: jullrich@sans.edu
#
##

from scapy.all import *

dst="10.128.0.11"
dport=80

ip=IP(dst=dst)
sport=random.randint(49152,65535)
isn=random.randint(0,4294967296)
TCP_SYN=TCP(sport=sport, dport=dport, flags="S", seq=isn,options=[('WScale',0)])
TCP_SYNACK=sr1(ip/TCP_SYN)
my_ack = TCP_SYNACK.seq + 1
TCP_ACK=TCP(sport=sport, dport=dport, flags="A", seq=isn+1, ack=my_ack)
send(ip/TCP_ACK)
my_payload1="GET / HTTP/1.1\r\nHost: www."
my_payload2="sec503.com\r\n\r\n"
TCP_PUSH=TCP(sport=sport,dport=dport, flags="PA", seq=isn+1,ack=my_ack)
send(ip/TCP_PUSH/my_payload1)
TCP_PUSH=TCP(sport=sport,dport=dport, flags="PA", seq=isn+1+len(my_payload1),ack=my_ack)
send(ip/TCP_PUSH/my_payload2)
TCP_FIN=TCP(sport=sport,dport=dport,flags="FA", seq=isn+1+len(my_payload1)+len(my_payload2),ack=my_ack)
TCP_FINACK=sr1(ip/TCP_FIN)
my_ack=TCP_FINACK.seq+1

TCP_ACK=TCP(sport=sport, dport=dport, flags="A", seq=isn+1+len(my_payload1)+len(my_payload2), ack=my_ack)
send(ip/TCP_ACK)
