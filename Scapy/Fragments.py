#!/usr/bin/env python2.7

##
#
#  This script will recreate the overlapping fragments
# used in the extra credit fragmentation exercise
#
#  please send comments/corrections to jullrich@sans.edu
# use/modify for good
##


import sys
import random
import socket
from scapy.all import *

dst=sys.argv[1]

try:
    socket.inet_aton(dst)
except socket.error:
    print "Invalid IP Address"
    sys.exit

ipid = random.randint(0,65535)

ip=IP(dst=dst,id=ipid,proto=1,flags=1,frag=0)
packet1=ip/ICMP(type=8,chksum=0x5048)/'FRAGMENTFFRRAAGG'
ip.frag=2
packet2=ip/'GGAARRFFGGAARRFFGGAARRFF'
ip.frag=4
ip.flags=0
packet3=ip/'RRAAGGFFRRAAGGFF'
send(packet1)
send(packet3)
send(packet2)
