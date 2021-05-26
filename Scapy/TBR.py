#!/usr/bin/python
import threading
from scapy.all import *
import sys

# Listening interface
ethernet = 'ens33'

ones =   "11111111"
twos =   "22222222"
threes = "33333333"
fours =  "44444444"
fives =  "55555555"
sixes =  "66666666"
checksums = []
possible_payloads = { }

payload = 3*ones+2*fours+1*twos+3*threes+3*sixes
possible_payloads[payload] = "BSD"
payload = 1*ones + 3*fours + 2*twos + 3*fives + 3*sixes
possible_payloads[payload] = "BSD Right"
payload = 3*ones + 2*fours + 1*twos + 3*fives + 3*sixes
possible_payloads[payload] = "Linux"
payload = 3*ones + 1*fours + 2*twos + 3*threes + 3*sixes
possible_payloads[payload] = "First"
payload = 1*ones + 4*fours + 1*twos + 3*fives + 3*sixes
possible_payloads[payload] = "Last / RFC 791"
payload = 3*ones + 1*fours + 1*twos + 3*threes + 3*sixes
possible_payloads[payload] = "OS X"

def send_packets(chk):
	packet1 = IP(dst=target, flags="MF", frag=0)/ICMP(type=8,code=0, chksum=chk)/(3*ones)
	packet2 = IP(dst=target, flags="MF", frag=4, proto=1)/(2*twos)
	packet3 = IP(dst=target, flags="MF", frag=6, proto=1)/(3*threes)
	packet4 = IP(dst=target, flags="MF", frag=1, proto=1)/(4*fours)
	packet5 = IP(dst=target, flags="MF", frag=6, proto=1)/(3*fives)
	packet6 = IP(dst=target, frag=9, proto=1)/(3*sixes)
	send(packet1, verbose = False)
	send(packet2, verbose = False)
	send(packet3, verbose = False)
	send(packet4, verbose = False)
	send(packet5, verbose = False)
	send(packet6, verbose = False)

def capture_response():
	packets = sniff(filter=("icmp[0] = 0 and src host %s" % target), count = 1, iface = ethernet)
	packet = packets[0]
	print(str(possible_payloads[ICMP].payload))

if len(sys.argv) < 2:
	print("You must supply a target IP address.")
	sys.exit(1)
target = sys.argv[1]

for payload in possible_payloads:
	packet = IP(dst=target)/ICMP(type=8,code=0)/payload
	send(packet, verbose=False)
#	packet = packet.__class__(str(packet))
	checksums.append(packet[ICMP].chksum)

# This is a fixup to the payload table because Google has a really
# weird response, truncating the response.
payload = 3*ones + 1*fours + 2*twos + 2*threes
possible_payloads[payload] = "Google - Truncated response"

thread = threading.Thread(target=capture_response)
thread.start()
for x in checksums:
	send_packets(x)
thread.join()
