import sys
import random
from scapy.all import *

version = 0.1

def determineMACAddress():
  localMACs = [get_if_hwaddr(i) for i in get_if_list()]
  # Assume the last one is the MAC to send from.
  return localMACs[-1]

def spoofIsAt(pkt):
  isAt = ARP()
  isAt.hwdst=pkt[ARP].hwsrc
  isAt.pdst=pkt[ARP].psrc
  isAt.psrc=pkt[ARP].pdst
  isAt.hwsrc=sourceMAC
  isAt.op=2 #is-at
  print "Taking over {0}!".format(isAt.psrc)
  send(isAt, verbose = 0)

def spoofSYNACK(pkt):
  # Spoof the SYN ACK with a small window
  if (pkt[IP].src in answered and answered[pkt[IP].src] == pkt[IP].sport):
    return
  response = IP()/TCP()
  response[IP].src = pkt[IP].dst  # Since Ether also has a .src, we have to qualify
  response[IP].dst = pkt[IP].src
  response[TCP].sport = pkt[TCP].dport
  response[TCP].dport = pkt[TCP].sport
  response[TCP].seq = random.randint(1,2400000000)
  response[TCP].ack = pkt[TCP].seq + 1
  response[TCP].window = random.randint(1,100)
  response[TCP].flags = 0x12
  send(response, verbose = 0)
  answered[response[IP].dst] = response[TCP].dport


def spoofACK(pkt):
  # ACK anything that gets sent back with a zero window
  response = IP()/TCP()
  response[IP].src = pkt[IP].dst
  response[IP].dst = pkt[IP].src
  response[TCP].sport = pkt[TCP].dport
  response[TCP].dport = pkt[TCP].sport
  response[TCP].seq = pkt[TCP].ack
  response[TCP].ack = pkt[TCP].seq
  if Raw in pkt:
    if(len(pkt[Raw].load) > 1):  # The window probe is 1 byte
      response[TCP].ack = pkt[TCP].seq + len(pkt[Raw].load)
  response[TCP].window = 0
  response[TCP].flags = 0x10
  send(response, verbose = 0)



def packet_received(pkt):
  if pkt[Ether].src != sourceMAC:
    if ARP in pkt and pkt[ARP].op == 1: #who-has
      if(pkt[ARP].pdst in whohases and not pkt[Ether].src==sourceMAC):
        now = time.time()
        delta = now - whohases[pkt[ARP].pdst]
        if(delta <= 1.25):
          spoofIsAt(pkt)
      whohases[pkt[ARP].pdst] = time.time()
    if TCP in pkt and (pkt[TCP].flags & 0x3f) == 0x02:
      spoofSYNACK(pkt)
    if TCP in pkt and (pkt[TCP].flags & 0x12) == 0x10:
      spoofACK(pkt)

answered = dict()
whohases=dict()
sourceMAC = determineMACAddress()
print "Scapified LaBrea"
print "Version {0} - Copyright David Hoelzer / Enclave Forensics, Inc.".format(version)
print "Using {0} as the source MAC.  If this is wrong, edit the code.".format(sourceMAC)
sniff(prn=packet_received, store=0)
