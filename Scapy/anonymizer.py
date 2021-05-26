#!/usr/bin/env python3

##
#
#  This script will anonymize IP addresses.
#  Right now, it just replaces them in the IP (v4 and v6) header
#  goal is to expand this script to also search payload and
#  include hostnames
#
#   questions/comments: jullrich@sans.edu
#
##

import sys
import os

os.sys.path.append('/opt/local/bin')
from scapy.all import *

anon=['10.5.1.241','10.5.1.250','2603:3010:182:8021::ab9e']
replace=['192.0.2.10','192.0.2.2','2001:db8::2']

def anon4(ip):
  print(ip[IP].src)
  if ip[IP].src in anon:
    n=anon.index(ip[IP].src)
    ip[IP].src=replace[n]
  if ip[IP].dst in anon:
    n=anon.index(ip[IP].dst)
    ip[IP].dst=replace[n]    
  return ip

def anon6(ip):
  print(ip[IPv6].src)
  if ip[IPv6].src in anon:
    n=anon.index(ip[IPv6].src)
    ip[IPv6].src=replace[n]
  if ip[IPv6].dst in anon:
    n=anon.index(ip[IPv6].dst)
    ip[IPv6].dst=replace[n]
  return ip
                 



print(sys.argv[1])
pkts=rdpcap(sys.argv[1])

for i in range(0,len(pkts)):
  if Ether in pkts[i]:
    # IPv4
    if pkts[i]['Ether'].type == 2048:
      pkts[i]['IP']=anon4(pkts[i]['IP'])
      p=pkts[i]['IP'].proto
      del pkts[i]['IP'].chksum
      if p == 17:
        del pkts[i]['UDP'].chksum
      if p == 6:
        del pkts[i]['TCP'].chksum
    # IPv6
    elif pkts[i]['Ether'].type == 34525:
      pkts[i]['IPv6']=anon6(pkts[i]['IPv6'])
      p=pkts[i]['IPv6'].nh
      if p == 17:
        del pkts[i]['UDP'].chksum
      if p == 6:
        del pkts[i]['TCP'].chksum
    # ARP
    elif pkts[i]['Ether'].type == 2054:
      s=pkts[i]['Ether'].src
    # VLAN
    elif pkts[i]['Ether'].type == 33024:
      s=pkts[i]['Ether'].src
    else:
      print(pkts[i]['Ether'].type)
  else:
    pkts[i].summary()

wrpcap('out.pcap',pkts)


      
