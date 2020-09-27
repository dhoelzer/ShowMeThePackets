#!/usr/bin/env python
import os
os.sys.path.append("/usr/local/lib/python3.7/site-packages")
from scapy.all import TCP, IP, send, sr1
import random
import sys

class Connection:
    remote_host = ""
    remote_port = 0
    source_port = 0
    sequence = 0
    ack = 0

    def __init__(self, host='127.0.0.1', port=80):
        self.sequence = random.randrange(0,4000000)
        self.source_port = random.randrange(32000,33000)
        self.remote_host = host
        self.remote_port = int(port)
        packets = sr1(IP(dst=host)/TCP(dport=self.remote_port, sport=self.source_port, flags=0x02, seq=self.sequence))
        syn_ack = packets[0]
        self.ack = syn_ack["TCP"].seq
        self.ack = self.ack + 1
        self.sequence = self.sequence + 1
        send(IP(dst=host)/TCP(dport=self.remote_port, sport=self.source_port, flags=0x10, seq=self.sequence, ack=self.ack))

    def send(self, payload="", urgptr=0):
        if(urgptr > 0):
            packets = sr1(
                IP(dst=self.remote_host)/
                TCP(dport=self.remote_port, sport=self.source_port, ack=self.ack, seq=self.sequence, flags=0x38, urgptr=urgptr)/
                payload)
        else:
            packets = sr1(IP(dst=self.remote_host)/TCP(dport=self.remote_port, sport=self.source_port, ack=self.ack, seq=self.sequence, flags=0x18)/payload)
        self.sequence = self.sequence + len(payload)

    def close(self):
        packets = sr1(IP(dst=self.remote_host)/TCP(dport=self.remote_port, sport=self.source_port, ack=self.ack, seq=self.sequence, flags=0x11))        
        send(IP(dst=self.remote_host)/TCP(sport=self.source_port, dport=self.remote_port, ack=self.ack+1, seq=self.seq+1, flags=0x10))

def usage():
    docstring = f"""
{sys.argv[0]} <host> <port>

This tool will sequentially establish a series of connections to the
specified host.  The connections will behave as follows:

  1 - Normal connection sending the following over three packets:
    '#1 This is a test of the '
    'Urgent '
    'broadcasting system'

  2 - Normal connection sending the following over three packets
    but with the entirety of the second packet marked as urgent:
    '#2 This is a test of the '
    'Urgent '
    'broadcasting system'

  3 - Normal connection sending the following over three packets
    but with the first word of the second packet marked as urgent:
    '#3 This is a test of the '
    'Urgent '
    'broadcasting system'

  4 - Normal connection sending the following over three packets
    but with the entirety of the third packet marked as urgent:
    '#4 This is a test of the '
    'Urgent '
    'broadcasting system'

  5 - Normal connection sending the following over three packets
    but with the first letter of the second packet marked as urgent:
    '#5 This is a test of the '
    'Urgent '
    'broadcasting system'

  6 - Normal connection sending the following over three packets
    but with the first character of the first packet marked as urgent:
    '#6 This is a test of the '
    'Urgent '
    'broadcasting system'

  7 - Normal connection sending the following over three packets
    but with the first character of the third packet marked as urgent:
    '#7 This is a test of the '
    'Urgent '
    'broadcasting system'
"""
    print(docstring)
    sys.exit(0)

if len(sys.argv) != 3:
    usage()

target = sys.argv[1]
port = sys.argv[2]

for i in range(0,1):
    conn = Connection(host=target, port=port)
    if i == 0:
        conn.send('#1 This is a test of the ')
        conn.send('Urgent ')
        conn.send('broadcasting system')
        conn.close
    elif i == 1:
        conn.send('#2 This is a test of the ')
        conn.send('Urgent ', urgptr=len('Urgent '))
        conn.send('broadcasting system')
        conn.close
    elif i == 2:
        conn.send('#3 This is a test of the ')
        conn.send('Urgent ', urgptr=len('Urgent'))
        conn.send('broadcasting system')
        conn.close
    elif i == 3:
        conn.send('#4 This is a test of the ')
        conn.send('Urgent ')
        conn.send('broadcasting system', urgptr=len('broadcasting system'))
        conn.close
    elif i == 4:
        conn.send('#5 This is a test of the ')
        conn.send('Urgent ', urgptr=1)
        conn.send('broadcasting system')
        conn.close
    elif i == 5:
        conn.send('#6 This is a test of the ', urgptr=1)
        conn.send('Urgent ')
        conn.send('broadcasting system')
        conn.close
    elif i == 6:
        conn.send('#7 This is a test of the ')
        conn.send('Urgent ')
        conn.send('broadcasting system', urgptr=1)
        conn.close

