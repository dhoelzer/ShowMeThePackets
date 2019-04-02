#!/usr/bin/evn bash

###
#
# This script can be used to recover the exfiltrated file sent by the "ICMPCovertChannel" script
# TODO: the last line is duplicated if it doesn't fill the 16 characters.
#
# created by Johannes Ullrich jullrich@sans.edu.
# Creative Commons Attribution-NonComercial-ShareAlike license
# https://creativecommons.org/licenses/by-nc-sa/4.0/
#
###

if [ "$#" != 1 ]; then
    echo "The pcap file used to collect the data is required."
    exit
fi

for line in `tshark -r $1 -Y 'icmp.type==8' -n -T fields -e data`; do
    echo $b | cut -c 1-16; done | xxd -p -r
done
