#!/usr/bin/env bash

###
#
# This script can be used to recover the exfiltrated file sent by the "ICMPCovertChannel" script
# TODO: the last line is duplicated if it doesn't fill the 16 characters.
#
#  created by Johannes Ullrich jullrich@sans.edu.
#  Creative Commons Attribution-NonComercial-ShareAlike license
#  https://creativecommons.org/licenses/by-nc-sa/4.0/
###

if [ "$#" != 2 ]; then
    echo "This script requires two parameters: the pcap file name and the domain name used to exfil the data"
    exit
fi

tshark -r $1 -Y "dns.qry.name contains $2" -n -T fields -e dns.qry.name | xxd -r -p

