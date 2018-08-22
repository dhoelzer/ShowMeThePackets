#!/bin/bash

SECTIONS=4
COLS=$(tput cols)
ROWS=$(tput lines)
SPLIT=$(($ROWS-$SECTIONS-4))
SPLIT=$(($SPLIT/$SECTIONS))
function sep
{
  string=$1
  line="+---[ $string ]"
  strlen=${#line}
  padding=$(($COLS-$strlen-1))
  printf -v output '%*s' "$padding"
  echo $line${output// /-}+
}
sep Connections
if [ -e conn.log ] ; then 
  cat conn.log | bro-cut -d ts id.orig_h id.orig_p id.resp_h id.resp_p proto orig_bytes resp_bytes orig_pkts resp_pkts | tail -$SPLIT
fi
sep Weird
if [ -e weird.log ] ; then
  cat weird.log | bro-cut -d ts id.orig_h id.orig_p id.resp_h id.resp_p name|  tail -$SPLIT
fi
sep "DNS Queries"
if [ -e dns.log ] ; then
  cat dns.log | bro-cut -d ts id.orig_h query answers auth | tail -$SPLIT
fi
sep Notices
if [ -e notice.log ] ; then
  cat notice.log | bro-cut -d ts id.orig_h id.resp_h note msg | tail -$SPLIT
fi
