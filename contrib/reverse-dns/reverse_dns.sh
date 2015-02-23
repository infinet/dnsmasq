#!/bin/bash
# $Id: reverse_dns.sh 4 2015-02-17 20:14:59Z jo $
#
# Usage: reverse_dns.sh IP
# Uses the dnsmasq query log to lookup the name 
# that was last queried to return the given IP.
#

IP=$1
qmIP=`echo $IP | sed 's#\.#\\.#g'`
LOG=/var/log/dnsmasq.log

IP_regex='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'

if ! [[ $IP =~ $IP_regex ]]; then
  echo -n $IP
  exit
fi

NAME=`tac $LOG | \
  grep " is $IP" | head -1 | \
  sed "s#.* \([^ ]*\) is $qmIP.*#\1#" `

if [ -z "$NAME" ]; then
  echo -n $IP
else
  echo -n $NAME
fi

