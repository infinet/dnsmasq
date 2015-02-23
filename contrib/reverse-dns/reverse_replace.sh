#!/bin/bash
# $Id: reverse_replace.sh 4 2015-02-17 20:14:59Z jo $
#
# Usage e.g.: netstat -n -4 | reverse_replace.sh 
# Parses stdin for IP4 addresses and replaces them 
# with names retrieved by reverse_dns.sh
#

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
DNS=$DIR/reverse_dns.sh

# sed regex
IP_regex='[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'

while read LINE; do
  if grep --quiet $IP_regex <<< "$LINE"; then
    IPs=`sed "s#.*\b\($IP_regex\)\b.*#\1 #g" <<< "$LINE"`
    IPs=($IPs)
    for IP in "${IPs[@]}"
    do
      NAME=`$DNS $IP`
      # echo "$NAME is $IP";
      LINE="${LINE/$IP/$NAME}" 
    done
  fi
  echo $LINE
done < /dev/stdin

