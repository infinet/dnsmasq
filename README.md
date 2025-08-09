DNSMASQ fork for improving --ipsets, --server, and --address performance
========================================================================

Dnsmasq matches domain names for --ipsets, --server, and --address options by
iterates over linked list. It is good enough for general use, but slows down as
the domain names to be matched grows.

Here introduce a modified dnsmasq for fast lookup ipset/server/address options.
The match time is constant regardless the size of rules.


                       root
                        |
             +---------------------+
            com                   org
             |                     |
    +------------------+     +-------------+
    yahoo google twitter   debian       freebsd
      |      |               |             |
     www    mail          +---------+     www
                          cn jp uk us
                          |
                         ftp


The lookup steps over domain name hierarchy top-down. All labels are stored in
open addressing hash tables. Sub-level labels that belong to different parent
nodes are stored separately. e.g. yahoo, google, and twitter are in one hash
table, while debian and freebsd are in another.

The hash table size is power of 2, two hash functions are used to compute hash
bucket. For locating a particular label from hash table, two hash values are
compared first, only if they are match, should the more expensive string
comparison be used to confirm the search.


Example usage
-------------

Use DNS blackhole to block malware site:

    address=/example.com/

Force google DNS as upstream server for special domain:

    server=/example.com/8.8.8.8

Add all IPs of a paticular domain to IPSET:

    ipset=/example.com/example-ipset
