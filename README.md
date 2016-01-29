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


Precompiled OpenWrt packages
----------------------------

For OpenWrt Chaos Calmer 15.05 on
[ar71xx and mt7620 platform](http://sourceforge.net/projects/dnsmasq-fast-lookup/files/). DNSSEC is disabled.

    sha1sum
    d90c5eaa3c88d2e569a9801d2b081943fbd6410d dnsmasq-full_2.72-5_ar71xx_Chaos_Calmer_15.05.ipk
    eb2d9e332271d8dd376492645c8fe073fbf59cdb dnsmasq-full_2.72-5_ramips_24kec_Chaos_Calmer_15.05.ipk

    md5sum
    a4d7fbcfb2e8cdf318d3bb41eb3ac10e dnsmasq-full_2.72-5_ar71xx_Chaos_Calmer_15.05.ipk
    d30409051b5216b9ce18a2791cbc2519 dnsmasq-full_2.72-5_ramips_24kec_Chaos_Calmer_15.05.ipk


Example usage
-------------

Use DNS blackhole to block malware site:

    address=/example.com/

Force google DNS as upstream server for special domain:

    server=/example.com/8.8.8.8

Add all IPs of a paticular domain to IPSET:

    ipset=/example.com/example-ipset
