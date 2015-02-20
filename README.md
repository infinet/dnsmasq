## DNSMASQ fork for improving --ipsets, --server, and --address performance

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


### Precompiled OpenWrt packages

For OpenWrt Attitude Adjustment (12.09 final) and Barrier Breaker (14.07)
[ar71xx](http://sourceforge.net/projects/dnsmasq-fast-lookup/files/). DNSSEC is
disabled.

    sha1sum
    d9376f269e14eeb2823df1c1d12ec6168914927b  dnsmasq-ipset_2.72-4_ar71xx_Attitude_Adjustment_12.09.ipk
    5b5e677c7115ce35eaa2624861c8f291153a2a8c  dnsmasq-ipset_2.72-4_ar71xx_Barrier_Breaker_14.07.ipk

    md5sum
    8717aec763d90061d157d28f5ba6a959  dnsmasq-ipset_2.72-4_ar71xx_Attitude_Adjustment_12.09.ipk
    dba2b0a803afbd8f4ebe67bf0a1cce6b  dnsmasq-ipset_2.72-4_ar71xx_Barrier_Breaker_14.07.ipk

