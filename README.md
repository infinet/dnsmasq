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
    1770fb227bfbf67459aecce8f3116556355adde4  dnsmasq-ipset_2.73test6_ar71xx_Attitude_Adjustment_12.09.ipk
    980a022d018a7e2d30d3ca8577e093e59df67425  dnsmasq-ipset_2.73test6_ar71xx_Barrier_Breaker_14.07.ipk

    md5sum
    cafb043b046df36f9b137b55cf0a98ff  dnsmasq-ipset_2.73test6_ar71xx_Attitude_Adjustment_12.09.ipk
    49798f6c45399fd935d09396bde560b9  dnsmasq-ipset_2.73test6_ar71xx_Barrier_Breaker_14.07.ipk

