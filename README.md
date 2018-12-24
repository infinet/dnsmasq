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

For OpenWrt Chaos Calmer 15.05 on ar71xx and mt7620 platform:

[dnsmasq-full_2.72-5_ar71xx_Chaos_Calmer_15.05.ipk](https://ipfs.io/ipfs/QmYktJLB7f1CmM4sLzZBTBTBSVxu3HD6wjfZE3bqHzBK48/dnsmasq-full_2.72-5_ar71xx_Chaos_Calmer_15.05.ipk)

[dnsmasq-full_2.72-5_ramips_24kec_Chaos_Calmer_15.05.ipk](https://ipfs.io/ipfs/QmYktJLB7f1CmM4sLzZBTBTBSVxu3HD6wjfZE3bqHzBK48/dnsmasq-full_2.72-5_ramips_24kec_Chaos_Calmer_15.05.ipk)

For LEDE 17.01 on mt7628NN platform(GL-MT300N-V2):

[dnsmasq-full_2.73-11_mipsel_24kc_LEDE_17.01.ipk](https://ipfs.io/ipfs/QmYktJLB7f1CmM4sLzZBTBTBSVxu3HD6wjfZE3bqHzBK48/dnsmasq-full_2.73-11_mipsel_24kc_LEDE_17.01.ipk)

	sha1sum
	0a1a7c13714e982b2cf98b33fe16d572f3d1a58d  dnsmasq-full_2.72-5_ar71xx_Chaos_Calmer_15.05.ipk
	58b1b3e9447f55ae26dc6a5834cea826ae7a51c1  dnsmasq-full_2.72-5_ramips_24kec_Chaos_Calmer_15.05.ipk
	c0788585e4ca68b3b8a9107bbbfd89bcaabc0479  dnsmasq-full_2.73-11_mipsel_24kc_LEDE_17.01.ipk


Example usage
-------------

Use DNS blackhole to block malware site:

    address=/example.com/

Force google DNS as upstream server for special domain:

    server=/example.com/8.8.8.8

Add all IPs of a paticular domain to IPSET:

    ipset=/example.com/example-ipset
