## DNSMASQ fork for improving --ipsets and --server performance

### Current status

The --ipsets and --server lookup has been rewritten. It scales well with thousands
of --ipsets and --server entries.


               _______root_______
              /                  \
            com                   org
          /  |  \                /    \
         /   |   \              /      \
    yahoo google twitter     debian  freebsd
      |      |                  |        |
     www    mail               cn       www
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

The search should take constant time regardless the size of --ipset and --server
rules.



### Issues

* `tcp_request` not working
* `check_server` not print out server supported domains properly


[Contact me](mailto: weichen302@gmail.com)
