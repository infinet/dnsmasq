/* dnsmasq is Copyright (c) 2000-2003 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* Author's email: simon@thekelleys.org.uk */

#define COPYRIGHT "Copyright (C) 2000-2004 Simon Kelley" 

#ifdef __linux__
/* for pselect.... */
#define _XOPEN_SOURCE 600 
/* but then DNS headers don't compile without.... */
#define _BSD_SOURCE
#endif
 
/* get these before config.h  for IPv6 stuff... */
#include <sys/types.h> 
#include <netinet/in.h>

/* get this before config.h too. */
#include <syslog.h>
#include <arpa/nameser.h>

#include "config.h"
 
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/wait.h>
#if defined(__sun) || defined(__sun__)
#  include <sys/sockio.h>
#endif
#include <sys/time.h>
#include <limits.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#ifdef HAVE_GETOPT_LONG
#  include <getopt.h>
#endif
#include <time.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#if defined(__OpenBSD__) || defined(__NetBSD__)
#  include <netinet/if_ether.h>
#else
#  include <net/ethernet.h>
#endif
#include <net/if_arp.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#ifdef HAVE_BPF
#  include <net/bpf.h>
#  include <net/if_dl.h>
#else
#  include <netpacket/packet.h>
#endif
#include <sys/uio.h>

/* Size: we check after adding each record, so there must be 
     memory for the largest packet, and the largest record */
#define DNSMASQ_PACKETSZ PACKETSZ+MAXDNAME+RRFIXEDSZ

#define OPT_BOGUSPRIV      1
#define OPT_FILTER         2
#define OPT_LOG            4
#define OPT_SELFMX         8
#define OPT_NO_HOSTS       16
#define OPT_NO_POLL        32
#define OPT_DEBUG          64
#define OPT_ORDER          128
#define OPT_NO_RESOLV      256
#define OPT_EXPAND         512
#define OPT_LOCALMX        1024
#define OPT_NO_NEG         2048
#define OPT_NODOTS_LOCAL   4096
#define OPT_NOWILD         8192
#define OPT_ETHERS         16384
#define OPT_RESOLV_DOMAIN  32768
#define OPT_NO_FORK        65536
#define OPT_AUTHORITATIVE  131072

struct all_addr {
  union {
    struct in_addr addr4;
#ifdef HAVE_IPV6
    struct in6_addr addr6;
#endif
  } addr;
};

struct bogus_addr {
  struct in_addr addr;
  struct bogus_addr *next;
};

/* dns doctor param */
struct doctor {
  struct in_addr in, out, mask;
  struct doctor *next;
};

struct mx_record {
  char *mxname, *mxtarget;
  struct mx_record *next;
};

union bigname {
  char name[MAXDNAME];
  union bigname *next; /* freelist */
};

struct crec { 
  struct crec *next, *prev, *hash_next;
  time_t ttd; /* time to die */
  int uid; 
  union {
    struct all_addr addr;
    struct {
      struct crec *cache;
      int uid;
    } cname;
  } addr;
  unsigned short flags;
  union {
    char sname[SMALLDNAME];
    union bigname *bname;
    char *namep;
  } name;
};

#define F_IMMORTAL  1
#define F_CONFIG    2
#define F_REVERSE   4
#define F_FORWARD   8
#define F_DHCP      16 
#define F_NEG       32       
#define F_HOSTS     64
#define F_IPV4      128
#define F_IPV6      256
#define F_BIGNAME   512
#define F_UPSTREAM  1024
#define F_SERVER    2048
#define F_NXDOMAIN  4096
#define F_QUERY     8192
#define F_CNAME     16384
#define F_NOERR     32768

/* struct sockaddr is not large enough to hold any address,
   and specifically not big enough to hold and IPv6 address.
   Blech. Roll our own. */
union mysockaddr {
  struct sockaddr sa;
  struct sockaddr_in in;
#ifdef HAVE_BROKEN_SOCKADDR_IN6
  /* early versions of glibc don't include sin6_scope_id in sockaddr_in6
     but latest kernels _require_ it to be set. The choice is to have
     dnsmasq fail to compile on back-level libc or fail to run
     on latest kernels with IPv6. Or to do this: sorry that it's so gross. */
  struct my_sockaddr_in6 {
    sa_family_t     sin6_family;    /* AF_INET6 */
    uint16_t        sin6_port;      /* transport layer port # */
    uint32_t        sin6_flowinfo;  /* IPv6 traffic class & flow info */
    struct in6_addr sin6_addr;      /* IPv6 address */
    uint32_t        sin6_scope_id;  /* set of interfaces for a scope */
  } in6;
#elif defined(HAVE_IPV6)
  struct sockaddr_in6 in6;
#endif
};

#define SERV_FROM_RESOLV     1  /* 1 for servers from resolv, 0 for command line. */
#define SERV_NO_ADDR         2  /* no server, this domain is local only */
#define SERV_LITERAL_ADDRESS 4  /* addr is the answer, not the server */ 
#define SERV_HAS_SOURCE      8  /* source address specified */
#define SERV_HAS_DOMAIN     16  /* server for one domain only */
#define SERV_FOR_NODOTS     32  /* server for names with no domain part only */
#define SERV_TYPE    (SERV_HAS_DOMAIN | SERV_FOR_NODOTS)

struct serverfd {
  int fd;
  union mysockaddr source_addr;
  struct serverfd *next;
};

struct server {
  union mysockaddr addr, source_addr;
  struct serverfd *sfd; /* non-NULL if this server has its own fd bound to
			   a source port */
  char *domain; /* set if this server only handles a domain. */ 
  int flags, tcpfd;
  struct server *next; 
};

struct irec {
  union mysockaddr addr;
  struct irec *next;
};

struct listener {
  int fd, tcpfd, family;
  struct listener *next;
};

/* interface and address parms from command line. */
struct iname {
  char *name;
  union mysockaddr addr;
  int isloop, used;
  struct iname *next;
};

/* resolv-file parms from command-line */
struct resolvc {
  struct resolvc *next;
  int is_default;
  int logged;
  char *name;
};

/* adn-hosts parms from command-line */
struct hostsfile {
  struct hostsfile *next;
  char *fname;
  int index; /* matches to cache entries fro logging */
};

struct frec {
  union mysockaddr source;
  struct all_addr dest;
  struct server *sentto;
  unsigned int iface;
  unsigned short orig_id, new_id;
  int fd;
  unsigned int crc;
  time_t time;
  struct frec *next;
};

struct dhcp_lease {
  int clid_len;          /* length of client identifier */
  unsigned char *clid;   /* clientid */
  char *hostname, *fqdn; /* name from client-hostname option or config */
  time_t expires;        /* lease expiry */
  unsigned char hwaddr[ETHER_ADDR_LEN]; 
  struct in_addr addr;
  struct dhcp_lease *next;
};

struct dhcp_netid {
  char *net;
  struct dhcp_netid *next;
};

struct dhcp_netid_list {
  struct dhcp_netid *list;
  struct dhcp_netid_list *next;
};
struct dhcp_config {
  unsigned int flags;
  int clid_len;          /* length of client identifier */
  unsigned char *clid;   /* clientid */
  unsigned char hwaddr[ETHER_ADDR_LEN]; 
  char *hostname;
  struct dhcp_netid netid;
  struct in_addr addr;
  unsigned int lease_time;
  struct dhcp_config *next;
};

#define CONFIG_DISABLE   1
#define CONFIG_CLID      2
#define CONFIG_HWADDR    4
#define CONFIG_TIME      8
#define CONFIG_NAME     16
#define CONFIG_ADDR     32
#define CONFIG_NETID    64
#define CONFIG_NOCLID  128

struct dhcp_opt {
  int opt, len, is_addr;
  unsigned char *val;
  struct dhcp_netid *netid;
  struct dhcp_opt *next;
};

struct dhcp_boot {
  char *file, *sname;
  struct in_addr next_server;
  struct dhcp_netid *netid;
  struct dhcp_boot *next;
};

struct dhcp_vendor {
  int len, is_vendor;
  char *data;
  struct dhcp_netid netid;
  struct dhcp_vendor *next;
};

struct dhcp_context {
  unsigned int lease_time, addr_epoch;
  struct in_addr netmask, broadcast, router;
  struct in_addr start, end; /* range of available addresses */
  int static_only;
  struct dhcp_netid netid;
  struct dhcp_context *next, *current;
};

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;


struct udp_dhcp_packet {
        struct ip ip;
        struct udphdr {
	  u16 uh_sport;               /* source port */
	  u16 uh_dport;               /* destination port */
	  u16 uh_ulen;                /* udp length */
	  u16 uh_sum;                 /* udp checksum */
	} udp;
        struct dhcp_packet {
	  u8 op, htype, hlen, hops;
	  u32 xid;
	  u16 secs, flags;
	  struct in_addr ciaddr, yiaddr, siaddr, giaddr;
	  u8 chaddr[16], sname[64], file[128];
	  u8 options[312];
	} data;
};


struct daemon {
  /* datastuctures representing the command-line and 
     config file arguments. All set (including defaults)
     in option.c */

  unsigned int options;
  struct resolvc default_resolv, *resolv_files;
  struct mx_record *mxnames;
  char *mxtarget;
  char *lease_file; 
  char *username, *groupname;
  char *domain_suffix;
  char *runfile; 
  struct iname *if_names, *if_addrs, *if_except;
  struct bogus_addr *bogus_addr;
  struct server *servers;
  int cachesize;
  int port, query_port;
  unsigned long local_ttl;
  struct hostsfile *addn_hosts;
  struct dhcp_context *dhcp;
  struct dhcp_config *dhcp_conf;
  struct dhcp_opt *dhcp_opts;
  struct dhcp_vendor *dhcp_vendors;
  struct dhcp_boot *boot_config;
  struct dhcp_netid_list *dhcp_ignore;
  int dhcp_max; 
  unsigned int min_leasetime;
  struct doctor *doctors;
  unsigned short edns_pktsz;

  /* globally used stuff for DNS */
  char *packet; /* packet buffer */
  char *namebuff; /* MAXDNAME size buffer */
  struct serverfd *sfds;
  struct listener *listeners;
  struct server *last_server;
  int uptime_fd;
  
  /* DHCP state */
  int dhcpfd, dhcp_raw_fd, dhcp_icmp_fd, lease_fd;
  struct udp_dhcp_packet *dhcp_packet;
  char *dhcp_buff, *dhcp_buff2;
};

/* cache.c */
void cache_init(int cachesize, int log);
void log_query(unsigned short flags, char *name, struct all_addr *addr, 
	       unsigned short type, struct hostsfile *addn_hosts, int index);
struct crec *cache_find_by_addr(struct crec *crecp,
				struct all_addr *addr, time_t now, 
				unsigned short prot);
struct crec *cache_find_by_name(struct crec *crecp, 
				char *name, time_t now, unsigned short  prot);
void cache_end_insert(void);
void cache_start_insert(void);
struct crec *cache_insert(char *name, struct all_addr *addr,
			  time_t now, unsigned long ttl, unsigned short flags);
void cache_reload(int opts, char *buff, char *domain_suffix, struct hostsfile  *addn_hosts);
void cache_add_dhcp_entry(struct daemon *daemon, char *host_name, struct in_addr *host_address, time_t ttd);
void cache_unhash_dhcp(void);
void dump_cache(struct daemon *daemon);
char *cache_get_name(struct crec *crecp);

/* rfc1035.c */
unsigned short extract_request(HEADER *header, unsigned int qlen, 
			       char *name, unsigned short *typep);
int setup_reply(HEADER *header, unsigned int qlen,
		struct all_addr *addrp, unsigned short flags,
		unsigned long local_ttl);
void extract_addresses(HEADER *header, unsigned int qlen, char *namebuff, 
		       time_t now, struct daemon *daemon);
int answer_request(HEADER *header, char *limit, unsigned int qlen, struct daemon *daemon, time_t now);
int check_for_bogus_wildcard(HEADER *header, unsigned int qlen, char *name, 
			     struct bogus_addr *addr, time_t now);
unsigned char *find_pseudoheader(HEADER *header, unsigned int plen,
				 unsigned int *len, unsigned char **p);
int check_for_local_domain(char *name, time_t now, struct mx_record *mx);
unsigned int questions_crc(HEADER *header, unsigned int plen);
int resize_packet(HEADER *header, unsigned int plen, 
		  unsigned char *pheader, unsigned int hlen);

/* util.c */
unsigned short rand16(void);
int legal_char(char c);
int canonicalise(char *s);
int atoi_check(char *a, int *res);
void die(char *message, char *arg1);
void complain(char *message, char *arg1);
void *safe_malloc(int size);
char *safe_string_alloc(char *cp);
int sa_len(union mysockaddr *addr);
int sockaddr_isequal(union mysockaddr *s1, union mysockaddr *s2);
int hostname_isequal(unsigned char *a, unsigned char *b);
time_t dnsmasq_time(int fd);
int is_same_net(struct in_addr a, struct in_addr b, struct in_addr mask);
int retry_send(void);

/* option.c */
struct daemon *read_opts (int argc, char **argv);

/* forward.c */
void forward_init(int first);
void reply_query(struct serverfd *sfd, struct daemon *daemon, time_t now);
void receive_query(struct listener *listen, struct daemon *daemon, time_t now);
char *tcp_request(struct daemon *daemon, int confd, time_t now);

/* network.c */
struct serverfd *allocate_sfd(union mysockaddr *addr, struct serverfd **sfds);
void reload_servers(char *fname, struct daemon *daemon);
void check_servers(struct daemon *daemon, struct irec *interfaces);
struct irec *enumerate_interfaces(struct daemon *daemon);
struct listener *create_wildcard_listeners(int port);
struct listener *create_bound_listeners(struct irec *interfaces, int port);

/* dhcp.c */
void dhcp_init(struct daemon *daemon);
void dhcp_packet(struct daemon *daemon, time_t now);

int address_available(struct dhcp_context *context, struct in_addr addr);
int address_allocate(struct dhcp_context *context, struct daemon *daemon,
		     struct in_addr *addrp, unsigned char *hwaddr);
struct dhcp_config *find_config(struct dhcp_config *configs,
				struct dhcp_context *context,
				unsigned char *clid, int clid_len,
				unsigned char *hwaddr, char *hostname);
void dhcp_update_configs(struct dhcp_config *configs);
void dhcp_read_ethers(struct daemon *daemon);
struct dhcp_config *config_find_by_address(struct dhcp_config *configs, struct in_addr addr);

/* lease.c */
void lease_update_file(int force, time_t now);
void lease_update_dns(struct daemon *daemon);
void lease_init(struct daemon *daemon, time_t now);
struct dhcp_lease *lease_allocate(unsigned char *clid, int clid_len, struct in_addr addr);
void lease_set_hwaddr(struct dhcp_lease *lease, unsigned char *hwaddr);
void lease_set_hostname(struct dhcp_lease *lease, char *name, char *suffix);
void lease_set_expires(struct dhcp_lease *lease, time_t exp);
struct dhcp_lease *lease_find_by_client(unsigned char *clid, int clid_len);
struct dhcp_lease *lease_find_by_addr(struct in_addr addr);
void lease_prune(struct dhcp_lease *target, time_t now);
void lease_update_from_configs(struct dhcp_config *dhcp_configs, char *domain);

/* rfc2131.c */
int dhcp_reply(struct daemon *daemon, struct in_addr iface_addr, char *iface_name, unsigned int sz, time_t now);

/* dnsmasq.c */
int icmp_ping(struct daemon *daemon, struct in_addr addr);

/* isc.c */
#ifdef HAVE_ISC_READER
void load_dhcp(struct daemon *daemon, time_t now);
#endif

