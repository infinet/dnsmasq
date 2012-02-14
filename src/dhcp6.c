/* dnsmasq is Copyright (c) 2000-2012 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
     
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dnsmasq.h"

#ifdef HAVE_DHCP6

struct iface_param {
  struct dhcp_context *current;
  int ind;
};

struct listen_param {
  int fd_or_iface;
  struct listen_param *next;
};

static int join_multicast(struct in6_addr *local, int prefix, 
			  int scope, int if_index, int dad, void *vparam);

static int complete_context6(struct in6_addr *local,  int prefix,
			     int scope, int if_index, int dad, void *vparam);

static int make_duid1(unsigned int type, char *mac, size_t maclen, void *parm); 

void dhcp6_init(void)
{
  int fd;
  struct sockaddr_in6 saddr;
  struct listen_param *listenp, listen; 
#if defined(IP_TOS) && defined(IPTOS_CLASS_CS6)
  int class = IPTOS_CLASS_CS6;
#endif
  
  if ((fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1 ||
#if defined(IP_TOS) && defined(IPTOS_CLASS_CS6)
      setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &class, sizeof(class)) == -1 ||
#endif
      !fix_fd(fd) ||
      !set_ipv6pktinfo(fd))
    die (_("cannot create DHCPv6 socket: %s"), NULL, EC_BADNET);
  
  memset(&saddr, 0, sizeof(saddr));
#ifdef HAVE_SOCKADDR_SA_LEN
  saddr.sin6_len = sizeof(struct sockaddr_in6);
#endif
  saddr.sin6_family = AF_INET6;
  saddr.sin6_addr = in6addr_any;
  saddr.sin6_port = htons(DHCPV6_SERVER_PORT);
  
  if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in6)))
    die(_("failed to bind DHCPv6 server socket: %s"), NULL, EC_BADNET);
  
  /* join multicast groups on each interface we're interested in */
  listen.fd_or_iface = fd;
  listen.next = NULL;
  if (!iface_enumerate(AF_INET6, &listen, join_multicast))
     die(_("failed to join DHCPv6 multicast group: %s"), NULL, EC_BADNET);
  for (listenp = listen.next; listenp; )
    {
      struct listen_param *tmp = listenp->next;
      free(listenp);
      listenp = tmp;
    }
  
  daemon->dhcp6fd = fd;
}

static int join_multicast(struct in6_addr *local, int prefix, 
			  int scope, int if_index, int dad, void *vparam)
{
  char ifrn_name[IFNAMSIZ];
  struct ipv6_mreq mreq;
  struct listen_param *listenp, *param = vparam;
  int fd = param->fd_or_iface;
  struct dhcp_context *context;
  struct iname *tmp;

  (void)prefix;
  (void)scope;
  (void)dad;
  
  /* record which interfaces we join on, so
     that we do it at most one per interface, even when they
     have multiple addresses */
  for (listenp = param->next; listenp; listenp = listenp->next)
    if (if_index == listenp->fd_or_iface)
      return 1;
  
  if (!indextoname(fd, if_index, ifrn_name))
    return 0;

  /* Are we doing DHCP on this interface? */
  if (!iface_check(AF_INET6, (struct all_addr *)local, ifrn_name))
    return 1;
 
  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
    if (tmp->name && (strcmp(tmp->name, ifrn_name) == 0))
      return 1;

  /* weird libvirt-inspired access control */
  for (context = daemon->dhcp6; context; context = context->next)
    if (!context->interface || strcmp(context->interface, ifrn_name) == 0)
      break;

  if (!context)
    return 1;

  mreq.ipv6mr_interface = if_index;
  inet_pton(AF_INET6, ALL_RELAY_AGENTS_AND_SERVERS, &mreq.ipv6mr_multiaddr);
  
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
    return 0;

  inet_pton(AF_INET6, ALL_SERVERS, &mreq.ipv6mr_multiaddr);
  
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
    return 0;
  
  listenp = whine_malloc(sizeof(struct listen_param));
  listenp->fd_or_iface = if_index;
  listenp->next = param->next;
  param->next = listenp;
  
  return 1;
}


void dhcp6_packet(time_t now)
{
  struct dhcp_context *context;
  struct iface_param parm;
  struct cmsghdr *cmptr;
  struct msghdr msg;
  int if_index = 0;
  union {
    struct cmsghdr align; /* this ensures alignment */
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_u;
  union mysockaddr from;
  struct all_addr dest;
  ssize_t sz; 
  struct ifreq ifr;
  struct iname *tmp;

  msg.msg_control = control_u.control6;
  msg.msg_controllen = sizeof(control_u);
  msg.msg_flags = 0;
  msg.msg_name = &from;
  msg.msg_namelen = sizeof(from);
  msg.msg_iov =  &daemon->dhcp_packet;
  msg.msg_iovlen = 1;
  
  if ((sz = recv_dhcp_packet(daemon->dhcp6fd, &msg)) == -1 || sz <= 4)
    return;
  
  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
    if (cmptr->cmsg_level == IPPROTO_IPV6 && cmptr->cmsg_type == daemon->v6pktinfo)
      {
	union {
	  unsigned char *c;
	  struct in6_pktinfo *p;
	} p;
	p.c = CMSG_DATA(cmptr);
        
	if_index = p.p->ipi6_ifindex;
	dest.addr.addr6 = p.p->ipi6_addr;
      }

  if (!indextoname(daemon->dhcp6fd, if_index, ifr.ifr_name))
    return;
    
  if (!iface_check(AF_INET6, (struct all_addr *)&dest, ifr.ifr_name))
    return;
  
  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
    if (tmp->name && (strcmp(tmp->name, ifr.ifr_name) == 0))
      return;
 
  /* weird libvirt-inspired access control */
  for (context = daemon->dhcp6; context; context = context->next)
    if (!context->interface || strcmp(context->interface, ifr.ifr_name) == 0)
      break;
  
  if (!context)
    return;

  /* unlinked contexts are marked by context->current == context */
  for (context = daemon->dhcp6; context; context = context->next)
    context->current = context;
  
  parm.current = NULL;
  parm.ind = if_index;
  
  if (!iface_enumerate(AF_INET6, &parm, complete_context6))
    return;
  
  lease_prune(NULL, now); /* lose any expired leases */

  msg.msg_iov =  &daemon->dhcp_packet;
  sz = dhcp6_reply(parm.current, if_index, ifr.ifr_name, sz, IN6_IS_ADDR_MULTICAST(&from.in6.sin6_addr), now);
  
  lease_update_file(now);
  lease_update_dns();
  
  if (sz != 0)
    while (sendto(daemon->dhcp6fd, daemon->outpacket.iov_base, sz, 0, (struct sockaddr *)&from, sizeof(from)) &&
	   retry_send());
}

static int complete_context6(struct in6_addr *local,  int prefix,
			     int scope, int if_index, int dad, void *vparam)
{
  struct dhcp_context *context;
  struct iface_param *param = vparam;

  (void)scope; /* warning */
  (void)dad;

  for (context = daemon->dhcp6; context; context = context->next)
    {
      if (prefix == context->prefix &&
	  !IN6_IS_ADDR_LOOPBACK(local) &&
	  !IN6_IS_ADDR_LINKLOCAL(local) &&
	  !IN6_IS_ADDR_MULTICAST(local) &&
	  is_same_net6(local, &context->start6, prefix) &&
          is_same_net6(local, &context->end6, prefix))
        {
          /* link it onto the current chain if we've not seen it before */
          if (if_index == param->ind && context->current == context)
            {
              context->current = param->current;
              param->current = context;
	      context->local6 = *local;
            }
	}
    }          
  return 1;
}

struct dhcp_config *config_find_by_address6(struct dhcp_config *configs, struct in6_addr *net, int prefix, u64 addr)
{
  struct dhcp_config *config;
  
  for (config = configs; config; config = config->next)
    if ((config->flags & CONFIG_ADDR6) &&
	is_same_net6(&config->addr6, net, prefix) &&
	(prefix == 128 || addr6part(&config->addr6) == addr))
      return config;
  
  return NULL;
}

int address6_allocate(struct dhcp_context *context,  unsigned char *clid, int clid_len, 
		      int serial, struct dhcp_netid *netids, struct in6_addr *ans)   
{
  /* Find a free address: exclude anything in use and anything allocated to
     a particular hwaddr/clientid/hostname in our configuration.
     Try to return from contexts which match netids first. 
     
     Note that we assume the address prefix lengths are 64 or greater, so we can
     get by with 64 bit arithmetic.
*/

  u64 start, addr;
  struct dhcp_context *c, *d;
  int i, pass;
  u64 j; 

  /* hash hwaddr: use the SDBM hashing algorithm.  This works
     for MAC addresses, let's see how it manages with client-ids! */
  for (j = 0, i = 0; i < clid_len; i++)
    j += clid[i] + (j << 6) + (j << 16) - j;
  
  for (pass = 0; pass <= 1; pass++)
    for (c = context; c; c = c->current)
      if (c->flags & (CONTEXT_STATIC | CONTEXT_PROXY))
	continue;
      else if (!match_netid(c->filter, netids, pass))
	continue;
      else
	{ 
	  if (option_bool(OPT_CONSEC_ADDR))
	    /* seed is largest extant lease addr in this context */
	    start = lease_find_max_addr6(c) + serial;
	  else
	    start = addr6part(&c->start6) + ((j + c->addr_epoch + serial) % (1 + addr6part(&c->end6) - addr6part(&c->start6)));

	  /* iterate until we find a free address. */
	  addr = start;
	  
	  do {
	    /* eliminate addresses in use by the server. */
	    for (d = context; d; d = d->current)
	      if (addr == addr6part(&d->router6))
		break;

	    if (!d &&
		!lease6_find_by_addr(&c->start6, c->prefix, addr) && 
		!config_find_by_address6(daemon->dhcp_conf, &c->start6, c->prefix, addr))
	      {
		*ans = c->start6;
		setaddr6part (ans, addr);
		return 1;
	      }
	
	    addr++;
	    
	    if (addr  == addr6part(&c->end6) + 1)
	      addr = addr6part(&c->start6);
	    
	  } while (addr != start);
	}
  
  return 0;
}

struct dhcp_context *address6_available(struct dhcp_context *context, 
					struct in6_addr *taddr,
					struct dhcp_netid *netids)
{
  u64 start, end, addr = addr6part(taddr);
  struct dhcp_context *tmp;
 
  for (tmp = context; tmp; tmp = tmp->current)
    {
      start = addr6part(&tmp->start6);
      end = addr6part(&tmp->end6);

      if (!(tmp->flags & (CONTEXT_STATIC | CONTEXT_PROXY)) &&
          is_same_net6(&context->start6, taddr, context->prefix) &&
	  is_same_net6(&context->end6, taddr, context->prefix) &&
	  addr >= start &&
          addr <= end &&
          match_netid(tmp->filter, netids, 1))
        return tmp;
    }

  return NULL;
}

struct dhcp_context *narrow_context6(struct dhcp_context *context, 
				     struct in6_addr *taddr,
				     struct dhcp_netid *netids)
{
  /* We start of with a set of possible contexts, all on the current physical interface.
     These are chained on ->current.
     Here we have an address, and return the actual context correponding to that
     address. Note that none may fit, if the address came a dhcp-host and is outside
     any dhcp-range. In that case we return a static range if possible, or failing that,
     any context on the correct subnet. (If there's more than one, this is a dodgy 
     configuration: maybe there should be a warning.) */
  
  struct dhcp_context *tmp;

  if (!(tmp = address6_available(context, taddr, netids)))
    {
      for (tmp = context; tmp; tmp = tmp->current)
        if (match_netid(tmp->filter, netids, 1) &&
            is_same_net6(taddr, &tmp->start6, tmp->prefix) && 
            (tmp->flags & CONTEXT_STATIC))
          break;
      
      if (!tmp)
        for (tmp = context; tmp; tmp = tmp->current)
          if (match_netid(tmp->filter, netids, 1) &&
              is_same_net6(taddr, &tmp->start6, tmp->prefix) &&
              !(tmp->flags & CONTEXT_PROXY))
            break;
    }
  
  /* Only one context allowed now */
  if (tmp)
    tmp->current = NULL;
  
  return tmp;
}

static int is_addr_in_context6(struct dhcp_context *context, struct dhcp_config *config)
{
  if (!context) /* called via find_config() from lease_update_from_configs() */
    return 1; 
  if (!(config->flags & CONFIG_ADDR6))
    return 1;
  for (; context; context = context->current)
    if (is_same_net6(&config->addr6, &context->start6, context->prefix))
      return 1;
  
  return 0;
}


struct dhcp_config *find_config6(struct dhcp_config *configs,
				 struct dhcp_context *context,
				 unsigned char *duid, int duid_len,
				 char *hostname)
{
  int count, new;
  struct dhcp_config *config; 
  struct hwaddr_config *conf_addr;
  unsigned char *hwaddr = NULL; 
  int duid_type, hw_len = 0, hw_type = 0;
  
  if (duid)
    {  
      for (config = configs; config; config = config->next)
	if (config->flags & CONFIG_CLID)
	  {
	    if (config->clid_len == duid_len && 
		memcmp(config->clid, duid, duid_len) == 0 &&
		is_addr_in_context6(context, config))
	      return config;
	  }
      
      /* DHCPv6 doesn't deal in MAC addresses per-se, but some DUIDs do include
	 MAC addresses, so we try and parse them out here. Not that there is only one
	 DUID per host and it's created using any one of the MACs, so this is no
	 good no good for multihomed hosts. */
      hwaddr = duid;
      GETSHORT(duid_type, hwaddr);
      if (duid_type == 1 || duid_type == 3)
	{
	  GETSHORT(hw_type, hwaddr);
	  if (duid_type == 1)
	    hwaddr += 4; /* skip time */
	  hw_len = duid_len - 8;
	}

      if (hwaddr)
	for (config = configs; config; config = config->next)
	  if (config_has_mac(config, hwaddr, hw_len, hw_type) &&
	      is_addr_in_context6(context, config))
	    return config;
    }
  
  if (hostname && context)
    for (config = configs; config; config = config->next)
      if ((config->flags & CONFIG_NAME) && 
          hostname_isequal(config->hostname, hostname) &&
          is_addr_in_context6(context, config))
        return config;

  /* use match with fewest wildcard octets */
  if (hwaddr)
    {
       struct dhcp_config *candidate; 
       
       for (candidate = NULL, count = 0, config = configs; config; config = config->next)
	if (is_addr_in_context6(context, config))
	  for (conf_addr = config->hwaddr; conf_addr; conf_addr = conf_addr->next)
	    if (conf_addr->wildcard_mask != 0 &&
		conf_addr->hwaddr_len == hw_len &&  
		(conf_addr->hwaddr_type == hw_type || conf_addr->hwaddr_type == 0) &&
		(new = memcmp_masked(conf_addr->hwaddr, hwaddr, hw_len, conf_addr->wildcard_mask)) > count)
	      {
		count = new;
		candidate = config;
	      }
      
      return candidate;
    }
  
  return NULL;
}

void make_duid(time_t now)
{
  /* rebase epoch to 1/1/2000 */
  time_t newnow = now - 946684800;
  
  iface_enumerate(AF_LOCAL, &newnow, make_duid1);
  
  if(!daemon->duid)
    die("Cannot create DHCPv6 server DUID: %s", NULL, EC_MISC);
}

static int make_duid1(unsigned int type, char *mac, size_t maclen, void *parm)
{
  /* create DUID as specified in RFC3315. We use the MAC of the
     first interface we find that isn't loopback or P-to-P */
  
  unsigned char *p;

  daemon->duid = p = safe_malloc(maclen + 8);
  daemon->duid_len = maclen + 8;
  
#ifdef HAVE_BROKEN_RTC
  PUTSHORT(3, p); /* DUID_LL */
#else
  PUTSHORT(1, p); /* DUID_LLT */
#endif

  PUTSHORT(type, p); /* address type */

#ifndef HAVE_BROKEN_RTC
  PUTLONG(*((time_t *)parm), p); /* time */
#endif

  memcpy(p, mac, maclen);

  return 0;
}
#endif


