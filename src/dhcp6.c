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

static int join_multicast(struct in6_addr *local, int prefix, 
			  int scope, int if_index, void *vparam);

static int complete_context6(struct in6_addr *local,  int prefix,
			     int scope, int if_index, void *vparam);

void dhcp6_init(void)
{
  int fd;
  struct sockaddr_in6 saddr;
  int class = IPTOS_CLASS_CS6;
  
  if ((fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1 ||
      setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &class, sizeof(class)) == -1 ||
      !fix_fd(fd) ||
      !set_ipv6pktinfo(fd))
    die (_("cannot create DHCPv6 socket: %s"), NULL, EC_BADNET);
  
  memset(&saddr, 0, sizeof(saddr));
#ifdef HAVE_SOCKADDR_SA_LEN
  saddr.sin6_len = sizeof(addr.in6);
#endif
  saddr.sin6_family = AF_INET6;
  saddr.sin6_addr = in6addr_any;
  saddr.sin6_port = htons(DHCPV6_SERVER_PORT);
  
  if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in6)))
    die(_("failed to bind DHCPv6 server socket: %s"), NULL, EC_BADNET);
  
  /* join multicast groups on each interface we're interested in */
  if (!iface_enumerate(AF_INET6, &fd, join_multicast))
     die(_("failed to join DHCPv6 multicast group: %s"), NULL, EC_BADNET);
  
  daemon->dhcp6fd = fd;
  
}

static int join_multicast(struct in6_addr *local, int prefix, 
			  int scope, int if_index, void *vparam)
{
  char ifrn_name[IFNAMSIZ];
  struct ipv6_mreq mreq;
  struct in6_addr maddr;
  int fd = *((int *)vparam);
  struct dhcp_context *context;
  struct iname *tmp;

  (void)prefix;
  (void)scope; /* warnings */

  if (!indextoname(fd, if_index, ifrn_name))
    return 0;
  
  /* Are we doing DHCP on this interface? */
  if (!iface_check(AF_INET6, (struct all_addr *)local, ifrn_name))
    return 1;
 
  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
    if (tmp->name && (strcmp(tmp->name, ifrn_name) == 0))
      return 1;

  /* weird libvirt-inspired access control */
  for (context = daemon->dhcp; context; context = context->next)
    if (!context->interface || strcmp(context->interface, ifrn_name) == 0)
      break;

  if (!context)
    return 1;

  mreq.ipv6mr_interface = if_index;
  inet_pton(AF_INET6, ALL_RELAY_AGENTS_AND_SERVERS, &maddr);
  
  if (!setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
    return 0;

  inet_pton(AF_INET6, ALL_SERVERS, &maddr);
  
  if (!setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
    return 0;
  
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
  
  if ((sz = recv_dhcp_packet(daemon->dhcp6fd, &msg) == -1) || sz <= 4)
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
ls -l    
  if (!iface_check(AF_INET6, (struct all_addr *)&dest, ifr.ifr_name))
    return;
  
  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
    if (tmp->name && (strcmp(tmp->name, ifr.ifr_name) == 0))
      return;
 
  /* weird libvirt-inspired access control */
  for (context = daemon->dhcp; context; context = context->next)
    if (!context->interface || strcmp(context->interface, ifr.ifr_name) == 0)
      break;
  
  if (!context)
    return;
  
  /* unlinked contexts are marked by context->current == context */
  for (context = daemon->dhcp; context; context = context->next)
    context->current = context;
  
  parm.current = NULL;
  parm.ind = if_index;
  
  if (!iface_enumerate(AF_INET6, &parm, complete_context6))
    return;
  
  lease_prune(NULL, now); /* lose any expired leases */

  msg.msg_iov =  &daemon->dhcp_packet;
  sz = dhcp6_reply(parm.current, sz);
  /* ifr.ifr_name, if_index, (size_t)sz, 
     now, unicast_dest, &is_inform, pxe_fd, iface_addr); */
  lease_update_file(now);
  lease_update_dns();
  
  if (sz != 0)
    send_from(daemon->dhcp6fd, 0, daemon->outpacket.iov_base, sz, &from, &dest, if_index);
}

static int complete_context6(struct in6_addr *local,  int prefix,
			     int scope, int if_index, void *vparam)
{
  struct dhcp_context *context;
  struct iface_param *param = vparam;
  
  for (context = daemon->dhcp6; context; context = context->next)
    {
      if ((context->flags & CONTEXT_IPV6) &&
	  prefix == context->prefix &&
	  is_same_net6(local, &context->start6, prefix) &&
          is_same_net6(local, &context->end6, prefix))
        {
          /* link it onto the current chain if we've not seen it before */
          if (if_index == param->ind && context->current == context)
            {
              context->current = param->current;
              param->current = context;
            }
	}
    }          
  return 1;
}
#endif


