/* dnsmasq is Copyright (c) 2000 - 2003 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* Author's email: simon@thekelleys.org.uk */

#include "dnsmasq.h"

static struct frec *frec_list;

static struct frec *get_new_frec(time_t now);
static struct frec *lookup_frec(unsigned short id);
static struct frec *lookup_frec_by_sender(unsigned short id,
					  union mysockaddr *addr);
static unsigned short get_id(void);

/* May be called more than once. */
void forward_init(int first)
{
  struct frec *f;
  
  if (first)
    frec_list = NULL;
  for (f = frec_list; f; f = f->next)
    f->new_id = 0;
}

/* Send a UDP packet with it's source address set as "source" 
   unless nowild is true, when we just send it with the kernel default */
static void send_from(int fd, int nowild, char *packet, int len, 
		      union mysockaddr *to, struct all_addr *source,
		      unsigned int iface)
{
  struct msghdr msg;
  struct iovec iov[1]; 
  union {
    struct cmsghdr align; /* this ensures alignment */
#if defined(IP_PKTINFO)
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#elif defined(IP_SENDSRCADDR)
    char control[CMSG_SPACE(sizeof(struct in_addr))];
#endif
#ifdef HAVE_IPV6
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif
  } control_u;
  
  iov[0].iov_base = packet;
  iov[0].iov_len = len;

  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  msg.msg_name = to;
  msg.msg_namelen = sa_len(to);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  
  if (!nowild && to->sa.sa_family == AF_INET)
    {
      msg.msg_control = &control_u;
      msg.msg_controllen = sizeof(control_u);
      {
	struct cmsghdr *cmptr = CMSG_FIRSTHDR(&msg);
#if defined(IP_PKTINFO)
	struct in_pktinfo *pkt = (struct in_pktinfo *)CMSG_DATA(cmptr);
	pkt->ipi_ifindex = 0;
	pkt->ipi_spec_dst = source->addr.addr4;
	msg.msg_controllen = cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	cmptr->cmsg_level = SOL_IP;
	cmptr->cmsg_type = IP_PKTINFO;
#elif defined(IP_SENDSRCADDR)
	struct in_addr *a = (struct in_addr *)CMSG_DATA(cmptr);
	*a = source->addr.addr4;
	msg.msg_controllen = cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
	cmptr->cmsg_level = IPPROTO_IP;
	cmptr->cmsg_type = IP_SENDSRCADDR;
#endif
      }
    }

#ifdef HAVE_IPV6
  if (to->sa.sa_family == AF_INET6)
    {
      msg.msg_control = &control_u;
      msg.msg_controllen = sizeof(control_u);
      {
	struct cmsghdr *cmptr = CMSG_FIRSTHDR(&msg);
	struct in6_pktinfo *pkt = (struct in6_pktinfo *)CMSG_DATA(cmptr);
	pkt->ipi6_ifindex = iface; /* Need iface for IPv6 to handle link-local addrs */
	pkt->ipi6_addr = source->addr.addr6;
	msg.msg_controllen = cmptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmptr->cmsg_type = IPV6_PKTINFO;
	cmptr->cmsg_level = IPV6_LEVEL;
      }
    }
#endif
  
  /* certain Linux kernels seem to object to setting the source address in the IPv6 stack
     by returning EINVAL from sendmsg. In that case, try again without setting the
     source address, since it will nearly alway be correct anyway.  IPv6 stinks. */
  if (sendmsg(fd, &msg, 0) == -1 && errno == EINVAL)
    {
      msg.msg_controllen = 0;
      sendmsg(fd, &msg, 0);
    }
}
          
unsigned short search_servers(struct daemon *daemon, struct all_addr **addrpp,
			      unsigned short qtype, char *qdomain, int *type, char **domain)
			      
{
  /* If the query ends in the domain in one of our servers, set
     domain to point to that name. We find the largest match to allow both
     domain.org and sub.domain.org to exist. */
  
  unsigned int namelen = strlen(qdomain);
  unsigned int matchlen = 0;
  struct server *serv;
  unsigned short flags = 0;
  
  for (serv = daemon->servers; serv; serv=serv->next)
    /* domain matches take priority over NODOTS matches */
    if ((serv->flags & SERV_FOR_NODOTS) && *type != SERV_HAS_DOMAIN && !strchr(qdomain, '.'))
      {
	unsigned short sflag = serv->addr.sa.sa_family == AF_INET ? F_IPV4 : F_IPV6; 
	*type = SERV_FOR_NODOTS;
	flags = 0;
	if (serv->flags & SERV_NO_ADDR)
	  flags = F_NXDOMAIN; 
	else if ((serv->flags & SERV_LITERAL_ADDRESS) && (sflag & qtype))
	  {
	    flags = sflag;
	    if (serv->addr.sa.sa_family == AF_INET) 
	      *addrpp = (struct all_addr *)&serv->addr.in.sin_addr;
#ifdef HAVE_IPV6
	    else
	      *addrpp = (struct all_addr *)&serv->addr.in6.sin6_addr;
#endif 
	  }
      }
    else if (serv->flags & SERV_HAS_DOMAIN)
      {
	unsigned int domainlen = strlen(serv->domain);
	if (namelen >= domainlen &&
	    hostname_isequal(qdomain + namelen - domainlen, serv->domain) &&
	    domainlen >= matchlen)
	  {
	    unsigned short sflag = serv->addr.sa.sa_family == AF_INET ? F_IPV4 : F_IPV6;
	    *type = SERV_HAS_DOMAIN;
	    *domain = serv->domain;
	    matchlen = domainlen;
	    flags = 0;
	    if (serv->flags & SERV_NO_ADDR)
	      flags = F_NXDOMAIN; 
	    else if ((serv->flags & SERV_LITERAL_ADDRESS) && ((sflag | F_QUERY ) & qtype))
	      {
		flags = qtype;
		if (serv->addr.sa.sa_family == AF_INET) 
		  *addrpp = (struct all_addr *)&serv->addr.in.sin_addr;
#ifdef HAVE_IPV6
		else
		  *addrpp = (struct all_addr *)&serv->addr.in6.sin6_addr;
#endif
	      }
	  } 
      }

  if (flags & ~F_NXDOMAIN) /* flags set here means a literal found */
    {
      if (flags & F_QUERY)
	log_query(F_CONFIG | F_FORWARD | F_NEG, qdomain, NULL, 0);
      else
	log_query(F_CONFIG | F_FORWARD | flags, qdomain, *addrpp, 0);
    }
  else if (qtype && (daemon->options & OPT_NODOTS_LOCAL) && !strchr(qdomain, '.'))
    flags = F_NOERR;

  if (flags & (F_NOERR | F_NXDOMAIN))
    log_query(F_CONFIG | F_FORWARD | F_NEG | qtype | (flags & F_NXDOMAIN), qdomain, NULL, 0);

  return  flags;
}

/* returns new last_server */	
static void forward_query(struct daemon *daemon, int udpfd, union mysockaddr *udpaddr,
			  struct all_addr *dst_addr, unsigned int dst_iface,
			  HEADER *header, int plen, time_t now)
{
  struct frec *forward;
  char *domain = NULL;
  int forwardall = 0, type = 0;
  struct all_addr *addrp = NULL;
  unsigned short flags = 0;
  unsigned short gotname = extract_request(header, (unsigned int)plen, daemon->namebuff, NULL);
  struct server *start = NULL;
  
  /* may be  recursion not speced or no servers available. */
  if (!header->rd || !daemon->servers)
    forward = NULL;
  else if ((forward = lookup_frec_by_sender(ntohs(header->id), udpaddr)))
    {
      /* retry on existing query, send to all available servers  */
      domain = forward->sentto->domain;
      if (!(daemon->options & OPT_ORDER))
	{
	  forwardall = 1;
	  daemon->last_server = NULL;
	}
      type = forward->sentto->flags & SERV_TYPE;
      if (!(start = forward->sentto->next))
	start = daemon->servers; /* at end of list, recycle */
      header->id = htons(forward->new_id);
    }
  else 
    {
      if (gotname)
	flags = search_servers(daemon, &addrp, gotname, daemon->namebuff, &type, &domain);
      
      if (!flags && !(forward = get_new_frec(now)))
	/* table full - server failure. */
	flags = F_NEG;
      
      if (forward)
	{
	  /* In strict_order mode, or when using domain specific servers
	     always try servers in the order specified in resolv.conf,
	     otherwise, use the one last known to work. */
	  
	  if (type != 0  || (daemon->options & OPT_ORDER))
	    start = daemon->servers;
	  else if (!(start = daemon->last_server))
	    {
	      start = daemon->servers;
	      forwardall = 1;
	    }
	  
	  forward->source = *udpaddr;
	  forward->dest = *dst_addr;
	  forward->iface = dst_iface;
	  forward->new_id = get_id();
	  forward->fd = udpfd;
	  forward->orig_id = ntohs(header->id);
	  header->id = htons(forward->new_id);
	}
    }

  /* check for send errors here (no route to host) 
     if we fail to send to all nameservers, send back an error
     packet straight away (helps modem users when offline)  */
  
  if (!flags && forward)
    {
      struct server *firstsentto = start;
      int forwarded = 0;

      while (1)
	{ 
	  /* only send to servers dealing with our domain.
	     domain may be NULL, in which case server->domain 
	     must be NULL also. */
	  
	  if (type == (start->flags & SERV_TYPE) &&
	      (type != SERV_HAS_DOMAIN || hostname_isequal(domain, start->domain)))
	    {
	      if (!(start->flags & SERV_LITERAL_ADDRESS) &&
		  sendto(start->sfd->fd, (char *)header, plen, 0,
			 &start->addr.sa,
			 sa_len(&start->addr)) != -1)
		{
		  if (!gotname)
		    strcpy(daemon->namebuff, "query");
		  if (start->addr.sa.sa_family == AF_INET)
		    log_query(F_SERVER | F_IPV4 | F_FORWARD, daemon->namebuff, 
			      (struct all_addr *)&start->addr.in.sin_addr, 0); 
#ifdef HAVE_IPV6
		  else
		    log_query(F_SERVER | F_IPV6 | F_FORWARD, daemon->namebuff, 
			      (struct all_addr *)&start->addr.in6.sin6_addr, 0);
#endif 
		  forwarded = 1;
		  forward->sentto = start;
		  if (!forwardall) 
		    break;
		}
	    } 
	  
	  if (!(start = start->next))
 	    start = daemon->servers;
	  
	  if (start == firstsentto)
	    break;
	}
      
      if (forwarded)
	  return;
      
      /* could not send on, prepare to return */ 
      header->id = htons(forward->orig_id);
      forward->new_id = 0; /* cancel */
    }	  
  
  /* could not send on, return empty answer or address if known for whole domain */
  plen = setup_reply(header, (unsigned int)plen, addrp, flags, daemon->local_ttl);
  send_from(udpfd, daemon->options & OPT_NOWILD, (char *)header, plen, udpaddr, dst_addr, dst_iface);
  
  return;
}

static int process_reply(struct daemon *daemon, HEADER *header, time_t now, 
			 union mysockaddr *serveraddr, int n)
{
  unsigned char *pheader;
   
  /* If upstream is advertising a larger UDP packet size
	 than we allow, trim it so that we don't get overlarge
	 requests for the client. */

  if ((pheader = find_pseudoheader(header, n)))
    {
      unsigned short udpsz;
      unsigned char *psave = pheader;
      
      GETSHORT(udpsz, pheader);
      if (udpsz > daemon->edns_pktsz)
	PUTSHORT(daemon->edns_pktsz, psave);
    }

  /* Complain loudly if the upstream server is non-recursive. */
  if (!header->ra && header->rcode == NOERROR && ntohs(header->ancount) == 0)
    {
      char addrbuff[ADDRSTRLEN];
#ifdef HAVE_IPV6
      if (serveraddr->sa.sa_family == AF_INET)
	inet_ntop(AF_INET, &serveraddr->in.sin_addr, addrbuff, ADDRSTRLEN);
      else if (serveraddr->sa.sa_family == AF_INET6)
	inet_ntop(AF_INET6, &serveraddr->in6.sin6_addr, addrbuff, ADDRSTRLEN);
#else
      strcpy(addrbuff, inet_ntoa(serveraddr->in.sin_addr));
#endif
      syslog(LOG_WARNING, "nameserver %s refused to do a recursive query", addrbuff);
      return 0;
    }
  
  if ((header->rcode == NOERROR || header->rcode == NXDOMAIN) && header->opcode == QUERY)
    {
      if (!(daemon->bogus_addr && 
	    header->rcode == NOERROR && 
	    check_for_bogus_wildcard(header, (unsigned int)n, daemon->namebuff, daemon->bogus_addr, now)))
	{
	  if (header->rcode == NOERROR && ntohs(header->ancount) != 0)
	    extract_addresses(header, (unsigned int)n, daemon->namebuff, now, daemon->doctors);
	  else if (!(daemon->options & OPT_NO_NEG))
	    extract_neg_addrs(header, (unsigned int)n, daemon->namebuff, now);
	}
    }
  
  return 1;
}

/* sets new last_server */
void reply_query(struct serverfd *sfd, struct daemon *daemon, time_t now)
{
  /* packet from peer server, extract data for cache, and send to
     original requester */
  struct frec *forward;
  HEADER *header;
  union mysockaddr serveraddr;
  socklen_t addrlen = sizeof(serveraddr);
  int n = recvfrom(sfd->fd, daemon->packet, daemon->edns_pktsz, 0, &serveraddr.sa, &addrlen);
  
  /* Determine the address of the server replying  so that we can mark that as good */
  serveraddr.sa.sa_family = sfd->source_addr.sa.sa_family;
#ifdef HAVE_IPV6
  if (serveraddr.sa.sa_family == AF_INET6)
    serveraddr.in6.sin6_flowinfo = htonl(0);
#endif
  
  header = (HEADER *)daemon->packet;
  if (n >= (int)sizeof(HEADER) && header->qr && (forward = lookup_frec(ntohs(header->id))))
    {
      /* find good server by address if possible, otherwise assume the last one we sent to */ 
      if ((forward->sentto->flags & SERV_TYPE) == 0)
	{
	  struct server *last_server;
	  daemon->last_server = forward->sentto;
	  for (last_server = daemon->servers; last_server; last_server = last_server->next)
	    if (!(last_server->flags & (SERV_LITERAL_ADDRESS | SERV_HAS_DOMAIN | SERV_FOR_NODOTS | SERV_NO_ADDR)) &&
		sockaddr_isequal(&last_server->addr, &serveraddr))
	      {
		daemon->last_server = last_server;
		break;
	      }
	}
      
      if (process_reply(daemon, header, now, &serveraddr, n))
	{
	  header->id = htons(forward->orig_id);
	  send_from(forward->fd, daemon->options & OPT_NOWILD, daemon->packet, n, 
		    &forward->source, &forward->dest, forward->iface);
	  forward->new_id = 0; /* cancel */
	}
    }
}

void receive_query(struct listener *listen, struct daemon *daemon, time_t now)
{
  HEADER *header = (HEADER *)daemon->packet;
  union mysockaddr source_addr;
  unsigned short type;
  struct iname *tmp;
  struct all_addr dst_addr;
  int check_dst = !(daemon->options & OPT_NOWILD);
  int m, n, if_index = 0;
  struct iovec iov[1];
  struct msghdr msg;
  struct cmsghdr *cmptr;
  union {
    struct cmsghdr align; /* this ensures alignment */
#ifdef HAVE_IPV6
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif
#if defined(IP_PKTINFO)
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#elif defined(IP_RECVDSTADDR)
    char control[CMSG_SPACE(sizeof(struct in_addr)) +
		 CMSG_SPACE(sizeof(struct sockaddr_dl))];
#endif
  } control_u;
  
  iov[0].iov_base = daemon->packet;
  iov[0].iov_len = daemon->edns_pktsz;
    
  msg.msg_control = control_u.control;
  msg.msg_controllen = sizeof(control_u);
  msg.msg_flags = 0;
  msg.msg_name = &source_addr;
  msg.msg_namelen = sizeof(source_addr);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  
  if ((n = recvmsg(listen->fd, &msg, 0)) == -1)
    return;
  
  source_addr.sa.sa_family = listen->family;
#ifdef HAVE_IPV6
  if (listen->family == AF_INET6)
    {
      check_dst = 1;
      source_addr.in6.sin6_flowinfo = htonl(0);
    }
#endif
  
  if (check_dst && msg.msg_controllen < sizeof(struct cmsghdr))
    return;

#if defined(IP_PKTINFO)
  if (check_dst && listen->family == AF_INET)
    for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
      if (cmptr->cmsg_level == SOL_IP && cmptr->cmsg_type == IP_PKTINFO)
	{
	  dst_addr.addr.addr4 = ((struct in_pktinfo *)CMSG_DATA(cmptr))->ipi_spec_dst;
	  if_index = ((struct in_pktinfo *)CMSG_DATA(cmptr))->ipi_ifindex;
	}
#elif defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
  if (check_dst && listen->family == AF_INET)
    {
      for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVDSTADDR)
	  dst_addr.addr.addr4 = *((struct in_addr *)CMSG_DATA(cmptr));
	else if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
	  if_index = ((struct sockaddr_dl *)CMSG_DATA(cmptr))->sdl_index;
    }
#endif

#ifdef HAVE_IPV6
  if (listen->family == AF_INET6)
    {
      for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	if (cmptr->cmsg_level == IPV6_LEVEL && cmptr->cmsg_type == IPV6_PKTINFO)
	  {
	    dst_addr.addr.addr6 = ((struct in6_pktinfo *)CMSG_DATA(cmptr))->ipi6_addr;
	    if_index =((struct in6_pktinfo *)CMSG_DATA(cmptr))->ipi6_ifindex;
	  }
    }
#endif
  
  if (n < (int)sizeof(HEADER) || header->qr)
    return;
  
  /* enforce available interface configuration */
  if (check_dst)
    {
      struct ifreq ifr;

      if (if_index == 0)
	return;
      
      if (daemon->if_except || daemon->if_names)
	{
#ifdef SIOCGIFNAME
	  ifr.ifr_ifindex = if_index;
	  if (ioctl(listen->fd, SIOCGIFNAME, &ifr) == -1)
	    return;
#else
	  if (!if_indextoname(if_index, ifr.ifr_name))
	    return;
#endif
	}

      for (tmp = daemon->if_except; tmp; tmp = tmp->next)
	if (tmp->name && (strcmp(tmp->name, ifr.ifr_name) == 0))
	  return;
      
      if (daemon->if_names || daemon->if_addrs)
	{
	  for (tmp = daemon->if_names; tmp; tmp = tmp->next)
	    if (tmp->name && (strcmp(tmp->name, ifr.ifr_name) == 0))
	      break;
	  if (!tmp)
	    for (tmp = daemon->if_addrs; tmp; tmp = tmp->next)
	      if (tmp->addr.sa.sa_family == listen->family)
		{
		  if (tmp->addr.sa.sa_family == AF_INET &&
		      tmp->addr.in.sin_addr.s_addr == dst_addr.addr.addr4.s_addr)
		    break;
#ifdef HAVE_IPV6
		  else if (tmp->addr.sa.sa_family == AF_INET6 &&
			   memcmp(&tmp->addr.in6.sin6_addr, 
				  &dst_addr.addr.addr6, 
				  sizeof(struct in6_addr)) == 0)
		    break;
#endif
		}
	  if (!tmp)
	    return; 
	}
    }
  
  if (extract_request(header, (unsigned int)n, daemon->namebuff, &type))
    {
      if (listen->family == AF_INET) 
	log_query(F_QUERY | F_IPV4 | F_FORWARD, daemon->namebuff, 
		  (struct all_addr *)&source_addr.in.sin_addr, type);
#ifdef HAVE_IPV6
      else
	log_query(F_QUERY | F_IPV6 | F_FORWARD, daemon->namebuff, 
		  (struct all_addr *)&source_addr.in6.sin6_addr, type);
#endif
    }

  m = answer_request (header, ((char *) header) + PACKETSZ, (unsigned int)n, daemon, now);
  if (m >= 1)
    send_from(listen->fd, daemon->options & OPT_NOWILD, (char *)header, m, &source_addr, &dst_addr, if_index);
  else
    forward_query(daemon, listen->fd, &source_addr, &dst_addr, if_index,
		  header, n, now);
}

static int read_write(int fd, char *packet, int size, int rw)
{
  int n, done;
  
  for (done = 0; done < size; done += n)
    {
    retry:
      if (rw)
	n = read(fd, &packet[done], (size_t)(size - done));
      else
	n = write(fd, &packet[done], (size_t)(size - done));

      if (n == 0)
	return 0;
      else if (n == -1)
	{
	  if (errno == EINTR)
	    goto retry;
	  else if (errno == EAGAIN)
	    {
	      struct timespec waiter;
	      waiter.tv_sec = 0;
	      waiter.tv_nsec = 10000;
	      nanosleep(&waiter, NULL);
	      goto retry;
	    }
	  else
	    return 0;
	}
    }
  return 1;
}
  
/* The daemon forks before calling this: it should deal with one connection,
   blocking as neccessary, and then return. Note, need to be a bit careful
   about resources for debug mode, when the fork is suppressed: that's
   done by the caller. */
char *tcp_request(struct daemon *daemon, int confd, time_t now)
{
  int size = 0, m;
  unsigned short qtype, gotname;
  unsigned char c1, c2;
  /* Max TCP packet + slop */
  char *packet = malloc(65536 + MAXDNAME + RRFIXEDSZ);
  HEADER *header;
  struct server *last_server;
  
  while (1)
    {
      if (!packet ||
	  !read_write(confd, &c1, 1, 1) || !read_write(confd, &c2, 1, 1) ||
	  !(size = c1 << 8 | c2) ||
	  !read_write(confd, packet, size, 1))
       	return packet; 
  
      if (size < (int)sizeof(HEADER))
	continue;
      
      header = (HEADER *)packet;
      
      if ((gotname = extract_request(header, (unsigned int)size, daemon->namebuff, &qtype)))
	{
	  union mysockaddr peer_addr;
	  socklen_t peer_len = sizeof(union mysockaddr);
	  
	  if (getpeername(confd, (struct sockaddr *)&peer_addr, &peer_len) != -1)
	    {
	      if (peer_addr.sa.sa_family == AF_INET) 
		log_query(F_QUERY | F_IPV4 | F_FORWARD, daemon->namebuff, 
			  (struct all_addr *)&peer_addr.in.sin_addr, qtype);
#ifdef HAVE_IPV6
	      else
		log_query(F_QUERY | F_IPV6 | F_FORWARD, daemon->namebuff, 
			  (struct all_addr *)&peer_addr.in6.sin6_addr, qtype);
#endif
	    }
	}
      
      /* m > 0 if answered from cache */
      m = answer_request(header, ((char *) header) + 65536, (unsigned int)size, daemon, now);
      
      if (m == 0)
	{
	  unsigned short flags = 0;
	  struct all_addr *addrp = NULL;
	  int type = 0;
	  char *domain = NULL;
	  
	  if (gotname)
	    flags = search_servers(daemon, &addrp, gotname, daemon->namebuff, &type, &domain);
	  
	  if (type != 0  || (daemon->options & OPT_ORDER) || !daemon->last_server)
	    last_server = daemon->servers;
	  else
	    last_server = daemon->last_server;
      
	  if (!flags && last_server)
	    {
	      struct server *firstsendto = NULL;
	      
	      /* Loop round available servers until we succeed in connecting to one.
	         Note that this code subtley ensures that consecutive queries on this connection
	         which can go to the same server, do so. */
	      while (1) 
		{
		  if (!firstsendto)
		    firstsendto = last_server;
		  else
		    {
		      if (!(last_server = last_server->next))
			last_server = daemon->servers;
		      
		      if (last_server == firstsendto)
			break;
		    }
	      
		  /* server for wrong domain */
		  if (type != (last_server->flags & SERV_TYPE) ||
		      (type == SERV_HAS_DOMAIN && !hostname_isequal(domain, last_server->domain)))
		    continue;
		  
		  if ((last_server->tcpfd == -1) &&
		      (last_server->tcpfd = socket(last_server->addr.sa.sa_family, SOCK_STREAM, 0)) != -1 &&
		      connect(last_server->tcpfd, &last_server->addr.sa, sa_len(&last_server->addr)) == -1)
		    {
		      close(last_server->tcpfd);
		      last_server->tcpfd = -1;
		    }
		  
		  if (last_server->tcpfd == -1)	
		    continue;
		  
		  c1 = size >> 8;
		  c2 = size;
		  
		  if (!read_write(last_server->tcpfd, &c1, 1, 0) ||
		      !read_write(last_server->tcpfd, &c2, 1, 0) ||
		      !read_write(last_server->tcpfd, packet, size, 0) ||
		      !read_write(last_server->tcpfd, &c1, 1, 1) ||
		      !read_write(last_server->tcpfd, &c2, 1, 1))
		    {
		      close(last_server->tcpfd);
		      last_server->tcpfd = -1;
		      continue;
		    } 
	      
		  m = (c1 << 8) | c2;
		  if (!read_write(last_server->tcpfd, packet, m, 1))
		    return packet;
		  
		  if (!gotname)
		    strcpy(daemon->namebuff, "query");
		  if (last_server->addr.sa.sa_family == AF_INET)
		    log_query(F_SERVER | F_IPV4 | F_FORWARD, daemon->namebuff, 
			      (struct all_addr *)&last_server->addr.in.sin_addr, 0); 
#ifdef HAVE_IPV6
		  else
		    log_query(F_SERVER | F_IPV6 | F_FORWARD, daemon->namebuff, 
			      (struct all_addr *)&last_server->addr.in6.sin6_addr, 0);
#endif 
		  
		  /* There's no point in updating the cache, since this process will exit and
		     lose the information after one query. We make this call for the alias and 
		     bogus-nxdomain side-effects. */
		  process_reply(daemon, header, now, &last_server->addr, m);
		  
		  break;
		}
	    }
	  
	  /* In case of local answer or no connections made. */
	  if (m == 0)
	    m = setup_reply(header, (unsigned int)size, addrp, flags, daemon->local_ttl);
	}
      
      c1 = m>>8;
      c2 = m;
      if (!read_write(confd, &c1, 1, 0) ||
	  !read_write(confd, &c2, 1, 0) || 
	  !read_write(confd, packet, m, 0))
	return packet;
    }
}

static struct frec *get_new_frec(time_t now)
{
  struct frec *f = frec_list, *oldest = NULL;
  time_t oldtime = now;
  int count = 0;
  static time_t warntime = 0;

  while (f)
    {
      if (f->new_id == 0)
	{
	  f->time = now;
	  return f;
	}

      if (difftime(f->time, oldtime) <= 0)
	{
	  oldtime = f->time;
	  oldest = f;
	}

      count++;
      f = f->next;
    }
  
  /* can't find empty one, use oldest if there is one
     and it's older than timeout */
  if (oldest && difftime(now, oldtime)  > TIMEOUT)
    { 
      oldest->time = now;
      return oldest;
    }
  
  if (count > FTABSIZ)
    { /* limit logging rate so syslog isn't DOSed either */
      if (!warntime || difftime(now, warntime) > LOGRATE)
	{
	  warntime = now;
	  syslog(LOG_WARNING, "forwarding table overflow: check for server loops.");
	}
      return NULL;
    }

  if ((f = (struct frec *)malloc(sizeof(struct frec))))
    {
      f->next = frec_list;
      f->time = now;
      frec_list = f;
    }
  return f; /* OK if malloc fails and this is NULL */
}
 
static struct frec *lookup_frec(unsigned short id)
{
  struct frec *f;

  for(f = frec_list; f; f = f->next)
    if (f->new_id == id)
      return f;
      
  return NULL;
}

static struct frec *lookup_frec_by_sender(unsigned short id,
					  union mysockaddr *addr)
{
  struct frec *f;
  
  for(f = frec_list; f; f = f->next)
    if (f->new_id &&
	f->orig_id == id && 
	sockaddr_isequal(&f->source, addr))
      return f;
   
  return NULL;
}


/* return unique random ids between 1 and 65535 */
static unsigned short get_id(void)
{
  unsigned short ret = 0;

  while (ret == 0)
    {
      ret = rand16();
      
      /* scrap ids already in use */
      if ((ret != 0) && lookup_frec(ret))
	ret = 0;
    }

  return ret;
}





