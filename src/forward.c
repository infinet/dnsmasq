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
		      union mysockaddr *to, struct all_addr *source)
{
  struct msghdr msg;
  struct iovec iov[1]; 
  struct cmsghdr *cmptr;
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

  if (nowild)
    {
      msg.msg_control = NULL;
      msg.msg_controllen = 0;
      }
  else
    {
      msg.msg_control = &control_u;
      msg.msg_controllen = sizeof(control_u);
    }
  msg.msg_flags = 0;
  msg.msg_name = to;
  msg.msg_namelen = sa_len(to);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;

  cmptr = CMSG_FIRSTHDR(&msg);

#if defined(IP_PKTINFO)
  if (!nowild && to->sa.sa_family == AF_INET)
    {
      struct in_pktinfo *pkt = (struct in_pktinfo *)CMSG_DATA(cmptr);
      pkt->ipi_ifindex = 0;
      pkt->ipi_spec_dst = source->addr.addr4;
      msg.msg_controllen = cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
      cmptr->cmsg_level = SOL_IP;
      cmptr->cmsg_type = IP_PKTINFO;
    }
#elif defined(IP_SENDSRCADDR)
  if (!nowild && to->sa.sa_family == AF_INET)
    {
      struct in_addr *a = (struct in_addr *)CMSG_DATA(cmptr);
      *a = source->addr.addr4;
      msg.msg_controllen = cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
      cmptr->cmsg_level = IPPROTO_IP;
      cmptr->cmsg_type = IP_SENDSRCADDR;
    }
#endif

#ifdef HAVE_IPV6
  if (!nowild && to->sa.sa_family == AF_INET6)
    {
      struct in6_pktinfo *pkt = (struct in6_pktinfo *)CMSG_DATA(cmptr);
      pkt->ipi6_ifindex = 0;
      pkt->ipi6_addr = source->addr.addr6;
      msg.msg_controllen = cmptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
      cmptr->cmsg_type = IPV6_PKTINFO;
      cmptr->cmsg_level = IPV6_LEVEL;
    }
#endif

  sendmsg(fd, &msg, 0);
}
          

/* returns new last_server */	
static struct server *forward_query(int udpfd, union mysockaddr *udpaddr, 
				    struct all_addr *dst_addr, HEADER *header, 
				    int plen, unsigned int options, char *dnamebuff, 
				    struct server *servers, struct server *last_server,
				    time_t now, unsigned long local_ttl)
{
  struct frec *forward;
  char *domain = NULL;
  int type = 0;
  struct server *serv;
  struct all_addr *addrp = NULL;
  unsigned short flags = 0;
  unsigned short gotname = extract_request(header, (unsigned int)plen, dnamebuff);

  /* may be  recursion not speced or no servers available. */
  if (!header->rd || !servers)
    forward = NULL;
  else if ((forward = lookup_frec_by_sender(ntohs(header->id), udpaddr)))
    {
      /* retry on existing query, send to next server */
      domain = forward->sentto->domain;
      type = forward->sentto->flags & SERV_TYPE;
      if (!(forward->sentto = forward->sentto->next))
	forward->sentto = servers; /* at end of list, recycle */
      header->id = htons(forward->new_id);
    }
  else 
    {
      if (gotname)
	{
	  /* If the query ends in the domain in one of our servers, set
	     domain to point to that name. We find the largest match to allow both
	     domain.org and sub.domain.org to exist. */
	  
	  unsigned int namelen = strlen(dnamebuff);
	  unsigned int matchlen = 0;
	 
	  for (serv=servers; serv; serv=serv->next)
	    /* domain matches take priority over NODOTS matches */
	    if ((serv->flags & SERV_FOR_NODOTS) && type != SERV_HAS_DOMAIN && !strchr(dnamebuff, '.'))
	      {
		if (serv->flags & SERV_LITERAL_ADDRESS)
		  {
		    /* flags gets set if server is in fact an answer */
		    unsigned short sflag = serv->addr.sa.sa_family == AF_INET ? F_IPV4 : F_IPV6; 
		    if (sflag & gotname) /* only OK if addrfamily == query */
		      {
			type = SERV_FOR_NODOTS;
			flags = sflag;
			if (serv->addr.sa.sa_family == AF_INET) 
			  addrp = (struct all_addr *)&serv->addr.in.sin_addr;
#ifdef HAVE_IPV6
			else
			  addrp = (struct all_addr *)&serv->addr.in6.sin6_addr;
#endif 
		      }
		  }
		else
		  flags = 0;
	      }
	    else if (serv->flags & SERV_HAS_DOMAIN)
	      {
		unsigned int domainlen = strlen(serv->domain);
		if (namelen >= domainlen &&
		    hostname_isequal(dnamebuff + namelen - domainlen, serv->domain) &&
		    domainlen >= matchlen)
		  {
		    if (serv->flags & SERV_LITERAL_ADDRESS)
		      { /* flags gets set if server is in fact an answer */
			unsigned short sflag = serv->addr.sa.sa_family == AF_INET ? F_IPV4 : F_IPV6; 
			if ((sflag | F_QUERY ) & gotname) /* only OK if addrfamily == query */
			  {
			    type = SERV_HAS_DOMAIN;
			    flags = gotname;
			    domain = serv->domain;
			    matchlen = domainlen; 
			    if (serv->addr.sa.sa_family == AF_INET) 
			      addrp = (struct all_addr *)&serv->addr.in.sin_addr;
#ifdef HAVE_IPV6
			    else
			      addrp = (struct all_addr *)&serv->addr.in6.sin6_addr;
#endif
			  }
		      }
		    else
		      {
			flags = 0; /* may be better match from previous literal */
			domain = serv->domain;
			matchlen = domainlen;
			type = SERV_HAS_DOMAIN;
		      }
		  } 
	      }
	}
      
      if (flags) /* flags set here means a literal found */
	{
	  if (flags & F_QUERY)
	    log_query(F_CONFIG | F_FORWARD | F_NEG, dnamebuff, NULL);
	  else
	    log_query(F_CONFIG | F_FORWARD | flags, dnamebuff, addrp);
	}
      else
	{
	  /* we may by policy not forward names without a domain part */
	  if (gotname && (options & OPT_NODOTS_LOCAL) && !strchr(dnamebuff, '.'))
	    flags = F_NXDOMAIN;
	  else if (!(forward = get_new_frec(now)))
	    /* table full - server failure. */
	    flags = F_NEG;
	}
      
      if (forward)
	{
	  /* In strict_order mode, or when using domain specific servers
	     always try servers in the order specified in resolv.conf,
	     otherwise, use the one last known to work. */
	  
	  if (type != 0  || (options & OPT_ORDER))
	    forward->sentto = servers;
	  else
	    forward->sentto = last_server;
	  
	  forward->source = *udpaddr;
	  forward->dest = *dst_addr;
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
      struct server *firstsentto = forward->sentto;
            
      while (1)
	{ 
	  int logflags = 0;
	  
	  if (forward->sentto->addr.sa.sa_family == AF_INET)
	    {
	      logflags = F_SERVER | F_IPV4 | F_FORWARD;
	      addrp = (struct all_addr *)&forward->sentto->addr.in.sin_addr;
	    }
#ifdef HAVE_IPV6
	  else
	    { 
	      logflags = F_SERVER | F_IPV6 | F_FORWARD;
	      addrp = (struct all_addr *)&forward->sentto->addr.in6.sin6_addr;
	    }
#endif
	  /* only send to servers dealing with our domain.
	     domain may be NULL, in which case server->domain 
	     must be NULL also. */
	  
	  if (type == (forward->sentto->flags & SERV_TYPE) &&
	      (type != SERV_HAS_DOMAIN || hostname_isequal(domain, forward->sentto->domain)))
	    {
	      if (forward->sentto->flags & SERV_NO_ADDR)
		flags = F_NOERR; /* NULL servers are OK. */
	      else if (!(forward->sentto->flags & SERV_LITERAL_ADDRESS) &&
		       sendto(forward->sentto->sfd->fd, (char *)header, plen, 0,
			      &forward->sentto->addr.sa,
			      sa_len(&forward->sentto->addr)) != -1)
		{
		  log_query(logflags, gotname ? dnamebuff : "query", addrp); 
		  /* for no-domain, don't update last_server */
		  return domain ? last_server : (forward->sentto->next ? forward->sentto->next : servers);
		}
	    } 
	  
	  if (!(forward->sentto = forward->sentto->next))
	    forward->sentto = servers;
	  
	  /* check if we tried all without success */
	  if (forward->sentto == firstsentto)
	    break;
	}
      
      /* could not send on, prepare to return */ 
      header->id = htons(forward->orig_id);
      forward->new_id = 0; /* cancel */
    }	  
  
  /* could not send on, return empty answer or address if known for whole domain */
  plen = setup_reply(header, (unsigned int)plen, addrp, flags, local_ttl);
  send_from(udpfd, options & OPT_NOWILD, (char *)header, plen, udpaddr, dst_addr);
  
  if (flags & (F_NOERR | F_NXDOMAIN))
    log_query(F_CONFIG | F_FORWARD | F_NEG | gotname | (flags & F_NXDOMAIN), dnamebuff, NULL);
  
  return last_server;
}

/* returns new last_server */
struct server *reply_query(int fd, int options, char *packet, time_t now,
			   char *dnamebuff, struct server *last_server, 
			   struct bogus_addr *bogus_nxdomain, struct doctor *doctors)
{
  /* packet from peer server, extract data for cache, and send to
     original requester */
  struct frec *forward;
  HEADER *header;
  int n = recv(fd, packet, PACKETSZ, 0);
  
  header = (HEADER *)packet;
  if (n >= (int)sizeof(HEADER) && header->qr)
    {
      if ((forward = lookup_frec(ntohs(header->id))))
	{
	  if (header->rcode == NOERROR || header->rcode == NXDOMAIN)
	    {
	      if (!forward->sentto->domain)
		last_server = forward->sentto; /* known good */
	      if (header->opcode == QUERY)
		{
		  if (!(bogus_nxdomain && 
			header->rcode == NOERROR && 
			check_for_bogus_wildcard(header, (unsigned int)n, dnamebuff, bogus_nxdomain, now)))
		    {
		      if (header->rcode == NOERROR && ntohs(header->ancount) != 0)
			extract_addresses(header, (unsigned int)n, dnamebuff, now, doctors);
		      else if (!(options & OPT_NO_NEG))
			extract_neg_addrs(header, (unsigned int)n, dnamebuff, now);
		    }
		}
	    }
	  header->id = htons(forward->orig_id);
	  /* There's no point returning an upstream reply marked as truncated,
	     since that will prod the resolver into moving to TCP - which we
	     don't support. */
	  header->tc = 0; /* goodbye truncate */
	  send_from(forward->fd, options & OPT_NOWILD, packet, n, &forward->source, &forward->dest);
	  forward->new_id = 0; /* cancel */
	}
    }

  return last_server;
}

struct server *receive_query(struct listener *listen, char *packet, char *mxname, 
			     char *mxtarget, unsigned int options, time_t now, 
			     unsigned long local_ttl, char *namebuff,
			     struct iname *names, struct iname *addrs, struct iname *except,
			     struct server *last_server, struct server *servers)
{
  HEADER *header = (HEADER *)packet;
  union mysockaddr source_addr;
  struct iname *tmp;
  struct all_addr dst_addr;
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
  
  iov[0].iov_base = packet;
  iov[0].iov_len = PACKETSZ;
    
  msg.msg_control = control_u.control;
  msg.msg_controllen = sizeof(control_u);
  msg.msg_flags = 0;
  msg.msg_name = &source_addr;
  msg.msg_namelen = sizeof(source_addr);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  
  n = recvmsg(listen->fd, &msg, 0);
  
  source_addr.sa.sa_family = listen->family;
#ifdef HAVE_IPV6
  if (listen->family == AF_INET6)
    source_addr.in6.sin6_flowinfo = htonl(0);
#endif
  
  if (!(options & OPT_NOWILD) && msg.msg_controllen < sizeof(struct cmsghdr))
    return last_server;

#if defined(IP_PKTINFO)
  if (!(options & OPT_NOWILD) && listen->family == AF_INET)
    for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
      if (cmptr->cmsg_level == SOL_IP && cmptr->cmsg_type == IP_PKTINFO)
	{
	  dst_addr.addr.addr4 = ((struct in_pktinfo *)CMSG_DATA(cmptr))->ipi_spec_dst;
	  if_index = ((struct in_pktinfo *)CMSG_DATA(cmptr))->ipi_ifindex;
	}
#elif defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
  if (!(options & OPT_NOWILD) && listen->family == AF_INET)
    {
      for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVDSTADDR)
	  dst_addr.addr.addr4 = *((struct in_addr *)CMSG_DATA(cmptr));
	else if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
	  if_index = ((struct sockaddr_dl *)CMSG_DATA(cmptr))->sdl_index;
    }
#endif

#ifdef HAVE_IPV6
  if (!(options & OPT_NOWILD) && listen->family == AF_INET6)
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
    return last_server;
  
  /* enforce available interface configuration */
  if (!(options & OPT_NOWILD))
    {
      struct ifreq ifr;

      if (if_index == 0)
	return last_server;
      
      if (except || names)
	{
#ifdef SIOCGIFNAME
	  ifr.ifr_ifindex = if_index;
	  if (ioctl(listen->fd, SIOCGIFNAME, &ifr) == -1)
	    return last_server;
#else
	  if (!if_indextoname(if_index, ifr.ifr_name))
	    return last_server;
#endif
	}

      for (tmp = except; tmp; tmp = tmp->next)
	if (tmp->name && (strcmp(tmp->name, ifr.ifr_name) == 0))
	  return last_server;
      
      if (names || addrs)
	{
	  for (tmp = names; tmp; tmp = tmp->next)
	    if (tmp->name && (strcmp(tmp->name, ifr.ifr_name) == 0))
	      break;
	  if (!tmp)
	    for (tmp = addrs; tmp; tmp = tmp->next)
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
	    return last_server; 
	}
    }
  
  if (extract_request(header, (unsigned int)n, namebuff))
    {
      if (listen->family == AF_INET) 
	log_query(F_QUERY | F_IPV4 | F_FORWARD, namebuff, 
		  (struct all_addr *)&source_addr.in.sin_addr);
#ifdef HAVE_IPV6
      else
	log_query(F_QUERY | F_IPV6 | F_FORWARD, namebuff, 
		  (struct all_addr *)&source_addr.in6.sin6_addr);
#endif
    }

  m = answer_request (header, ((char *) header) + PACKETSZ, (unsigned int)n, 
		      mxname, mxtarget, options, now, local_ttl, namebuff);
  if (m >= 1)
    send_from(listen->fd, options & OPT_NOWILD, (char *)header, m, &source_addr, &dst_addr);
  else
    last_server = forward_query(listen->fd, &source_addr, &dst_addr,
				header, n, options, namebuff, servers, 
				last_server, now, local_ttl);
  return last_server;
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





