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

/* delete all forward records recieved from socket fd */
void reap_forward(int fd)
{
   struct frec *f;

   for (f = frec_list; f; f = f->next)
     if (f->fd == fd)
       f->new_id = 0;
}
 
/* returns new last_server */	
struct server *forward_query(int udpfd, union mysockaddr *udpaddr, HEADER *header, 
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
		    domainlen > matchlen)
		  {
		    if (serv->flags & SERV_LITERAL_ADDRESS)
		      { /* flags gets set if server is in fact an answer */
			unsigned short sflag = serv->addr.sa.sa_family == AF_INET ? F_IPV4 : F_IPV6; 
			if (sflag & gotname) /* only OK if addrfamily == query */
			  {
			    type = SERV_HAS_DOMAIN;
			    flags = sflag;
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
		      }
		  } 
	      }
	}
      
      if (flags) /* flags set here means a literal found */
	log_query(F_CONFIG | F_FORWARD | flags, dnamebuff, addrp);
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
  sendto(udpfd, (char *)header, plen, 0, &udpaddr->sa, sa_len(udpaddr));
 
  if (flags & (F_NOERR | F_NXDOMAIN))
    log_query(F_CONFIG | F_FORWARD | F_NEG | gotname | (flags & F_NXDOMAIN), dnamebuff, NULL);
  
  return last_server;
}

/* returns new last_server */
struct server *reply_query(int fd, int options, char *packet, time_t now,
			   char *dnamebuff, struct server *last_server, struct bogus_addr *bogus_nxdomain)
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
			extract_addresses(header, (unsigned int)n, dnamebuff, now);
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
	  sendto(forward->fd, packet, n, 0, 
		 &forward->source.sa, sa_len(&forward->source));
	  forward->new_id = 0; /* cancel */
	}
    }

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





