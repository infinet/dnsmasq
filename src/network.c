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

static struct irec *add_iface(struct irec *list, char *name, union mysockaddr *addr, 
			      struct iname *names, struct iname *addrs, 
			      struct iname *except)
{
  struct irec *iface;
  struct iname *tmp;
  
  /* check blacklist */
  if (except)
    for (tmp = except; tmp; tmp = tmp->next)
      if (tmp->name && strcmp(tmp->name, name) == 0)
	return NULL;
  
  /* we may need to check the whitelist */
  if (names || addrs)
    { 
      for (tmp = names; tmp; tmp = tmp->next)
	if (tmp->name && (strcmp(tmp->name, name) == 0))
	  break;
      if (!tmp && !addrs) 
	return NULL;
 
      for (tmp = addrs; tmp; tmp = tmp->next)
	if (sockaddr_isequal(&tmp->addr, addr))
	  break;
      if (!tmp) 
	return NULL;
    }
  
  /* check whether the interface IP has been added already 
     it is possible to have multiple interfaces with the same address */
  for (; list; list = list->next) 
    if (sockaddr_isequal(&list->addr, addr))
      break;
  if (list)
    return NULL;
  
  /* If OK, add it to the head of the list */
  iface = safe_malloc(sizeof(struct irec));
  iface->addr = *addr;

  return iface;
}


struct irec *enumerate_interfaces(struct iname *names,
				  struct iname *addrs,
				  struct iname *except,
				  int port)
{
  struct irec *iface = NULL, *new;
  char *buf, *ptr;
  struct ifreq *ifr = NULL;
  struct ifconf ifc;
  int lastlen = 0;
  int len = 20 * sizeof(struct ifreq);
  int fd = socket(PF_INET, SOCK_DGRAM, 0);
  
  if (fd == -1)
    die ("cannot create socket to enumerate interfaces: %s", NULL);
      
  while (1)
     {
       buf = safe_malloc(len);

       ifc.ifc_len = len;
       ifc.ifc_buf = buf;
       if (ioctl(fd, SIOCGIFCONF, &ifc) < 0)
	 {
	   if (errno != EINVAL || lastlen != 0)
	     die ("ioctl error while enumerating interfaces: %s", NULL);
	 }
       else
	 {
	   if (ifc.ifc_len == lastlen)
	     break; /* got a big enough buffer now */
	   lastlen = ifc.ifc_len;
	 }
       len += 10*sizeof(struct ifreq);
       free(buf);
     }
  
  for (ptr = buf; ptr < buf + len; )
    {
      union mysockaddr addr;
#ifdef HAVE_SOCKADDR_SA_LEN
      /* subsequent entries may not be aligned, so copy into
	 an aligned buffer to avoid nasty complaints about 
	 unaligned accesses. */
      int ifr_len = ((struct ifreq *)ptr)->ifr_addr.sa_len + IF_NAMESIZE;
      if (!(ifr = realloc(ifr, ifr_len)))
	die("cannot allocate buffer", NULL);
      
      memcpy(ifr, ptr, ifr_len);
      ptr += ifr_len;
#else
      ifr = (struct ifreq *)ptr;
      ptr += sizeof(struct ifreq);
#endif
      
      /* copy address since getting flags overwrites */
      if (ifr->ifr_addr.sa_family == AF_INET)
	{
	  addr.in = *((struct sockaddr_in *) &ifr->ifr_addr);
	  addr.in.sin_port = htons(port);
	}
#ifdef HAVE_IPV6
      else if (ifr->ifr_addr.sa_family == AF_INET6)
	{
#ifdef HAVE_BROKEN_SOCKADDR_IN6
	  addr.in6 = *((struct my_sockaddr_in6 *) &ifr->ifr_addr);
#else
	  addr.in6 = *((struct sockaddr_in6 *) &ifr->ifr_addr);
#endif
	  addr.in6.sin6_port = htons(port);
	  addr.in6.sin6_flowinfo = htonl(0);
	}
#endif
      else
	continue; /* unknown address family */
      
      if (ioctl(fd, SIOCGIFFLAGS, ifr) < 0)
	die("ioctl error getting interface flags: %m", NULL);

      /* If we are restricting the set of interfaces to use, make
	 sure that loopback interfaces are in that set. */
      if (names && (ifr->ifr_flags & IFF_LOOPBACK))
	{
	  struct iname *lo = safe_malloc(sizeof(struct iname));
	  lo->name = safe_string_alloc(ifr->ifr_name);
	  lo->next = names->next;
	  names->next = lo;
	}
      
      if ((new = add_iface(iface, ifr->ifr_name, 
			   &addr, names, addrs, except)))
	{
	  new->next = iface;
	  iface = new;
	}

#if defined(HAVE_LINUX_IPV6_PROC) && defined(HAVE_IPV6)
      /* IPv6 addresses don't seem to work with SIOCGIFCONF. Barf */
      /* This code snarfed from net-tools 1.60 and certainly linux specific, though
	 it shouldn't break on other Unices, and their SIOGIFCONF might work. */
      {
	FILE *f = fopen(IP6INTERFACES, "r");
	int found = 0;
	union mysockaddr addr6;

	if (f)
	  {
	    unsigned int plen, scope, flags, if_idx;
	    char devname[20], addrstring[32];
	    
	    while (fscanf(f, "%32s %02x %02x %02x %02x %20s\n",
			  addrstring, &if_idx, &plen, &scope, &flags, devname) != EOF) 
	      {
		if (strcmp(devname, ifr->ifr_name) == 0)
		  {
		    int i;
		    unsigned char *addr6p = (unsigned char *) &addr6.in6.sin6_addr;
		    memset(&addr6, 0, sizeof(addr6));
		    addr6.sa.sa_family = AF_INET6;
		    for (i=0; i<16; i++)
		      {
			unsigned int byte;
			sscanf(addrstring+i+i, "%02x", &byte);
			addr6p[i] = byte;
		      }
		    addr6.in6.sin6_port = htons(port);
		    addr6.in6.sin6_flowinfo = htonl(0);
		    addr6.in6.sin6_scope_id = htonl(scope);
		    
		    found = 1;
		    break;
		  }
	      }
	    
	    fclose(f);
	  }
	
	if (found && (new = add_iface(iface, ifr->ifr_name,
				      &addr6, names, addrs, except)))
	  {
	    new->next = iface;
	    iface = new;
	  }
      }
#endif /* LINUX */
    }
  
  if (buf)
    free(buf);
#ifdef HAVE_SOCKADDR_SA_LEN
  if (ifr)
    free(ifr);
#endif
  close(fd);

  return iface;
}

struct listener *create_wildcard_listeners(int port)
{
  union mysockaddr addr;
  int opt = 1;
  struct listener *listen;
#ifdef HAVE_IPV6
  int fd;
#endif

  addr.in.sin_family = AF_INET;
  addr.in.sin_addr.s_addr = INADDR_ANY;
  addr.in.sin_port = htons(port);
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
  listen = safe_malloc(sizeof(struct listener));
  if ((listen->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    die("failed to create socket: %s", NULL);
  if (setsockopt(listen->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1 ||
#if defined(IP_PKTINFO) 
      setsockopt(listen->fd, SOL_IP, IP_PKTINFO, &opt, sizeof(opt)) == -1 ||
#elif defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
      setsockopt(listen->fd, IPPROTO_IP, IP_RECVDSTADDR, &opt, sizeof(opt)) == -1 ||
      setsockopt(listen->fd, IPPROTO_IP, IP_RECVIF, &opt, sizeof(opt)) == -1 ||
#endif 
      bind(listen->fd, (struct sockaddr *)&addr, sa_len(&addr)) == -1)
    die("failed to bind socket: %s", NULL);
  listen->next = NULL;
  listen->family = AF_INET;
#ifdef HAVE_IPV6
  addr.in6.sin6_family = AF_INET6;
  addr.in6.sin6_addr = in6addr_any;
  addr.in6.sin6_port = htons(port);
  addr.in6.sin6_flowinfo = htonl(0);
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
  if ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
    {
      if (errno != EPROTONOSUPPORT &&
	  errno != EAFNOSUPPORT &&
	  errno != EINVAL)
	die("failed to create IPv6 socket: %s", NULL);
    }
  else
    {
      listen->next = safe_malloc(sizeof(struct listener));
      listen->next->fd = fd;
      listen->next->family = AF_INET6;
      listen->next->next = NULL;
      if (setsockopt(listen->next->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1 ||
	  setsockopt(listen->next->fd, IPV6_LEVEL, IPV6_PKTINFO, &opt, sizeof(opt)) == -1 ||
	  bind(listen->next->fd, (struct sockaddr *)&addr, sa_len(&addr)) == -1)
	die("failed to bind IPv6 socket: %s", NULL);
    }
#endif
  
  return listen;
}

struct listener *create_bound_listeners(struct irec *interfaces)
{

  struct listener *listeners = NULL;
  struct irec *iface;
  int opt = 1;

  for (iface = interfaces ;iface; iface = iface->next)
    {
      struct listener *new = safe_malloc(sizeof(struct listener));
      new->family = iface->addr.sa.sa_family;
      new->next = listeners;
      listeners = new;
      if ((new->fd = socket(iface->addr.sa.sa_family, SOCK_DGRAM, 0)) == -1)
	die("failed to create socket: %s", NULL);
      if (setsockopt(new->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1 ||
	  bind(new->fd, &iface->addr.sa, sa_len(&iface->addr)) == -1)
	die("failed to bind socket: %s", NULL);
    }

  return listeners;
}

static struct serverfd *allocate_sfd(union mysockaddr *addr, struct serverfd **sfds)
{
  struct serverfd *sfd;
  
  /* may have a suitable one already */
  for (sfd = *sfds; sfd; sfd = sfd->next )
    if (sockaddr_isequal(&sfd->source_addr, addr))
      return sfd;
  
  /* need to make a new one. */
  errno = ENOMEM; /* in case malloc fails. */
  if (!(sfd = malloc(sizeof(struct serverfd))))
    return NULL;
  
  if ((sfd->fd = socket(addr->sa.sa_family, SOCK_DGRAM, 0)) == -1)
    {
      free(sfd);
      return NULL;
    }
  
  if (bind(sfd->fd, (struct sockaddr *)addr, sa_len(addr)) == -1)
    {
      int errsave = errno; /* save error from bind. */
      close(sfd->fd);
      free(sfd);
      errno = errsave;
      return NULL;
    }
  
  sfd->source_addr = *addr;
  sfd->next = *sfds;
  *sfds = sfd;
  
  return sfd;
}

struct server *check_servers(struct server *new, struct irec *interfaces, struct serverfd **sfds)
{
  char addrbuff[ADDRSTRLEN];
  struct irec *iface;
  struct server *tmp, *ret = NULL;
  int port = 0;

  /* forward table rules reference servers, so have to blow them away */
  forward_init(0);
  
  for (;new; new = tmp)
    {
      tmp = new->next;
      
      if (!(new->flags & (SERV_LITERAL_ADDRESS | SERV_NO_ADDR)))
	{
#ifdef HAVE_IPV6
	  if (new->addr.sa.sa_family == AF_INET)
	    {
	      inet_ntop(AF_INET, &new->addr.in.sin_addr, addrbuff, ADDRSTRLEN);
	      port = ntohs(new->addr.in.sin_port);
	    }
	  else if (new->addr.sa.sa_family == AF_INET6)
	    {
	      inet_ntop(AF_INET6, &new->addr.in6.sin6_addr, addrbuff, ADDRSTRLEN);
	      port = ntohs(new->addr.in6.sin6_port);
	    }
#else
	  strcpy(addrbuff, inet_ntoa(new->addr.in.sin_addr));
	  port = ntohs(new->addr.in.sin_port); 
#endif
	  for (iface = interfaces; iface; iface = iface->next)
	    if (sockaddr_isequal(&new->addr, &iface->addr))
	      break;
	  if (iface)
	    {
	      syslog(LOG_WARNING, "ignoring nameserver %s - local interface", addrbuff);
	      free(new);
	      continue;
	    }
	  
	  /* Do we need a socket set? */
	  if (!new->sfd && !(new->sfd = allocate_sfd(&new->source_addr, sfds)))
	    {
	      syslog(LOG_WARNING, 
		     "ignoring nameserver %s - cannot make/bind socket: %m", addrbuff);
	      free(new);
	      continue;
	    }
	}
      
      /* reverse order - gets it right. */
      new->next = ret;
      ret = new;
      
      if (new->flags & (SERV_HAS_DOMAIN | SERV_FOR_NODOTS))
	{
	  char *s1, *s2;
	  if (new->flags & SERV_HAS_DOMAIN)
	    s1 = "domain", s2 = new->domain;
	  else
	    s1 = "unqualified", s2 = "domains";
	  
	  if (new->flags & SERV_NO_ADDR)
	    syslog(LOG_INFO, "using local addresses only for %s %s", s1, s2);
	  else if (!(new->flags & SERV_LITERAL_ADDRESS))
	    syslog(LOG_INFO, "using nameserver %s#%d for %s %s", addrbuff, port, s1, s2);
	}
      else
	syslog(LOG_INFO, "using nameserver %s#%d", addrbuff, port); 
    }
  
 return ret;
}
  
struct server *reload_servers(char *fname, char *buff, struct server *serv, int query_port)
{
  FILE *f;
  char *line;
  struct server *old_servers = NULL;
  struct server *new_servers = NULL;

  /* move old servers to free list - we can reuse the memory 
     and not risk malloc if there are the same or fewer new servers. 
     Servers which were specced on the command line go to the new list. */
  while (serv)
    {
      struct server *tmp = serv->next;
      if (serv->flags & SERV_FROM_RESOLV)
	{
	  serv->next = old_servers;
	  old_servers = serv;
	}
      else
	{
	  serv->next = new_servers;
	  new_servers = serv;
	}
      serv = tmp;
    }

  /* buff happens to be NAXDNAME long... */
  f = fopen(fname, "r");
  if (!f)
    {
      syslog(LOG_ERR, "failed to read %s: %m", fname);
    }
  else
    {
      syslog(LOG_INFO, "reading %s", fname);
      while ((line = fgets(buff, MAXDNAME, f)))
	{
	  union  mysockaddr addr, source_addr;
	  char *token = strtok(line, " \t\n\r");
	  struct server *serv;
	  
	  if (!token || strcmp(token, "nameserver") != 0)
	    continue;
	  if (!(token = strtok(NULL, " \t\n")))
	    continue;
	  
#ifdef HAVE_IPV6
          if (inet_pton(AF_INET, token, &addr.in.sin_addr))
#else
          if ((addr.in.sin_addr.s_addr = inet_addr(token)) != (in_addr_t) -1)
#endif
	    {
#ifdef HAVE_SOCKADDR_SA_LEN
	      source_addr.in.sin_len = addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
	      source_addr.in.sin_family = addr.in.sin_family = AF_INET;
	      addr.in.sin_port = htons(NAMESERVER_PORT);
	      source_addr.in.sin_addr.s_addr = INADDR_ANY;
	      source_addr.in.sin_port = htons(query_port);
	    }
#ifdef HAVE_IPV6
	  else if (inet_pton(AF_INET6, token, &addr.in6.sin6_addr))
	    {
#ifdef HAVE_SOCKADDR_SA_LEN
	      source_addr.in6.sin6_len = addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
	      source_addr.in6.sin6_family = addr.in6.sin6_family = AF_INET6;
	      addr.in6.sin6_port = htons(NAMESERVER_PORT);
	      source_addr.in6.sin6_flowinfo = addr.in6.sin6_flowinfo = htonl(0);
	      source_addr.in6.sin6_addr = in6addr_any;
	      source_addr.in6.sin6_port = htons(query_port);
	    }
#endif /* IPV6 */
	  else
	    continue;
	  
	  if (old_servers)
	    {
	      serv = old_servers;
	      old_servers = old_servers->next;
	    }
	  else if (!(serv = malloc(sizeof (struct server))))
	    continue;
	  
	  /* this list is reverse ordered: 
	     it gets reversed again in check_servers */
	  serv->next = new_servers;
	  new_servers = serv;
	  serv->addr = addr;
	  serv->source_addr = source_addr;
	  serv->domain = NULL;
	  serv->sfd = NULL;
	  serv->flags = SERV_FROM_RESOLV;
	}
  
      fclose(f);
    }

  /* Free any memory not used. */
  while(old_servers)
    {
      struct server *tmp = old_servers->next;
      free(old_servers);
      old_servers = tmp;
    }

  return new_servers;
}







