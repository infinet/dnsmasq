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

#ifdef HAVE_DHCP

void dhcp_common_init(void)
{
    /* These each hold a DHCP option max size 255
       and get a terminating zero added */
  daemon->dhcp_buff = safe_malloc(256);
  daemon->dhcp_buff2 = safe_malloc(256); 
  daemon->dhcp_buff3 = safe_malloc(256);
  
  /* dhcp_packet is used by v4 and v6, outpacket only by v6 
     sizeof(struct dhcp_packet) is as good an initial size as any,
     even for v6 */
  expand_buf(&daemon->dhcp_packet, sizeof(struct dhcp_packet));
#ifdef HAVE_DHCP6
  if (daemon->dhcp6)
    expand_buf(&daemon->outpacket, sizeof(struct dhcp_packet));
#endif
}

ssize_t recv_dhcp_packet(int fd, struct msghdr *msg)
{  
  ssize_t sz;
 
  while (1)
    {
      msg->msg_flags = 0;
      while ((sz = recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC)) == -1 && errno == EINTR);
      
      if (sz == -1)
	return -1;
      
      if (!(msg->msg_flags & MSG_TRUNC))
	break;

      /* Very new Linux kernels return the actual size needed, 
	 older ones always return truncated size */
      if ((size_t)sz == daemon->dhcp_packet.iov_len)
	{
	  if (!expand_buf(&daemon->dhcp_packet, sz + 100))
	    return -1;
	}
      else
	{
	  expand_buf(&daemon->dhcp_packet, sz);
	  break;
	}
    }
  
  while ((sz = recvmsg(fd, msg, 0)) == -1 && errno == EINTR);
  
  return (msg->msg_flags & MSG_TRUNC) ? -1 : sz;
}

struct dhcp_netid *run_tag_if(struct dhcp_netid *tags)
{
  struct tag_if *exprs;
  struct dhcp_netid_list *list;

  for (exprs = daemon->tag_if; exprs; exprs = exprs->next)
    if (match_netid(exprs->tag, tags, 1))
      for (list = exprs->set; list; list = list->next)
	{
	  list->list->next = tags;
	  tags = list->list;
	}

  return tags;
}


struct dhcp_netid *option_filter(struct dhcp_netid *tags, struct dhcp_netid *context_tags, struct dhcp_opt *opts)
{
  struct dhcp_netid *tagif = run_tag_if(tags);
  struct dhcp_opt *opt;

  /* flag options which are valid with the current tag set (sans context tags) */
  for (opt = opts; opt; opt = opt->next)
    {
      opt->flags &= ~DHOPT_TAGOK;
      if (!(opt->flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925)) &&
	  match_netid(opt->netid, tagif, 0))
	opt->flags |= DHOPT_TAGOK;
    }

  /* now flag options which are valid, including the context tags,
     otherwise valid options are inhibited if we found a higher priority one above */
  if (context_tags)
    {
      struct dhcp_netid *last_tag;

      for (last_tag = context_tags; last_tag->next; last_tag = last_tag->next);
      last_tag->next = tags;
      tagif = run_tag_if(context_tags);
      
      for (opt = opts; opt; opt = opt->next)
	if (!(opt->flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925 | DHOPT_TAGOK)) &&
	    match_netid(opt->netid, tagif, 0))
	  {
	    struct dhcp_opt *tmp;  
	    for (tmp = opts; tmp; tmp = tmp->next) 
	      if (tmp->opt == opt->opt && opt->netid && (tmp->flags & DHOPT_TAGOK))
		break;
	    if (!tmp)
	      opt->flags |= DHOPT_TAGOK;
	  }      
    }
  
  /* now flag untagged options which are not overridden by tagged ones */
  for (opt = opts; opt; opt = opt->next)
    if (!(opt->flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925 | DHOPT_TAGOK)) && !opt->netid)
      {
	struct dhcp_opt *tmp;  
	for (tmp = opts; tmp; tmp = tmp->next) 
	  if (tmp->opt == opt->opt && (tmp->flags & DHOPT_TAGOK))
	    break;
	if (!tmp)
	  opt->flags |= DHOPT_TAGOK;
	else if (!tmp->netid)
	  my_syslog(MS_DHCP | LOG_WARNING, _("Ignoring duplicate dhcp-option %d"), tmp->opt); 
      }

  return tagif;
}
	
/* Is every member of check matched by a member of pool? 
   If tagnotneeded, untagged is OK */
int match_netid(struct dhcp_netid *check, struct dhcp_netid *pool, int tagnotneeded)
{
  struct dhcp_netid *tmp1;
  
  if (!check && !tagnotneeded)
    return 0;

  for (; check; check = check->next)
    {
      /* '#' for not is for backwards compat. */
      if (check->net[0] != '!' && check->net[0] != '#')
	{
	  for (tmp1 = pool; tmp1; tmp1 = tmp1->next)
	    if (strcmp(check->net, tmp1->net) == 0)
	      break;
	  if (!tmp1)
	    return 0;
	}
      else
	for (tmp1 = pool; tmp1; tmp1 = tmp1->next)
	  if (strcmp((check->net)+1, tmp1->net) == 0)
	    return 0;
    }
  return 1;
}

/* return domain or NULL if none. */
char *strip_hostname(char *hostname)
{
  char *dot = strchr(hostname, '.');
 
  if (!dot)
    return NULL;
  
  *dot = 0; /* truncate */
  if (strlen(dot+1) != 0)
    return dot+1;
  
  return NULL;
}

void log_tags(struct dhcp_netid *netid, u32 xid)
{
  if (netid && option_bool(OPT_LOG_OPTS))
    {
      char *s = daemon->namebuff;
      for (*s = 0; netid; netid = netid->next)
	{
	  /* kill dupes. */
	  struct dhcp_netid *n;
	  
	  for (n = netid->next; n; n = n->next)
	    if (strcmp(netid->net, n->net) == 0)
	      break;
	  
	  if (!n)
	    {
	      strncat (s, netid->net, (MAXDNAME-1) - strlen(s));
	      if (netid->next)
		strncat (s, ", ", (MAXDNAME-1) - strlen(s));
	    }
	}
      my_syslog(MS_DHCP | LOG_INFO, _("%u tags: %s"), xid, s);
    } 
}   
  
int match_bytes(struct dhcp_opt *o, unsigned char *p, int len)
{
  int i;
  
  if (o->len > len)
    return 0;
  
  if (o->len == 0)
    return 1;
     
  if (o->flags & DHOPT_HEX)
    { 
      if (memcmp_masked(o->val, p, o->len, o->u.wildcard_mask))
	return 1;
    }
  else 
    for (i = 0; i <= (len - o->len); ) 
      {
	if (memcmp(o->val, p + i, o->len) == 0)
	  return 1;
	    
	if (o->flags & DHOPT_STRING)
	  i++;
	else
	  i += o->len;
      }
  
  return 0;
}

void check_dhcp_hosts(int fatal)
{
  /* If the same IP appears in more than one host config, then DISCOVER
     for one of the hosts will get the address, but REQUEST will be NAKed,
     since the address is reserved by the other one -> protocol loop. 
     Also check that FQDNs match the domain we are using. */
  
  struct dhcp_config *configs, *cp;
 
  for (configs = daemon->dhcp_conf; configs; configs = configs->next)
    {
      char *domain;

      if ((configs->flags & DHOPT_BANK) || fatal)
       {
	 for (cp = configs->next; cp; cp = cp->next)
	   if ((configs->flags & cp->flags & CONFIG_ADDR) && configs->addr.s_addr == cp->addr.s_addr)
	     {
	       if (fatal)
		 die(_("duplicate IP address %s in dhcp-config directive."), 
		     inet_ntoa(cp->addr), EC_BADCONF);
	       else
		 my_syslog(MS_DHCP | LOG_ERR, _("duplicate IP address %s in %s."), 
			   inet_ntoa(cp->addr), daemon->dhcp_hosts_file);
	       configs->flags &= ~CONFIG_ADDR;
	     }
	 
	 /* split off domain part */
	 if ((configs->flags & CONFIG_NAME) && (domain = strip_hostname(configs->hostname)))
	   configs->domain = domain;
       }
    }
}

void dhcp_update_configs(struct dhcp_config *configs)
{
  /* Some people like to keep all static IP addresses in /etc/hosts.
     This goes through /etc/hosts and sets static addresses for any DHCP config
     records which don't have an address and whose name matches. 
     We take care to maintain the invariant that any IP address can appear
     in at most one dhcp-host. Since /etc/hosts can be re-read by SIGHUP, 
     restore the status-quo ante first. */
  
  struct dhcp_config *config;
  struct crec *crec;
  int prot = AF_INET;

  for (config = configs; config; config = config->next)
    if (config->flags & CONFIG_ADDR_HOSTS)
      config->flags &= ~(CONFIG_ADDR | CONFIG_ADDR6 | CONFIG_ADDR_HOSTS);

#ifdef HAVE_DHCP6 
 again:  
#endif

  if (daemon->port != 0)
    for (config = configs; config; config = config->next)
      {
	int conflags = CONFIG_ADDR;
	int cacheflags = F_IPV4;

#ifdef HAVE_DHCP6
	if (prot == AF_INET6)
	  {
	    conflags = CONFIG_ADDR6;
	    cacheflags = F_IPV6;
	  }
#endif
	if (!(config->flags & conflags) &&
	    (config->flags & CONFIG_NAME) && 
	    (crec = cache_find_by_name(NULL, config->hostname, 0, cacheflags)) &&
	    (crec->flags & F_HOSTS))
	  {
	    if (cache_find_by_name(crec, config->hostname, 0, cacheflags))
	      {
		/* use primary (first) address */
	      while (crec && !(crec->flags & F_REVERSE))
		crec = cache_find_by_name(crec, config->hostname, 0, cacheflags);
	      if (!crec)
		continue; /* should be never */
	      inet_ntop(prot, &crec->addr.addr, daemon->addrbuff, ADDRSTRLEN);
	      my_syslog(MS_DHCP | LOG_WARNING, _("%s has more than one address in hostsfile, using %s for DHCP"), 
			config->hostname, daemon->addrbuff);
	      }
	    
	    if (prot == AF_INET && !config_find_by_address(configs, crec->addr.addr.addr.addr4))
	      {
		config->addr = crec->addr.addr.addr.addr4;
		config->flags |= CONFIG_ADDR | CONFIG_ADDR_HOSTS;
		continue;
	      }

#ifdef HAVE_DHCP6
	    if (prot == AF_INET6 && !config_find_by_address6(configs, &crec->addr.addr.addr.addr6, 129, 0))
	      {
		memcpy(config->hwaddr, &crec->addr.addr.addr.addr6, IN6ADDRSZ);
		config->flags |= CONFIG_ADDR6 | CONFIG_ADDR_HOSTS;
		continue;
	      }
#endif

	    inet_ntop(prot, &crec->addr.addr, daemon->addrbuff, ADDRSTRLEN);
	    my_syslog(MS_DHCP | LOG_WARNING, _("duplicate IP address %s (%s) in dhcp-config directive"), 
		      daemon->addrbuff, config->hostname);
	    
	    
	  }
      }

#ifdef HAVE_DHCP6
  if (prot == AF_INET)
    {
      prot = AF_INET6;
      goto again;
    }
#endif

}

#endif
