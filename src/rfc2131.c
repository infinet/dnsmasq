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

#include "dnsmasq.h"

#define BOOTREQUEST              1
#define BOOTREPLY                2
#define DHCP_COOKIE              0x63825363

#define OPTION_PAD               0
#define OPTION_NETMASK           1
#define OPTION_ROUTER            3
#define OPTION_DNSSERVER         6
#define OPTION_HOSTNAME          12
#define OPTION_DOMAINNAME        15
#define OPTION_BROADCAST         28
#define OPTION_CLIENT_ID         61
#define OPTION_REQUESTED_IP      50 
#define OPTION_LEASE_TIME        51
#define OPTION_OVERLOAD          52
#define OPTION_MESSAGE_TYPE      53
#define OPTION_SERVER_IDENTIFIER 54
#define OPTION_REQUESTED_OPTIONS 55
#define OPTION_MAXMESSAGE        57
#define OPTION_END               255

#define DHCPDISCOVER             1
#define DHCPOFFER                2
#define DHCPREQUEST              3
#define DHCPDECLINE              4
#define DHCPACK                  5
#define DHCPNAK                  6
#define DHCPRELEASE              7
#define DHCPINFORM               8

static unsigned char *option_put(unsigned char *p, unsigned char *end, int opt, int len, unsigned int val);
static void bootp_option_put(struct dhcp_packet *mess, char *filename, char *sname);
static int option_len(unsigned char *opt);
static void *option_ptr(unsigned char *opt);
static struct in_addr option_addr(unsigned char *opt);
static unsigned int option_uint(unsigned char *opt);
static void log_packet(char *type, struct in_addr *addr, unsigned char *hwaddr, char *interface);
static unsigned char *option_find(struct dhcp_packet *mess, int size, int opt_type);
static unsigned char *do_req_options(struct dhcp_context *context,
				     unsigned char *p, unsigned char *end, 
				     unsigned char *req_options, 
				     struct dhcp_opt *config_opts,
				     char *domainname, char *hostname);


int dhcp_reply(struct dhcp_context *context, struct dhcp_packet *mess,
	       unsigned int sz, time_t now, char *namebuff, 
	       struct dhcp_opt *dhcp_opts, struct dhcp_config *dhcp_configs, 
	       char *domain_suffix, char *dhcp_file, char *dhcp_sname, 
	       struct in_addr dhcp_next_server)
{
  unsigned char *opt, *clid;
  struct dhcp_lease *lease;
  int clid_len;
  unsigned char *p = mess->options;
  char *hostname = NULL;
  char *req_options = NULL;
  unsigned int renewal_time, expires_time, def_time;
  struct dhcp_config *config;
 
  if (mess->op != BOOTREQUEST || 
      mess->htype != ARPHRD_ETHER || 
      mess->hlen != ETHER_ADDR_LEN ||
      mess->cookie != htonl(DHCP_COOKIE))
    return 0;	
  
  mess->op = BOOTREPLY;

  /* If there is no client identifier option, use the hardware address */
  if ((opt = option_find(mess, sz, OPTION_CLIENT_ID)))
    {
      clid = option_ptr(opt);
      clid_len = option_len(opt);
    }
  else
    {
      clid =  mess->chaddr;
      clid_len = 0;
    }
  
  /* do we have a lease in store? */
  lease = lease_find_by_client(clid, clid_len);
  
  if ((opt = option_find(mess, sz, OPTION_REQUESTED_OPTIONS)))
    {
      int len = option_len(opt);
      req_options = namebuff;
      memcpy(req_options, option_ptr(opt), len);
      req_options[len] = OPTION_END;
    }

  if ((config = find_config(dhcp_configs, context, clid, clid_len, mess->chaddr, NULL)) && 
      config->hostname)
    hostname = config->hostname;
  else if ((opt = option_find(mess, sz, OPTION_HOSTNAME)))
    {
      int len = option_len(opt);
      /* namebuff is 1K long, use half for requested options and half for hostname */
      /* len < 256 by definition */
      hostname = namebuff + 500;
      memcpy(hostname, option_ptr(opt), len);
      /* May not be zero terminated */
      hostname[len] = 0;
      /* ensure there are no strange chars in there */
      if (!canonicalise(hostname))
	hostname = NULL;
    }

  if (hostname)
    {
      char *dot = strchr(hostname, '.');
      if (dot)
	{
	  if (!domain_suffix || !hostname_isequal(dot+1, domain_suffix))
	    {
	      syslog(LOG_WARNING, "Ignoring DHCP host name %s because it has an illegal domain part", hostname);
	      hostname = NULL;
	    }
	  else
	    *dot = 0; /* truncate */
	}
    }
     
  /* search again now we have a hostname */
  config = find_config(dhcp_configs, context, clid, clid_len, mess->chaddr, hostname);
  def_time = config && config->lease_time ? config->lease_time : context->lease_time;
  
  if ((opt = option_find(mess, sz, OPTION_LEASE_TIME)))
    {
      unsigned int req_time = option_uint(opt);
        
      if (def_time == 0xffffffff || 
	  (req_time != 0xffffffff && req_time < def_time))
	expires_time = renewal_time = req_time;
      else
	expires_time = renewal_time = def_time;
    }
  else
    {
      renewal_time = def_time;
      if (lease)
	expires_time = (unsigned int)difftime(lease->expires, now);
      else 
	expires_time = def_time;
    }
 
  if (!(opt = option_find(mess, sz, OPTION_MESSAGE_TYPE)))
    return 0;
  
  switch (opt[2])
    {
    case DHCPRELEASE:
      if (lease)
	{
	  log_packet("RELEASE", &lease->addr, mess->chaddr, context->iface);
	  lease_prune(lease, now);
	}
      return 0;
      
    case DHCPDISCOVER:
            
      if ((opt = option_find(mess, sz, OPTION_REQUESTED_IP)))	 
	mess->yiaddr = option_addr(opt);
      
      log_packet("DISCOVER", opt ? &mess->yiaddr : NULL, mess->chaddr, context->iface);
      
      if (lease)
	mess->yiaddr = lease->addr;
      else if (config && config->addr.s_addr && !lease_find_by_addr(config->addr))
	mess->yiaddr = config->addr;
      else if ((!opt || !address_available(context, mess->yiaddr)) &&
	       !address_allocate(context, dhcp_configs, &mess->yiaddr))
	{
	  syslog(LOG_WARNING, "address pool exhausted");
	  return 0;
	}
	            
      bootp_option_put(mess, dhcp_file, dhcp_sname);
      mess->siaddr = dhcp_next_server;
      p = option_put(p, &mess->options[308], OPTION_MESSAGE_TYPE, 1, DHCPOFFER);
      p = option_put(p, &mess->options[308], OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(context->serv_addr.s_addr));
      p = option_put(p, &mess->options[308], OPTION_LEASE_TIME, 4, expires_time);
      p = do_req_options(context, p, &mess->options[308], req_options, dhcp_opts, domain_suffix, NULL);
      p = option_put(p, &mess->options[308], OPTION_END, 0, 0);
      
      log_packet("OFFER" , &mess->yiaddr, mess->chaddr, context->iface);
      return p - (unsigned char *)mess;

      
    case DHCPREQUEST:
      if (mess->ciaddr.s_addr)
	{
	  /* RENEWING or REBINDING */ 
	  /* Must exist a lease for this address */
	  log_packet("REQUEST", &mess->ciaddr, mess->chaddr, context->iface);
	  
	  if (!lease || mess->ciaddr.s_addr != lease->addr.s_addr)
	    {
	      log_packet("NAK", &mess->ciaddr, mess->chaddr, context->iface);
	      
	      mess->siaddr.s_addr = mess->yiaddr.s_addr = mess->ciaddr.s_addr = 0;
	      bootp_option_put(mess, NULL, NULL);
	      p = option_put(p, &mess->options[308], OPTION_MESSAGE_TYPE, 1, DHCPNAK);
	      p = option_put(p, &mess->options[308], OPTION_END, 0, 0);
	      
	      return (unsigned char *)mess - p; /* -ve to force bcast */
	    }
	  
	  mess->yiaddr = mess->ciaddr;
	}
      else
	{
	  /* SELECTING  or INIT_REBOOT */
	  if ((opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER)) &&
	      (context->serv_addr.s_addr != option_addr(opt).s_addr))
	    return 0;
	  
	  if (!(opt = option_find(mess, sz, OPTION_REQUESTED_IP)))
	    return 0;
	  
	  mess->yiaddr = option_addr(opt);
	  log_packet("REQUEST", &mess->yiaddr, mess->chaddr, context->iface);
	  
	  /* If a lease exists for this host and another address, squash it. */
	  if (lease && lease->addr.s_addr != mess->yiaddr.s_addr)
	    {
	      lease_prune(lease, now);
	      lease = NULL;
	    }
	  
	  /* accept addresses in the dynamic range or ones allocated statically to
	     particular hosts or an address which the host already has. */
	  if (!lease &&
	      !address_available(context, mess->yiaddr) && 
	      (!config || config->addr.s_addr == 0 || config->addr.s_addr != mess->yiaddr.s_addr))
	    {
	      log_packet("NAK", &mess->yiaddr, mess->chaddr, context->iface);
	      
	      mess->siaddr.s_addr = mess->yiaddr.s_addr = mess->ciaddr.s_addr = 0;
	      bootp_option_put(mess, NULL, NULL);
	      p = option_put(p, &mess->options[308], OPTION_MESSAGE_TYPE, 1, DHCPNAK);
	      p = option_put(p, &mess->options[308], OPTION_END, 0, 0);
	      
	      return (unsigned char *)mess - p; /* -ve to force bcast */
	    }
	  
	  if (!lease && 
	      !(lease = lease_allocate(clid, clid_len, mess->yiaddr)))
	    return 0;
	}	    
      
      lease_set_hwaddr(lease, mess->chaddr);
      lease_set_hostname(lease, hostname, domain_suffix);
      lease_set_expires(lease, renewal_time == 0xffffffff ? 0 : now + (time_t)renewal_time);
      
      bootp_option_put(mess, dhcp_file, dhcp_sname);
      mess->siaddr = dhcp_next_server;
      p = option_put(p, &mess->options[308], OPTION_MESSAGE_TYPE, 1, DHCPACK);
      p = option_put(p, &mess->options[308], OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(context->serv_addr.s_addr));
      p = option_put(p, &mess->options[308], OPTION_LEASE_TIME, 4, renewal_time);
      p = do_req_options(context, p, &mess->options[308], req_options, dhcp_opts, domain_suffix, hostname);
      p = option_put(p, &mess->options[308], OPTION_END, 0, 0);
      
      log_packet("ACK", &mess->yiaddr, mess->chaddr, context->iface);
      return p - (unsigned char *)mess; 
      
    case DHCPINFORM:
      log_packet("INFORM", &mess->ciaddr, mess->chaddr, context->iface);
      
      p = option_put(p, &mess->options[308], OPTION_MESSAGE_TYPE, 1, DHCPACK);
      p = option_put(p, &mess->options[308], OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(context->serv_addr.s_addr));
      p = do_req_options(context, p, &mess->options[308], req_options, dhcp_opts, domain_suffix, hostname);
      p = option_put(p, &mess->options[308], OPTION_END, 0, 0);
      
      log_packet("ACK", &mess->ciaddr, mess->chaddr, context->iface);
      return p - (unsigned char *)mess; 
    }
  
  return 0;
}

static void log_packet(char *type, struct in_addr *addr, unsigned char *hwaddr, char *interface)
{
  syslog(LOG_INFO, "DHCP%s(%s)%s%s hwaddr=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
	 type,
	 interface, 
	 addr ? " " : "",
	 addr ? inet_ntoa(*addr) : "",
	 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
}

static int option_len(unsigned char *opt)
{
  return opt[1];
}

static void *option_ptr(unsigned char *opt)
{
  return &opt[2];
}

static struct in_addr option_addr(unsigned char *opt)
{
  /* this worries about unaligned data in the option. */
  /* struct in_addr is network byte order */
  struct in_addr ret;

  memcpy(&ret, option_ptr(opt), INADDRSZ);

  return ret;
}

static unsigned int option_uint(unsigned char *opt)
{
  /* this worries about unaligned data and byte order */
  unsigned int ret;

  memcpy(&ret, option_ptr(opt), sizeof(unsigned int));
  
  return ntohl(ret);
}

static void bootp_option_put(struct dhcp_packet *mess, char *filename, char *sname)
{
  memset(mess->sname, 0, sizeof(mess->sname));
  memset(mess->file, 0, sizeof(mess->file));
  if (sname)
    strncpy(mess->sname, sname, sizeof(mess->sname)-1);
  if (filename)
    strncpy(mess->file, filename, sizeof(mess->file)-1);
}

static unsigned char *option_put(unsigned char *p, unsigned char *end, int opt, int len, unsigned int val)
{
  int i;

  if (p + len + 2 < end)
    {
      *(p++) = opt;
      *(p++) = len;
      
      for (i = 0; i < len; i++)
	*(p++) = val >> (8 * (len - (i + 1)));
    }
  return p;
}

static unsigned char *option_find1(unsigned char *p, unsigned char *end, int opt, int *overload)
{
  
  if (!p)
    return NULL;
  
  while (*p != OPTION_END) 
    {
      if (end && (p >= end))
	return 0; /* malformed packet */
      else if (*p == OPTION_PAD)
	p++;
      else if (*p == OPTION_OVERLOAD)
	{
	  if (end && (p >= end - 3))
	    return 0; /* malformed packet */
	  if (overload) 
	    *overload = *(p+2);
	  p += 3;
	}
      else 
	{ 
	  int opt_len;;
	  if (end && (p >= end - 2))
	    return 0; /* malformed packet */
	  opt_len = option_len(p);
	  if (end && (p >= end - (2 + opt_len)))
	    return 0; /* malformed packet */
	  if (*p == opt)
	    return p;
	  p += opt_len + 2;
	}
    }
  
  return NULL;
}
 
static unsigned char *option_find(struct dhcp_packet *mess, int size, int opt_type)
{
  int overload = 0; 
  unsigned char *ret;
  
  ret = option_find1(&mess->options[0], ((unsigned char *)mess) + size, opt_type, &overload);
  
  if (!ret && (overload & 1)) 
    ret = option_find1(&mess->file[0], &mess->file[128], opt_type, &overload);

  if (!ret && (overload & 2))
    ret = option_find1(&mess->sname[0], &mess->file[64], opt_type, &overload);

  return ret;
}

static int in_list(unsigned char *list, int opt)
{
  int i;
  
  for (i = 0; list[i] != OPTION_END; i++)
    if (opt == list[i])
      return 1;

  return 0;
}

static struct dhcp_opt *option_find2(struct dhcp_opt *opts, int opt)
{
  for (; opts; opts = opts->next)
    if (opts->opt == opt)
      return opts;
  return NULL;
}

static unsigned char *do_req_options(struct dhcp_context *context,
				     unsigned char *p, unsigned char *end, 
				     unsigned char *req_options,
				     struct dhcp_opt *config_opts,
				     char *domainname, char *hostname)
{
  int i;
  
  if (!req_options)
    return p;

  if (in_list(req_options, OPTION_MAXMESSAGE))
    p = option_put(p, end, OPTION_MAXMESSAGE, 2, sizeof(struct udp_dhcp_packet));
  
  if (in_list(req_options, OPTION_NETMASK) &&
      !option_find2(config_opts, OPTION_NETMASK))
    p = option_put(p, end, OPTION_NETMASK, INADDRSZ, ntohl(context->netmask.s_addr));
  
  if (in_list(req_options, OPTION_BROADCAST) &&
      !option_find2(config_opts, OPTION_BROADCAST))
    p = option_put(p, end, OPTION_BROADCAST, INADDRSZ, ntohl(context->broadcast.s_addr));
  
  if (in_list(req_options, OPTION_ROUTER) &&
      !option_find2(config_opts, OPTION_ROUTER))
    p = option_put(p, end, OPTION_ROUTER, INADDRSZ, ntohl(context->serv_addr.s_addr));

  if (in_list(req_options, OPTION_DNSSERVER) &&
      !option_find2(config_opts, OPTION_DNSSERVER))
    p = option_put(p, end, OPTION_DNSSERVER, INADDRSZ, ntohl(context->serv_addr.s_addr));
  
  if (in_list(req_options, OPTION_DOMAINNAME) && 
      !option_find2(config_opts, OPTION_DOMAINNAME) &&
      domainname && (p + strlen(domainname) + 2 < end))
    {
      *(p++) = OPTION_DOMAINNAME;
      *(p++) = strlen(domainname);
      memcpy(p, domainname, strlen(domainname));
      p += strlen(domainname);
    }
 
  /* Note that we ignore attempts to set the hostname using 
     --dhcp-option=12,<name> */
  if (in_list(req_options, OPTION_HOSTNAME) && 
       hostname && (p + strlen(hostname) + 2 < end))
    {
      *(p++) = OPTION_HOSTNAME;
      *(p++) = strlen(hostname);
      memcpy(p, hostname, strlen(hostname));
      p += strlen(hostname);
    }
  
  for (i = 0; req_options[i] != OPTION_END; i++)
    {
      struct dhcp_opt *opt = option_find2(config_opts, req_options[i]);
      if (req_options[i] != OPTION_HOSTNAME && 
	  req_options[i] != OPTION_MAXMESSAGE &&
	  opt && (p + opt->len + 2 < end))
	{
	  *(p++) = opt->opt;
	  *(p++) = opt->len;
	  if (opt->len != 0)
	    {
	      if (opt->is_addr)
		{
		  int j;
		  struct in_addr *a = (struct in_addr *)opt->val;
		  for (j = 0; j < opt->len; j+=INADDRSZ, a++)
		    {
		      /* zero means "self" */
		      if (a->s_addr == 0)
			memcpy(p, &context->serv_addr, INADDRSZ);
		      else
			memcpy(p, a, INADDRSZ);
		      p += INADDRSZ;
		    }
		}
	      else
		{
		  memcpy(p, opt->val, opt->len);
		  p += opt->len;
		}
	    }
	}
    }
     
  return p;
}


