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
#define OPTION_REQUESTED_IP      50 
#define OPTION_LEASE_TIME        51
#define OPTION_OVERLOAD          52
#define OPTION_MESSAGE_TYPE      53
#define OPTION_SERVER_IDENTIFIER 54
#define OPTION_REQUESTED_OPTIONS 55
#define OPTION_MESSAGE           56
#define OPTION_MAXMESSAGE        57
#define OPTION_T1                58
#define OPTION_T2                59
#define OPTION_CLIENT_ID         61
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
static unsigned char *option_put_string(unsigned char *p, unsigned char *end, int opt, char *string);
static void bootp_option_put(struct dhcp_packet *mess, char *filename, char *sname);
static int option_len(unsigned char *opt);
static void *option_ptr(unsigned char *opt);
static struct in_addr option_addr(unsigned char *opt);
static unsigned int option_uint(unsigned char *opt, int size);
static void log_packet(char *type, struct in_addr *addr, unsigned char *hwaddr, char *interface, char *string);
static unsigned char *option_find(struct dhcp_packet *mess, int size, int opt_type);
static unsigned char *do_req_options(struct dhcp_context *context,
				     unsigned char *p, unsigned char *end, 
				     unsigned char *req_options, 
				     struct dhcp_opt *config_opts,
				     char *domainname, char *hostname,
				     struct in_addr router,
				     struct in_addr iface_addr,
				     int iface_mtu, char *netid);

static int have_config(struct dhcp_config *config, unsigned int mask)
{
  return config && (config->flags & mask);
}

int dhcp_reply(struct dhcp_context *context, 
	       struct in_addr iface_addr,
	       char *iface_name,
	       int iface_mtu,
	       struct udp_dhcp_packet *rawpacket,
	       unsigned int sz, time_t now, char *namebuff, 
	       struct dhcp_opt *dhcp_opts, struct dhcp_config *dhcp_configs, 
	       char *domain_suffix, char *dhcp_file, char *dhcp_sname, 
	       struct in_addr dhcp_next_server, struct in_addr router)
{
  unsigned char *opt, *clid;
  struct dhcp_lease *lease;
  int clid_len;
  struct dhcp_packet *mess = &rawpacket->data;
  unsigned char *p = mess->options;
  /* default max reply packet length, max be overridden */
  unsigned char *end = (unsigned char *)(rawpacket + 1);
  char *hostname = NULL;
  char *req_options = NULL;
  char *message = NULL;
  unsigned int renewal_time, expires_time, def_time;
  struct dhcp_config *config;
  char *netid;
  
  if (mess->op != BOOTREQUEST || 
      mess->hlen != ETHER_ADDR_LEN ||
      mess->cookie != htonl(DHCP_COOKIE))
    return 0;
  
  /* Token ring is supported when we have packet sockets
     to make the HW headers for us. We don't have the code to build
     token ring headers when using BPF. We rely on the fact that
     token ring hwaddrs are the same size as ethernet hwaddrs. */

#ifdef HAVE_BPF
  if (mess->htype != ARPHRD_ETHER)
    return 0;	
#else
  if (mess->htype != ARPHRD_ETHER && 
      mess->htype != ARPHRD_IEEE802)
    return 0;	
#endif
    
  mess->op = BOOTREPLY;

  if ((opt = option_find(mess, sz, OPTION_MAXMESSAGE)))
    {
      int maxsize = (int)option_uint(opt, 2);
      if (maxsize > DNSMASQ_PACKETSZ)
	maxsize = DNSMASQ_PACKETSZ; 
      if (maxsize > iface_mtu)
	maxsize = iface_mtu; 

      end = ((unsigned char *)rawpacket) + maxsize;
    }

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
      have_config(config, CONFIG_NAME))
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
      else
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
    }
     
  /* search again now we have a hostname */
  config = find_config(dhcp_configs, context, clid, clid_len, mess->chaddr, hostname);
  def_time = have_config(config, CONFIG_TIME) ? config->lease_time : context->lease_time;
  netid = have_config(config, CONFIG_NETID) ? config->netid : context->netid;
  
  if ((opt = option_find(mess, sz, OPTION_LEASE_TIME)))
    {
      unsigned int req_time = option_uint(opt, 4);
        
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
    case DHCPDECLINE:
      if (!(opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER)) ||
	  (iface_addr.s_addr != option_addr(opt).s_addr))
	return 0;

      /* sanitise any message. Paranoid? Moi? */
      if ((opt = option_find(mess, sz, OPTION_MESSAGE)))
	{ 
	  char *p = option_ptr(opt), *q = namebuff;
	  int i;
	  
	  for (i = option_len(opt); i > 0; i--)
	    {
	      char c = *p++;
	      if (isprint(c))
		*q++ = c;
	    }
	  *q++ = 0; /* add terminator */
	  message = namebuff;
	}
      
      if (!(opt = option_find(mess, sz, OPTION_REQUESTED_IP)))
	return 0;
      
      log_packet("DECLINE", option_ptr(opt), mess->chaddr, iface_name, message);
      
      if (lease && lease->addr.s_addr == option_addr(opt).s_addr)
	lease_prune(lease, now);
      
      if (have_config(config, CONFIG_ADDR) && 
	  config->addr.s_addr == option_addr(opt).s_addr)
	{
	  syslog(LOG_WARNING, "disabling DHCP static address %s", inet_ntoa(config->addr));
	  config->flags &= ~CONFIG_ADDR ;
	}
      
      return 0;

    case DHCPRELEASE:
      if (!(opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER)) ||
	  (iface_addr.s_addr != option_addr(opt).s_addr))
	return 0;
      
      log_packet("RELEASE", &mess->ciaddr, mess->chaddr, iface_name, NULL);

      if (lease && lease->addr.s_addr == mess->ciaddr.s_addr)
	lease_prune(lease, now);
	
      return 0;
      
    case DHCPDISCOVER:
      if ((opt = option_find(mess, sz, OPTION_REQUESTED_IP)))	 
	mess->yiaddr = option_addr(opt);
      
      if (have_config(config, CONFIG_DISABLE))
	message = "ignored";
      else if (have_config(config, CONFIG_ADDR) && !lease_find_by_addr(config->addr))
	mess->yiaddr = config->addr;
      else if (lease && 
	       ((lease->addr.s_addr & context->netmask.s_addr) == 
		(context->start.s_addr & context->netmask.s_addr)))
	mess->yiaddr = lease->addr;
      else if ((!opt || !address_available(context, mess->yiaddr)) &&
	       !address_allocate(context, dhcp_configs, &mess->yiaddr))
	message = "no address available";
	 
      log_packet("DISCOVER", opt ? &mess->yiaddr : NULL, mess->chaddr, iface_name, message);          
      if (message)
	return 0;

      bootp_option_put(mess, dhcp_file, dhcp_sname);
      mess->siaddr = dhcp_next_server;
      p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPOFFER);
      p = option_put(p, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(iface_addr.s_addr));
      p = option_put(p, end, OPTION_LEASE_TIME, 4, expires_time);
      p = do_req_options(context, p, end, req_options, dhcp_opts, domain_suffix, 
			 NULL, router, iface_addr, iface_mtu, netid);
      p = option_put(p, end, OPTION_END, 0, 0);
      
      log_packet("OFFER" , &mess->yiaddr, mess->chaddr, iface_name, NULL);
      return p - (unsigned char *)mess;

      
    case DHCPREQUEST:
      if ((opt = option_find(mess, sz, OPTION_REQUESTED_IP)))
	{
	  /* SELECTING  or INIT_REBOOT */
	  mess->yiaddr = option_addr(opt);
	  /* The RFC says that this is already zero, but there exist
	     real-world counter examples. */
	  mess->ciaddr.s_addr = 0; 
	  
	  if ((opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER)) &&
	      (iface_addr.s_addr != option_addr(opt).s_addr))
	    return 0;
	  
	  /* If a lease exists for this host and another address, squash it. */
	  if (lease && lease->addr.s_addr != mess->yiaddr.s_addr)
	    {
	      lease_prune(lease, now);
	      lease = NULL;
	    }
	  
	  /* accept addresses in the dynamic range or ones allocated statically to
	     particular hosts or an address which the host already has. */
	  if (!lease)
	    { 
	      if (!address_available(context, mess->yiaddr) && 
		  (!have_config(config, CONFIG_ADDR) || config->addr.s_addr != mess->yiaddr.s_addr))
		message = "address unavailable";
	      else if (!(lease = lease_allocate(clid, clid_len, mess->yiaddr)))
		message = "no leases left";
	    }
	}
      else
	{
	  /* RENEWING or REBINDING */ 
	  /* Must exist a lease for this address */
	  if (!mess->ciaddr.s_addr)
	    return 0;
	  
	  mess->yiaddr = mess->ciaddr;
	  if (!lease || mess->ciaddr.s_addr != lease->addr.s_addr)
	    message = "lease not found";
	}
      
      /* If a machine moves networks whilst it has a lease, we catch that here. */
      if ((mess->yiaddr.s_addr & context->netmask.s_addr) != (context->start.s_addr & context->netmask.s_addr))
	message = "wrong network";
      
      if (have_config(config, CONFIG_DISABLE))
	message = "disabled";

      log_packet("REQUEST", &mess->yiaddr, mess->chaddr, iface_name, NULL);
      
      if (message)
	{
	  log_packet("NAK", &mess->yiaddr, mess->chaddr, iface_name, message);
	  
	  mess->siaddr.s_addr = mess->yiaddr.s_addr = mess->ciaddr.s_addr = 0;
	  bootp_option_put(mess, NULL, NULL);
	  p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPNAK);
	  p = option_put_string(p, end, OPTION_MESSAGE, message);
	  p = option_put(p, end, OPTION_END, 0, 0);
	  mess->flags |= htons(0x8000); /* broadcast */
	  return p - (unsigned char *)mess;
	}
      
      log_packet("ACK", &mess->yiaddr, mess->chaddr, iface_name, hostname);
      
      lease_set_hwaddr(lease, mess->chaddr);
      lease_set_hostname(lease, hostname, domain_suffix);
      lease_set_expires(lease, renewal_time == 0xffffffff ? 0 : now + (time_t)renewal_time);
      
      bootp_option_put(mess, dhcp_file, dhcp_sname);
      mess->siaddr = dhcp_next_server;
      p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);
      p = option_put(p, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(iface_addr.s_addr));
      p = option_put(p, end, OPTION_LEASE_TIME, 4, renewal_time);
      if (renewal_time != 0xffffffff)
	{
	  unsigned short fuzz = rand16();
	  while (fuzz > (renewal_time/16))
	    fuzz = fuzz/2;
	  p = option_put(p, end, OPTION_T1, 4, (renewal_time/2) - fuzz);
	  p = option_put(p, end, OPTION_T2, 4, ((renewal_time * 7)/8) - fuzz);
	}
      p = do_req_options(context, p, end, req_options, dhcp_opts, domain_suffix, 
			 hostname, router, iface_addr, iface_mtu, netid);
      p = option_put(p, end, OPTION_END, 0, 0);
      return p - (unsigned char *)mess; 
      
    case DHCPINFORM:
      if (have_config(config, CONFIG_DISABLE))
	{
	  log_packet("INFORM", &mess->ciaddr, mess->chaddr, iface_name, "ignored");
	  return 0;
	}
      
      log_packet("INFORM", &mess->ciaddr, mess->chaddr, iface_name, NULL);
      
      p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);
      p = option_put(p, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(iface_addr.s_addr));
      p = do_req_options(context, p, end, req_options, dhcp_opts, domain_suffix, 
			 hostname, router, iface_addr, iface_mtu, netid);
      p = option_put(p, end, OPTION_END, 0, 0);
      
      log_packet("ACK", &mess->ciaddr, mess->chaddr, iface_name, hostname);
      return p - (unsigned char *)mess; 
    }
  
  return 0;
}

static void log_packet(char *type, struct in_addr *addr, unsigned char *hwaddr, char *interface, char *string)
{
  syslog(LOG_INFO, "DHCP%s(%s)%s%s %.2x:%.2x:%.2x:%.2x:%.2x:%.2x%s%s",
	 type,
	 interface, 
	 addr ? " " : "",
	 addr ? inet_ntoa(*addr) : "",
	 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5],
	 string ? " " : "",
	 string ? string : "");
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

static unsigned int option_uint(unsigned char *opt, int size)
{
  /* this worries about unaligned data and byte order */
  unsigned int ret = 0;
  int i;
  unsigned char *p = option_ptr(opt);
  
  for (i = 0; i < size; i++)
    ret = (ret << 8) | *p++;

  return ret;
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
  
  /* always keep one octet space for the END option. */ 
  if ((opt == OPTION_END) || (p + len + 3 < end))
    {
      *(p++) = opt;
      if (opt != OPTION_END)
	{
	  *(p++) = len;
	  
	  for (i = 0; i < len; i++)
	    *(p++) = val >> (8 * (len - (i + 1)));
	}
    }
  return p;
}

static unsigned char *option_put_string(unsigned char *p, unsigned char *end, int opt, char *string)
{
  if (p + strlen(string) + 3 < end)
    {
      *(p++) = opt;
      *(p++) = strlen(string);
      memcpy(p, string, strlen(string));
      p += strlen(string);
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

static struct dhcp_opt *option_find2(char *netid, struct dhcp_opt *opts, int opt)
{
  for (; opts; opts = opts->next)
    if (opts->opt == opt && 
	(!opts->netid || (netid && strcmp(opts->netid, netid) == 0)))
      return opts;
  return NULL;
}

static unsigned char *do_req_options(struct dhcp_context *context,
				     unsigned char *p, unsigned char *end, 
				     unsigned char *req_options,
				     struct dhcp_opt *config_opts,
				     char *domainname, char *hostname,
				     struct in_addr router, 
				     struct in_addr iface_addr,
				     int iface_mtu, char *netid)
{
  int i;
  
  if (!req_options)
    return p;
  
  if (in_list(req_options, OPTION_MAXMESSAGE))
    p = option_put(p, end, OPTION_MAXMESSAGE, 2, 
		   DNSMASQ_PACKETSZ > iface_mtu ? 
		   iface_mtu : DNSMASQ_PACKETSZ);
  
  if (in_list(req_options, OPTION_NETMASK) &&
      !option_find2(netid, config_opts, OPTION_NETMASK))
    p = option_put(p, end, OPTION_NETMASK, INADDRSZ, ntohl(context->netmask.s_addr));
  
  if (in_list(req_options, OPTION_BROADCAST) &&
      !option_find2(netid, config_opts, OPTION_BROADCAST))
    p = option_put(p, end, OPTION_BROADCAST, INADDRSZ, ntohl(context->broadcast.s_addr));
  
  if (in_list(req_options, OPTION_ROUTER) &&
      !option_find2(netid, config_opts, OPTION_ROUTER))
    p = option_put(p, end, OPTION_ROUTER, INADDRSZ, 
		   ntohl(router.s_addr));

  if (in_list(req_options, OPTION_DNSSERVER) &&
      !option_find2(netid, config_opts, OPTION_DNSSERVER))
    p = option_put(p, end, OPTION_DNSSERVER, INADDRSZ, ntohl(iface_addr.s_addr));
  
  if (domainname && in_list(req_options, OPTION_DOMAINNAME) && 
      !option_find2(netid, config_opts, OPTION_DOMAINNAME))
    p = option_put_string(p, end, OPTION_DOMAINNAME, domainname);
 
  /* Note that we ignore attempts to set the hostname using 
     --dhcp-option=12,<name> */
  if (hostname && in_list(req_options, OPTION_HOSTNAME))
    p = option_put_string(p, end, OPTION_HOSTNAME, hostname);
  
  for (i = 0; req_options[i] != OPTION_END; i++)
    {
      struct dhcp_opt *opt;
     
      if (req_options[i] == OPTION_HOSTNAME || 
	  req_options[i] == OPTION_MAXMESSAGE ||
	  !(opt = option_find2(netid, config_opts, req_options[i])) || 
	  (p + opt->len + 3 >= end))
	continue;
      
      /* For the options we have default values on
	 dhc-option=<optionno> means "don't include this option"
	 not "include a zero-length option" */
      if (opt->len == 0 && 
	  (opt->opt == OPTION_NETMASK ||
	   opt->opt == OPTION_BROADCAST ||
	   opt->opt == OPTION_ROUTER ||
	   opt->opt == OPTION_DNSSERVER))
	continue;
      
      *(p++) = opt->opt;
      *(p++) = opt->len;
      if (opt->len == 0)
	continue;
	
      if (opt->is_addr)
	{
	  int j;
	  struct in_addr *a = (struct in_addr *)opt->val;
	  for (j = 0; j < opt->len; j+=INADDRSZ, a++)
	    {
	      /* zero means "self" */
	      if (a->s_addr == 0)
		memcpy(p, &iface_addr, INADDRSZ);
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
  return p;
}


