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

/* The Linux in-kernel DHCP client silently ignores any packet 
   smaller than this. Sigh...........   */
#define MIN_PACKETSZ             300

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
#define OPTION_VENDOR_ID         60
#define OPTION_CLIENT_ID         61
#define OPTION_USER_CLASS        77
#define OPTION_SUBNET_SELECT     118
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
static unsigned char *option_end(unsigned char *p, unsigned char *end, struct dhcp_packet *start);
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
				     struct daemon *daemon,
				     char *hostname,
				     struct in_addr iface_addr,
				     struct dhcp_netid *netid,
				     struct in_addr subnet_addr);

static int have_config(struct dhcp_config *config, unsigned int mask)
{
  return config && (config->flags & mask);
}

int dhcp_reply(struct daemon *daemon, struct in_addr iface_addr, char *iface_name, unsigned int sz, time_t now)
{
  struct dhcp_context *context, *context_tmp;
  unsigned char *opt, *clid;
  struct dhcp_lease *lease, *ltmp;
  struct dhcp_vendor *vendor;
  int clid_len;
  struct dhcp_packet *mess = &daemon->dhcp_packet->data;
  unsigned char *p = mess->options + sizeof(u32); /* skip cookie */
  unsigned char *end = (unsigned char *)(daemon->dhcp_packet + 1);
  char *hostname = NULL;
  char *req_options = NULL;
  char *message = NULL;
  unsigned int renewal_time, expires_time, def_time;
  struct dhcp_config *config;
  struct dhcp_netid *netid = NULL;
  struct in_addr addr, subnet_addr;
  unsigned short fuzz = 0;
  unsigned int mess_type = 0;

  subnet_addr.s_addr = 0;

  if (mess->op != BOOTREQUEST)
    return 0;
  
  /* Token ring is supported when we have packet sockets
     to make the HW headers for us. We don't have the code to build
     token ring headers when using BPF. We rely on the fact that
     token ring hwaddrs are the same size as ethernet hwaddrs. */
  
#ifdef HAVE_BPF
  if (mess->htype != ARPHRD_ETHER)	
#else
  if (mess->htype != ARPHRD_ETHER && mess->htype != ARPHRD_IEEE802)
#endif
    {
      syslog(LOG_WARNING, "DHCP request for unsupported hardware type (%d) recieved on %s", 
	     mess->htype, iface_name);
      return 0;
    }	
  
  if (mess->hlen != ETHER_ADDR_LEN)
    return 0;
  
  /* check for DHCP rather than BOOTP */
  if ((opt = option_find(mess, sz, OPTION_MESSAGE_TYPE)))
    {
      mess_type = option_uint(opt, 1);

      /* only insist on a cookie for DHCP. */
      if (*((u32 *)&mess->options) != htonl(DHCP_COOKIE))
	return 0;

      /* Some buggy clients set ciaddr when they shouldn't, so clear that here since
	 it can affect the context-determination code. */
      if ((option_find(mess, sz, OPTION_REQUESTED_IP) || mess_type == DHCPDISCOVER))
	mess->ciaddr.s_addr = 0;

      /* Check for RFC3011 subnet selector */
      if ((opt = option_find(mess, sz, OPTION_SUBNET_SELECT)))
	subnet_addr = option_addr(opt);
    }
  
  /* Determine network for this packet. If the machine has an address already, and we don't have
     have a giaddr or explicit subnet selector, use the ciaddr. This is necessary because a 
     machine which got a lease via a relay won't use the relay to renew. */
  addr = 
    subnet_addr.s_addr ? subnet_addr : 
    (mess->giaddr.s_addr ? mess->giaddr : 
     (mess->ciaddr.s_addr ? mess->ciaddr : iface_addr));

  /* More than one context may match, we build a chain of them all on ->current
     Note that if netmasks, netid or lease times don't match, odd things may happen. */
    
  for (context = NULL, context_tmp = daemon->dhcp; context_tmp; context_tmp = context_tmp->next)
    if (context_tmp->netmask.s_addr  && 
	is_same_net(addr, context_tmp->start, context_tmp->netmask) &&
	is_same_net(addr, context_tmp->end, context_tmp->netmask))
      {
	context_tmp->current = context;
	context = context_tmp;
	
	/* start to build netid chain */
	if (context_tmp->netid.net)
	  {
	    context_tmp->netid.next = netid;
	    netid = &context_tmp->netid;
	  }
      }
  
  if (!context)
    {
      syslog(LOG_WARNING, "no address range available for DHCP request %s %s", 
	     subnet_addr.s_addr ? "with subnet selector" : "via",
	     subnet_addr.s_addr ? inet_ntoa(subnet_addr) : (mess->giaddr.s_addr ? inet_ntoa(mess->giaddr) : iface_name));
      return 0;
    }
  
  mess->op = BOOTREPLY;
    
  if (mess_type == 0)
    {
      /* BOOTP request */
      config = find_config(daemon->dhcp_conf, context, NULL, 0, mess->chaddr, NULL);
      if (have_config(config, CONFIG_ADDR) &&
	  !have_config(config, CONFIG_DISABLE) &&
	  !lease_find_by_addr(config->addr))
	{
	  struct dhcp_netid id;
	  char save = mess->file[128];
	  end = mess->options + 64; /* BOOTP vend area is only 64 bytes */
	  mess->yiaddr = config->addr;
	  mess->siaddr = daemon->dhcp_next_server.s_addr ? daemon->dhcp_next_server : iface_addr;
	  if (have_config(config, CONFIG_NAME))
	    hostname = config->hostname;
	  if (have_config(config, CONFIG_NETID))
	    {
	      config->netid.next = netid;
	      netid = &config->netid;
	    }
	  /* Match incoming filename field as a netid. */
	  if (mess->file[0])
	    {
	      mess->file[128] = 0; /* ensure zero term. */
	      id.net = mess->file;
	      id.next = netid;
	      netid = &id;
	    }
	  p = do_req_options(context, p, end, NULL, daemon, 
			     hostname, iface_addr, netid, subnet_addr);
	  /* must do this after do_req_options since it overwrites filename field. */
	  bootp_option_put(mess, daemon->dhcp_file, daemon->dhcp_sname);
	  p = option_end(p, end, mess);
	  log_packet(NULL, &config->addr, mess->chaddr, iface_name, NULL);
	  mess->file[128] = save;
	  return p - (unsigned char *)mess; 
	}
      return 0;
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
    
  config = find_config(daemon->dhcp_conf, context, clid, clid_len, mess->chaddr, NULL);

  if (have_config(config, CONFIG_NAME))
    hostname = config->hostname;
  else if ((opt = option_find(mess, sz, OPTION_HOSTNAME)))
    {
      int len = option_len(opt);
      hostname = daemon->dhcp_buff;
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
	      if (!daemon->domain_suffix || !hostname_isequal(dot+1, daemon->domain_suffix))
		{
		  syslog(LOG_WARNING, "Ignoring DHCP host name %s because it has an illegal domain part", hostname);
		  hostname = NULL;
		}
	      else
		{
		  *dot = 0; /* truncate */
		  if (strlen(hostname) == 0)
		    hostname = NULL; /* nothing left */
		}
	    }

	  /* Search again now we have a hostname. 
	     Only accept configs without CLID and HWADDR here, (they won't match)
	     to avoid impersonation by name. */
	  if (!config)
	    {
	      struct dhcp_config *new = find_config(daemon->dhcp_conf, context, NULL, 0, mess->chaddr, hostname);
	      if (!have_config(new, CONFIG_CLID) && !have_config(new, CONFIG_HWADDR))
		config = new;
	    }
	}
    }
  
  if (have_config(config, CONFIG_NETID))
    {
      config->netid.next = netid;
      netid = &config->netid;
    }
  
  /* Theres a chance that carefully chosen data could match the same
     vendor/user option twice and make a loop in the netid chain. */
  for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
    vendor->used = 0;

  if ((opt = option_find(mess, sz, OPTION_VENDOR_ID)))
    for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
      if (vendor->is_vendor && !vendor->used)
	{
	  int i;
	  for (i = 0; i <= (option_len(opt) - vendor->len); i++)
	    if (memcmp(vendor->data, option_ptr(opt)+i, vendor->len) == 0)
	      {
		vendor->used = 1;
		vendor->netid.next = netid;
		netid = &vendor->netid;
		break;
	      }
	}
  
  if ((opt = option_find(mess, sz, OPTION_USER_CLASS)))
    {
      unsigned char *ucp =  option_ptr(opt);
      int j;
      for (j = 0; j < option_len(opt); j += ucp[j] + 1)
	for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
	  if (!vendor->is_vendor && !vendor->used)
	    {
	      int i;
	      for (i = 0; i <= (ucp[j] - vendor->len); i++)
		if (memcmp(vendor->data, &ucp[j+i+1], vendor->len) == 0)
		  {
		    vendor->used = 1;
		    vendor->netid.next = netid;
		    netid = &vendor->netid;
		    break;
		  }
	    }
    }
     
  /* Can have setting to ignore the client ID for a particular MAC address or hostname */
  if (have_config(config, CONFIG_NOCLID))
    {
      clid =  mess->chaddr;
      clid_len = 0;
    }
    
  /* do we have a lease in store? */
  lease = lease_find_by_client(clid, clid_len);
  
  def_time = have_config(config, CONFIG_TIME) ? config->lease_time : context->lease_time;
  
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
  
  if ((opt = option_find(mess, sz, OPTION_REQUESTED_OPTIONS)))
    {
      int len = option_len(opt);
      req_options = daemon->dhcp_buff2;
      memcpy(req_options, option_ptr(opt), len);
      req_options[len] = OPTION_END;
    }
  
  switch (mess_type)
    {
    case DHCPDECLINE:
      if (!(opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER)) ||
	  (iface_addr.s_addr != option_addr(opt).s_addr))
	return 0;

      /* sanitise any message. Paranoid? Moi? */
      if ((opt = option_find(mess, sz, OPTION_MESSAGE)))
	{ 
	  char *p = option_ptr(opt), *q = daemon->dhcp_buff;
	  int i;
	  
	  for (i = option_len(opt); i > 0; i--)
	    {
	      char c = *p++;
	      if (isprint(c))
		*q++ = c;
	    }
	  *q++ = 0; /* add terminator */
	  message = daemon->dhcp_buff;
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
      else
	/* make sure this host gets a different address next time. */
	for (; context; context = context->current)
	  context->addr_epoch++;
      
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
	addr = option_addr(opt);
      if (have_config(config, CONFIG_DISABLE))
	message = "ignored";
      else if (have_config(config, CONFIG_ADDR) && 
               (!(ltmp = lease_find_by_addr(config->addr)) || ltmp == lease))
	mess->yiaddr = config->addr;
      else if (lease && address_available(context, lease->addr))
	mess->yiaddr = lease->addr;
      else if (opt && address_available(context, addr) && !lease_find_by_addr(addr) && 
	       !config_find_by_address(daemon->dhcp_conf, addr))
	mess->yiaddr = addr;
      else if (!address_allocate(context, daemon, &mess->yiaddr, mess->chaddr))
	message = "no address available";      
      log_packet("DISCOVER", opt ? &addr : NULL, mess->chaddr, iface_name, message);          
      
      if (message)
	return 0;
      
      bootp_option_put(mess, daemon->dhcp_file, daemon->dhcp_sname);
      mess->siaddr = daemon->dhcp_next_server.s_addr ? daemon->dhcp_next_server : iface_addr;
      p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPOFFER);
      p = option_put(p, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(iface_addr.s_addr));
      p = option_put(p, end, OPTION_LEASE_TIME, 4, expires_time);
      /* T1 and T2 are required in DHCPOFFER by HP's wacky Jetdirect client. */
      if (expires_time != 0xffffffff)
	{
	  p = option_put(p, end, OPTION_T1, 4, (expires_time/2));
	  p = option_put(p, end, OPTION_T2, 4, ((expires_time * 7)/8));
	}
      p = do_req_options(context, p, end, req_options, daemon, 
			 NULL, iface_addr, netid, subnet_addr);
      p = option_end(p, end, mess);
      
      log_packet("OFFER" , &mess->yiaddr, mess->chaddr, iface_name, NULL);
      return p - (unsigned char *)mess;
      
    case DHCPREQUEST:
      if (have_config(config, CONFIG_DISABLE))
	message = "disabled";
      else if ((opt = option_find(mess, sz, OPTION_REQUESTED_IP)))
	{
	  /* SELECTING  or INIT_REBOOT */
	  mess->yiaddr = option_addr(opt);
	  
	  if ((opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER)))
	    {
	      /* SELECTING */
	      if (iface_addr.s_addr != option_addr(opt).s_addr)
		return 0;
	      
	      /* If a lease exists for this host and another address, squash it. */
	      if (lease && lease->addr.s_addr != mess->yiaddr.s_addr)
		{
		  lease_prune(lease, now);
		  lease = NULL;
		}
	      
	      if (!lease)
		{ 
		  if (lease_find_by_addr(mess->yiaddr))
		    message = "address in use";
		  else if (!(lease = lease_allocate(clid, clid_len, mess->yiaddr)))
		    message = "no leases left";
		} 
	    }
	  else
	    {
	      /* INIT-REBOOT */
	      if (!lease)
		return 0;
	      
	      if (lease->addr.s_addr != mess->yiaddr.s_addr)
		message = "wrong address";
	    }
	}
      else
	{
	  /* RENEWING or REBINDING */ 
	  /* Must exist a lease for this address */
	  if (!lease || mess->ciaddr.s_addr != lease->addr.s_addr)
	    message = "lease not found";
	  
	  /* desynchronise renewals */
	  fuzz = rand16();
	  while (fuzz > (renewal_time/16))
	    fuzz = fuzz/2; 

	  mess->yiaddr = mess->ciaddr;
	}
      
      if (!message)
	{
	  struct dhcp_config *addr_config;
	  /* If a machine moves networks whilst it has a lease, we catch that here. */
	  if (!is_same_net(mess->yiaddr, context->start, context->netmask))
	    message = "wrong network";

	  /* Check for renewal of a lease which is now outside the allowed range. */
	  else if (!address_available(context, mess->yiaddr) &&
		   (!have_config(config, CONFIG_ADDR) || config->addr.s_addr != mess->yiaddr.s_addr))
	    message = "address no longer available";

	  /* Check if a new static address has been configured. Be very sure that
	     when the client does DISCOVER, it will get the static address, otherwise
	     an endless protocol loop will ensue. */

	  else if (have_config(config, CONFIG_ADDR) && !lease_find_by_addr(config->addr))
	    message = "static lease available";

	  /* Check to see if the address is reserved as a static address for another host */
	  else if ((addr_config = config_find_by_address(daemon->dhcp_conf, mess->yiaddr)) && addr_config != config)
	    message ="address reserved";
	}

      log_packet("REQUEST", &mess->yiaddr, mess->chaddr, iface_name, NULL);
      
      if (message)
	{
	  log_packet("NAK", &mess->yiaddr, mess->chaddr, iface_name, message);
	  
	  mess->siaddr.s_addr = mess->yiaddr.s_addr = mess->ciaddr.s_addr = 0;
	  bootp_option_put(mess, NULL, NULL);
	  p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPNAK);
	  p = option_put_string(p, end, OPTION_MESSAGE, message);
	  p = option_end(p, end, mess);
	  mess->flags |= htons(0x8000); /* broadcast */
	  return p - (unsigned char *)mess;
	}
      
      log_packet("ACK", &mess->yiaddr, mess->chaddr, iface_name, hostname);
      
      lease_set_hwaddr(lease, mess->chaddr);
      if (hostname)
	lease_set_hostname(lease, hostname, daemon->domain_suffix);
      lease_set_expires(lease, renewal_time == 0xffffffff ? 0 : now + (time_t)renewal_time);
      
      bootp_option_put(mess, daemon->dhcp_file, daemon->dhcp_sname);
      mess->siaddr = daemon->dhcp_next_server.s_addr ? daemon->dhcp_next_server : iface_addr;
      p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);
      p = option_put(p, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(iface_addr.s_addr));
      p = option_put(p, end, OPTION_LEASE_TIME, 4, renewal_time);
      if (renewal_time != 0xffffffff)
	{
	  p = option_put(p, end, OPTION_T1, 4, (renewal_time/2) - fuzz);
	  p = option_put(p, end, OPTION_T2, 4, ((renewal_time * 7)/8) - fuzz);
	}
      p = do_req_options(context, p, end, req_options, daemon, 
			 hostname, iface_addr, netid, subnet_addr);
      p = option_end(p, end, mess);
      return p - (unsigned char *)mess; 
      
    case DHCPINFORM:
      if (have_config(config, CONFIG_DISABLE))
	message = "ignored";
      
      log_packet("INFORM", &mess->ciaddr, mess->chaddr, iface_name, message);
     
      if (message || mess->ciaddr.s_addr == 0)
	return 0;
      
      p = option_put(p, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);
      p = option_put(p, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(iface_addr.s_addr));
      p = do_req_options(context, p, end, req_options, daemon, 
			 hostname, iface_addr, netid, subnet_addr);
      p = option_end(p, end, mess);
      
      log_packet("ACK", &mess->ciaddr, mess->chaddr, iface_name, hostname);
      return p - (unsigned char *)mess; 
    }
  
  return 0;
}

static void log_packet(char *type, struct in_addr *addr, unsigned char *hwaddr, char *interface, char *string)
{
  syslog(LOG_INFO, "%s%s(%s)%s%s %.2x:%.2x:%.2x:%.2x:%.2x:%.2x%s%s",
	 type ? "DHCP" : "BOOTP",
	 type ? type : "",
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
  if (p + len + 3 < end)
    {
      *(p++) = opt;
      *(p++) = len;
      
      for (i = 0; i < len; i++)
	*(p++) = val >> (8 * (len - (i + 1)));
    }
  return p;
}

static unsigned char *option_end(unsigned char *p, unsigned char *end, struct dhcp_packet *start)
{
  *(p++) = OPTION_END;
  while ((p < end) && (p - ((unsigned char *)start) < MIN_PACKETSZ))
    *p++ = 0;
  
  return p;
}

static unsigned char *option_put_string(unsigned char *p, unsigned char *end, int opt, char *string)
{
  int len = strlen(string);

  if (p + len + 3 < end)
    {
      *(p++) = opt;
      *(p++) = len;
      memcpy(p, string, len);
      p += len;
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
  
  /* skip over DHCP cookie; */
  ret = option_find1(&mess->options[0] + sizeof(u32), ((unsigned char *)mess) + size, opt_type, &overload);
  
  if (!ret && (overload & 1)) 
    ret = option_find1(&mess->file[0], &mess->file[128], opt_type, &overload);

  if (!ret && (overload & 2))
    ret = option_find1(&mess->sname[0], &mess->file[64], opt_type, &overload);

  return ret;
}

static int in_list(unsigned char *list, int opt)
{
  int i;
  
  /* If no requested options, send everything, not nothing. */
  if (!list)
    return 1;
  
  for (i = 0; list[i] != OPTION_END; i++)
    if (opt == list[i])
      return 1;

  return 0;
}

static struct dhcp_opt *option_find2(struct dhcp_netid *netid, struct dhcp_opt *opts, int opt)
{
  struct dhcp_opt *tmp;
  struct dhcp_netid *tmp1;
  
  for (tmp = opts; tmp; tmp = tmp->next)
    if (tmp->opt == opt)
      {
	if (netid)
	  {
	    if (tmp->netid)
	      for (tmp1 = netid; tmp1; tmp1 = tmp1->next)
		if (strcmp(tmp->netid, tmp1->net) == 0)
		  return tmp;
	  }
	else if (!tmp->netid)
	  return tmp;
      }
	      
  return netid ? option_find2(NULL, opts, opt) : NULL;
}

static unsigned char *do_req_options(struct dhcp_context *context,
				     unsigned char *p, unsigned char *end, 
				     unsigned char *req_options,
				     struct daemon *daemon,
				     char *hostname,
				     struct in_addr iface_addr,
				     struct dhcp_netid *netid,
				     struct in_addr subnet_addr)
{
  struct dhcp_opt *opt, *config_opts = daemon->dhcp_opts;

  if (in_list(req_options, OPTION_MAXMESSAGE))
    p = option_put(p, end, OPTION_MAXMESSAGE, 2, end - (unsigned char *)daemon->dhcp_packet);
  
  /* rfc3011 says this doesn't need to be in the requested options list. */
  if (subnet_addr.s_addr)
    p = option_put(p, end, OPTION_SUBNET_SELECT, INADDRSZ, ntohl(subnet_addr.s_addr));

  if (in_list(req_options, OPTION_NETMASK) &&
      !option_find2(netid, config_opts, OPTION_NETMASK))
    p = option_put(p, end, OPTION_NETMASK, INADDRSZ, ntohl(context->netmask.s_addr));
  
  /* May not have a "guessed" broadcast address if we got no packets via a relay
     from this net yet (ie just unicast renewals after a restart */
  if (context->broadcast.s_addr &&
      in_list(req_options, OPTION_BROADCAST) &&
      !option_find2(netid, config_opts, OPTION_BROADCAST))
    p = option_put(p, end, OPTION_BROADCAST, INADDRSZ, ntohl(context->broadcast.s_addr));
  
  /* Same comments as broadcast apply, and also may not be able to get a sensible
     default when using subnet select.  User must configure by steam in that case. */
  if (context->router.s_addr &&
      in_list(req_options, OPTION_ROUTER) &&
      !option_find2(netid, config_opts, OPTION_ROUTER))
    p = option_put(p, end, OPTION_ROUTER, INADDRSZ, ntohl(context->router.s_addr));

  if (in_list(req_options, OPTION_DNSSERVER) &&
      !option_find2(netid, config_opts, OPTION_DNSSERVER))
    p = option_put(p, end, OPTION_DNSSERVER, INADDRSZ, ntohl(iface_addr.s_addr));
  
  if (daemon->domain_suffix && in_list(req_options, OPTION_DOMAINNAME) && 
      !option_find2(netid, config_opts, OPTION_DOMAINNAME))
    p = option_put_string(p, end, OPTION_DOMAINNAME, daemon->domain_suffix);
 
  /* Note that we ignore attempts to set the hostname using 
     --dhcp-option=12,<name> */
  if (hostname && in_list(req_options, OPTION_HOSTNAME))
    p = option_put_string(p, end, OPTION_HOSTNAME, hostname);
  
  for (opt=config_opts; opt; opt = opt->next)
    {
      if (opt->opt == OPTION_HOSTNAME ||
	  opt->opt == OPTION_MAXMESSAGE ||
	  !in_list(req_options, opt->opt) ||
	  opt != option_find2(netid, config_opts, opt->opt) ||
	  p + opt->len + 3 >= end)
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


