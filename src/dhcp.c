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

void dhcp_packet(struct dhcp_context *context, char *packet, 
		 struct dhcp_opt *dhcp_opts, struct dhcp_config *dhcp_configs, 
		 time_t now, char *namebuff, char *domain_suffix,
		 char *dhcp_file, char *dhcp_sname, 
		 struct in_addr dhcp_next_server)
{
  struct udp_dhcp_packet *rawpacket = (struct udp_dhcp_packet *) packet;
  struct dhcp_packet *mess = (struct dhcp_packet *)&rawpacket->data;
  int sz, newlen;

  sz = recvfrom(context->fd, &rawpacket->data, 
		PACKETSZ - (sizeof(struct ip) + sizeof(struct udphdr)),
		0, NULL, 0);
  if ((unsigned int)sz > (sizeof(*mess) - sizeof(mess->options)))
    {
      lease_prune(NULL, now); /* lose any expired leases */
      newlen = dhcp_reply(context, mess, sz, now, namebuff, dhcp_opts, 
			  dhcp_configs, domain_suffix, dhcp_file,
			  dhcp_sname, dhcp_next_server );
      lease_update_dns(0);
	  
      if (newlen != 0)
	{
	  int broadcast = ntohs(mess->flags) & 0x8000;
	  
	  /* newlen -ve forces broadcast */
	  if (newlen < 0)
	    {
	      broadcast = 1;
	      newlen = -newlen;
	    }
	  
	  if (mess->giaddr.s_addr || mess->ciaddr.s_addr)
	    {
	      /* To send to BOOTP relay or configured client, use 
		 the IP packet */
	      
	      struct sockaddr_in dest;
	      dest.sin_family = AF_INET;
	      
	      if (mess->giaddr.s_addr)
		{
		  dest.sin_port = htons(DHCP_SERVER_PORT);
		  dest.sin_addr = mess->giaddr; 
		}
	      else
		{
		  dest.sin_port = htons(DHCP_CLIENT_PORT);
		  dest.sin_addr = mess->ciaddr;
		}
	      
	      sendto(context->fd, mess, newlen, 0, (struct sockaddr *)&dest, sizeof(dest));
	    }
	  else
	    {
	      /* Hairy stuff, packet either has to go to the
		 net broadcast or the destination can't reply to ARP yet,
		 but we do know the physical address. 
		 Build the packet by steam, and send directly, bypassing
		 the kernel IP stack */
	      
	      u32 i, sum;
#ifdef HAVE_PF_PACKET
	      struct sockaddr_ll dest;
	      
	      dest.sll_family = AF_PACKET;
	      dest.sll_halen =  ETHER_ADDR_LEN;
	      dest.sll_ifindex = context->ifindex;
	      dest.sll_protocol = htons(ETHERTYPE_IP);
	      
	      if (broadcast)
		{
		  memset(dest.sll_addr, 255,  ETHER_ADDR_LEN);
		  rawpacket->ip.ip_dst.s_addr = INADDR_BROADCAST;
		}
	      else
		{
		  memcpy(dest.sll_addr, mess->chaddr, ETHER_ADDR_LEN); 
		  rawpacket->ip.ip_dst.s_addr = mess->yiaddr.s_addr;
		}
#endif

#ifdef HAVE_BPF	      
	      struct ether_header header;
	      struct iovec iov [2];

	      header.ether_type = htons(ETHERTYPE_IP);
	      memcpy(header.ether_shost, context->hwaddr, ETHER_ADDR_LEN);
	      
	      if (broadcast)
		{
		  memset(header.ether_dhost, 255, ETHER_ADDR_LEN);
		  rawpacket->ip.ip_dst.s_addr = INADDR_BROADCAST;
		}
	      else
		{
		  memcpy(header.ether_dhost, mess->chaddr, ETHER_ADDR_LEN); 
		  rawpacket->ip.ip_dst.s_addr = mess->yiaddr.s_addr;
		}
#endif

	      rawpacket->ip.ip_p = IPPROTO_UDP;
	      rawpacket->ip.ip_src.s_addr = context->serv_addr.s_addr;
	      rawpacket->ip.ip_len = htons(sizeof(struct ip) + 
					    sizeof(struct udphdr) +
					    newlen) ;
	      rawpacket->ip.ip_hl = sizeof(struct ip) / 4;
	      rawpacket->ip.ip_v = IPVERSION;
	      rawpacket->ip.ip_tos = 0;
	      rawpacket->ip.ip_id = htons(0);
	      rawpacket->ip.ip_off = htons(0x4000); /* don't fragment */
	      rawpacket->ip.ip_ttl = IPDEFTTL;
	      rawpacket->ip.ip_sum = 0;
	      for (sum = 0, i = 0; i < sizeof(struct ip) / 2; i++)
		sum += ((u16 *)&rawpacket->ip)[i];
	      while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);  
	      rawpacket->ip.ip_sum = (sum == 0xffff) ? sum : ~sum;
	      
	      rawpacket->udp.uh_sport = htons(DHCP_SERVER_PORT);
	      rawpacket->udp.uh_dport = htons(DHCP_CLIENT_PORT);
	      ((u8 *)&rawpacket->data)[newlen] = 0; /* for checksum, in case length is odd. */
	      rawpacket->udp.uh_sum = 0;
	      rawpacket->udp.uh_ulen = sum = htons(sizeof(struct udphdr) + newlen);
	      sum += htons(IPPROTO_UDP);
	      for (i = 0; i < 4; i++)
		sum += ((u16 *)&rawpacket->ip.ip_src)[i];
	      for (i = 0; i < (sizeof(struct udphdr) + newlen + 1) / 2; i++)
		sum += ((u16 *)&rawpacket->udp)[i];
	      while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	      rawpacket->udp.uh_sum = (sum == 0xffff) ? sum : ~sum;

#ifdef HAVE_PF_PACKET	      
	      sendto(context->rawfd, rawpacket, ntohs(rawpacket->ip.ip_len), 
		     0, (struct sockaddr *)&dest, sizeof(dest));
#endif

#ifdef HAVE_BPF
	      iov[0].iov_base = (char *)&header;
	      iov[0].iov_len = sizeof(struct ether_header);
	      iov[1].iov_base = (char *)rawpacket;
	      iov[1].iov_len = ntohs(rawpacket->ip.ip_len);
	      writev(context->rawfd, iov, 2);
#endif	      
	    }
	}
    }
}

int address_available(struct dhcp_context *context, struct in_addr taddr)
{
  /* Check is an address is OK for this network, ie
     within allowable range and not in an existing lease */
  
  unsigned int addr, start, end;
  
  addr = ntohl(taddr.s_addr);
  start = ntohl(context->start.s_addr);
  end = ntohl(context->end.s_addr);

  if (addr < start)
    return 0;

  if (addr > end)
    return 0;

  if (lease_find_by_addr(taddr))
    return 0;
  
  return 1;
}

int address_allocate(struct dhcp_context *context, struct dhcp_config *configs,
		     struct in_addr *addrp)   
{
  /* Find a free address: exlude anything in use and anything allocated to
     a particular hwaddr/clientid/hostname in our configuration */

  struct dhcp_config *config;
  struct in_addr start = context->last;
  
  do {
    if (context->last.s_addr == context->end.s_addr)
      context->last = context->start;
    else
      context->last.s_addr = htonl(ntohl(context->last.s_addr) + 1);

    
    if (!lease_find_by_addr(context->last))
      {
	for (config = configs; config; config = config->next)
	  if (config->addr.s_addr == context->last.s_addr)
	    break;
	
	if (!config)
	  {
	    *addrp = context->last;
	    return 1;
	  }
      }
  } while (context->last.s_addr != start.s_addr);
  
  return 0;
}

static int is_addr_in_context(struct dhcp_context *context, struct dhcp_config *config)
{
  if (!context)
    return 1;
  if (config->addr.s_addr == 0)
    return 1;
  if ((config->addr.s_addr & context->netmask.s_addr) == (context->start.s_addr & context->netmask.s_addr))
    return 1;
  
  return 0;
}

struct dhcp_config *find_config(struct dhcp_config *configs,
				struct dhcp_context *context,
				unsigned char *clid, int clid_len,
				unsigned char *hwaddr, char *hostname)
{
  struct dhcp_config *config; 
  
  if (clid_len)
    for (config = configs; config; config = config->next)
      {
	if (config->clid_len == clid_len && 
	    memcmp(config->clid, clid, clid_len) == 0 &&
	    is_addr_in_context(context, config))
	  return config;
	
	/* dhcpcd prefixes ASCII client IDs by zero which is wrong, but we try and
	   cope with that here */
	if (*clid == 0 && config->clid_len == clid_len-1  &&
	    memcmp(config->clid, clid+1, clid_len-1) == 0 &&
	    is_addr_in_context(context, config))
	  return config;
      }
    
  for (config = configs; config; config = config->next)
    if (memcmp(config->hwaddr, hwaddr, ETHER_ADDR_LEN) == 0 &&
	is_addr_in_context(context, config))
      return config;
  
  if (hostname)
    for (config = configs; config; config = config->next)
      if (config->hostname && strcmp(config->hostname, hostname) == 0 &&
	  is_addr_in_context(context, config))
	return config;
  
  return NULL;
}

      
    
