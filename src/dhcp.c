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

void dhcp_init(int *fdp, int* rfdp)
{
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  struct sockaddr_in saddr;
  int opt = 1;
  
  if (fd == -1)
    die ("cannot create DHCP socket : %s", NULL);
  
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1 ||
#if defined(IP_PKTINFO)
      setsockopt(fd, SOL_IP, IP_PKTINFO, &opt, sizeof(opt)) == -1 ||
#elif defined(IP_RECVIF)
      setsockopt(fd, IPPROTO_IP, IP_RECVIF, &opt, sizeof(opt)) == -1 ||
#endif
      setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) == -1)  
    die("failed to set options on DHCP socket: %s", NULL);
  
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(DHCP_SERVER_PORT);
  saddr.sin_addr.s_addr = INADDR_ANY;
  if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)))
    die("failed to bind DHCP server socket: %s", NULL);

  *fdp = fd;

#ifdef HAVE_BPF
  opt = 0;
  while (1) 
    {
      char filename[50];
      sprintf(filename, "/dev/bpf%d", opt++);
      if ((fd = open(filename, O_RDWR, 0)) != -1)
	break;
      if (errno != EBUSY)
	die("cannot create DHCP BPF socket: %s", NULL);
    }	    
#else
  if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_IP))) == -1)
    die("cannot create DHCP packet socket: %s", NULL);
#endif
  
  *rfdp = fd;
}

void dhcp_packet(struct dhcp_context *contexts, char *packet, 
		 struct dhcp_opt *dhcp_opts, struct dhcp_config *dhcp_configs, 
		 time_t now, char *namebuff, char *domain_suffix,
		 char *dhcp_file, char *dhcp_sname, 
		 struct in_addr dhcp_next_server, int dhcp_fd, int raw_fd,
		 struct iname *names, struct iname *addrs, struct iname *except)
{
  struct udp_dhcp_packet *rawpacket = (struct udp_dhcp_packet *)packet;
  struct dhcp_packet *mess = (struct dhcp_packet *)&rawpacket->data;
  struct dhcp_context *context;
  struct iname *tmp;
  struct ifreq ifr;
  struct msghdr msg;
  struct iovec iov[2];
  struct cmsghdr *cmptr;
  int sz, newlen, iface_index = 0;
  struct in_addr source, real_netmask, iface_addr, netmask_save, broadcast_save;
#ifdef HAVE_BPF
  unsigned char iface_hwaddr[ETHER_ADDR_LEN];
#endif

  union {
    struct cmsghdr align; /* this ensures alignment */
#ifdef IP_PKTINFO
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#else
    char control[CMSG_SPACE(sizeof(struct sockaddr_dl))];
#endif
  } control_u;
  
  iov[0].iov_base = (char *)&rawpacket->data;
  iov[0].iov_len = DNSMASQ_PACKETSZ - (sizeof(struct ip) + sizeof(struct udphdr));

  msg.msg_control = control_u.control;
  msg.msg_controllen = sizeof(control_u);
  msg.msg_flags = 0;
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  
  sz = recvmsg(dhcp_fd, &msg, 0);
  
  if (sz < (int)(sizeof(*mess) - sizeof(mess->options)))
    return;
  
#if defined (IP_PKTINFO)
  if (msg.msg_controllen < sizeof(struct cmsghdr))
    return;
  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
    if (cmptr->cmsg_level == SOL_IP && cmptr->cmsg_type == IP_PKTINFO)
      iface_index = ((struct in_pktinfo *)CMSG_DATA(cmptr))->ipi_ifindex;
  
  if (!iface_index || !if_indextoname(iface_index, ifr.ifr_name))
    return;

#elif defined(IP_RECVIF)
  if (msg.msg_controllen < sizeof(struct cmsghdr))
    return;
  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
    if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
      iface_index = ((struct sockaddr_dl *)CMSG_DATA(cmptr))->sdl_index;
  
  if (!iface_index || !if_indextoname(iface_index, ifr.ifr_name))
    return;

#else
  if (!names || !names->name || names->next)
    {
      syslog(LOG_ERR, "must set exactly one interface on broken systems without IP_RECVIF");
      return;
    }
  else
    strcpy(ifr.ifr_name, names->name);
#endif

#ifdef HAVE_BPF
  ifr.ifr_addr.sa_family = AF_LINK;
  if (ioctl(dhcp_fd, SIOCGIFADDR, &ifr) < 0)
    return;
  memcpy(iface_hwaddr, LLADDR((struct sockaddr_dl *)&ifr.ifr_addr), ETHER_ADDR_LEN);
#endif
  
  ifr.ifr_addr.sa_family = AF_INET;
  if (ioctl(dhcp_fd, SIOCGIFADDR, &ifr) < 0 )
    return;
  iface_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

  /* enforce available interface configuration */
  for (tmp = except; tmp; tmp = tmp->next)
    if (tmp->name && (strcmp(tmp->name, ifr.ifr_name) == 0))
      return;
  
  if (names || addrs)
    {
      for (tmp = names; tmp; tmp = tmp->next)
	if (tmp->name && (strcmp(tmp->name, ifr.ifr_name) == 0))
	  break;
      if (!tmp)
	for (tmp = addrs; tmp; tmp = tmp->next)
	  if (tmp->addr.sa.sa_family == AF_INET && 
	      tmp->addr.in.sin_addr.s_addr == iface_addr.s_addr)
	    break;
      if (!tmp)
	return; 
    }
  
  /* If the packet came via a relay, use that address to look up the context,
     else use the address of the interface is arrived on. */
   source = mess->giaddr.s_addr ? mess->giaddr : iface_addr;

   for (context = contexts; context; context = context->next)
    {
      if (!context->netmask.s_addr && !mess->giaddr.s_addr && ioctl(dhcp_fd, SIOCGIFNETMASK, &ifr) != -1)
	real_netmask = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
      else
	real_netmask = context->netmask;
      
      if (real_netmask.s_addr && 
	  (source.s_addr & real_netmask.s_addr) == (context->start.s_addr & real_netmask.s_addr) &&
	  (source.s_addr & real_netmask.s_addr) == (context->end.s_addr & real_netmask.s_addr))
	break;
    }
      
  if (!context)
    {
      syslog(LOG_WARNING, "no address range available for DHCP request via %s", inet_ntoa(source));
      return;
    }
  
  netmask_save = context->netmask;
  broadcast_save = context->broadcast;
  
  context->netmask = real_netmask;
  
  if (!context->broadcast.s_addr)
    {
      if (mess->giaddr.s_addr)
	context->broadcast.s_addr = (mess->giaddr.s_addr & real_netmask.s_addr) | ~real_netmask.s_addr;
      else if (ioctl(dhcp_fd, SIOCGIFBRDADDR, &ifr) != -1)
	context->broadcast = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
      else
	context->broadcast.s_addr = (iface_addr.s_addr & real_netmask.s_addr) | ~real_netmask.s_addr;
    }
  
  if (ioctl(dhcp_fd, SIOCGIFMTU, &ifr) == -1)
   ifr.ifr_mtu = ETHERMTU;
  
  lease_prune(NULL, now); /* lose any expired leases */
  newlen = dhcp_reply(context, iface_addr, ifr.ifr_name, ifr.ifr_mtu, 
		      rawpacket, sz, now, namebuff, 
		      dhcp_opts, dhcp_configs, domain_suffix, dhcp_file,
		      dhcp_sname, dhcp_next_server);
  lease_update_file(0, now);
  lease_update_dns();
	  
  context->netmask = netmask_save;
  context->broadcast = broadcast_save;
  
  if (newlen == 0)
    return;
  
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
      
      sendto(dhcp_fd, mess, newlen, 0, (struct sockaddr *)&dest, sizeof(dest));
    }
  else
    {
      /* Hairy stuff, packet either has to go to the
	 net broadcast or the destination can't reply to ARP yet,
	 but we do know the physical address. 
	 Build the packet by steam, and send directly, bypassing
	 the kernel IP stack */
      
      u32 i, sum;
      unsigned char hwdest[ETHER_ADDR_LEN];
      
      if (ntohs(mess->flags) & 0x8000)
	{
	  memset(hwdest, 255,  ETHER_ADDR_LEN);
	  rawpacket->ip.ip_dst.s_addr = INADDR_BROADCAST;
	}
      else
	{
	  memcpy(hwdest, mess->chaddr, ETHER_ADDR_LEN); 
	  rawpacket->ip.ip_dst.s_addr = mess->yiaddr.s_addr;
	}
      
      rawpacket->ip.ip_p = IPPROTO_UDP;
      rawpacket->ip.ip_src.s_addr = iface_addr.s_addr;
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
      
      { 
#ifdef HAVE_BPF
	struct ether_header header;
	
	header.ether_type = htons(ETHERTYPE_IP);
	memcpy(header.ether_shost, iface_hwaddr, ETHER_ADDR_LEN);
	memcpy(header.ether_dhost, hwdest, ETHER_ADDR_LEN); 
	
	ioctl(raw_fd, BIOCSETIF, &ifr);
	
	iov[0].iov_base = (char *)&header;
	iov[0].iov_len = sizeof(struct ether_header);
	iov[1].iov_base = (char *)rawpacket;
	iov[1].iov_len = ntohs(rawpacket->ip.ip_len);
	writev(raw_fd, iov, 2);
#else
	struct sockaddr_ll dest;
	
	dest.sll_family = AF_PACKET;
	dest.sll_halen =  ETHER_ADDR_LEN;
	dest.sll_ifindex = iface_index;
	dest.sll_protocol = htons(ETHERTYPE_IP);
	memcpy(dest.sll_addr, hwdest, ETHER_ADDR_LEN); 
	sendto(raw_fd, rawpacket, ntohs(rawpacket->ip.ip_len), 
	       0, (struct sockaddr *)&dest, sizeof(dest));
	
#endif
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
      if (config->hostname && hostname_isequal(config->hostname, hostname) &&
	  is_addr_in_context(context, config))
	return config;
  
  return NULL;
}

struct dhcp_config *dhcp_read_ethers(struct dhcp_config *configs, char *buff)
{
  FILE *f = fopen(ETHERSFILE, "r");
  unsigned int e0, e1, e2, e3, e4, e5;
  char *ip, *cp, *name;
  struct in_addr addr;
  struct dhcp_config *config;
  
  if (!f)
    die("failed to open " ETHERSFILE ":%s", NULL);
  
  while (fgets(buff, MAXDNAME, f))
    {
      while (strlen(buff) > 0 && 
	     (buff[strlen(buff)-1] == '\n' || 
	      buff[strlen(buff)-1] == ' ' || 
	      buff[strlen(buff)-1] == '\r' || 
	      buff[strlen(buff)-1] == '\t'))
	buff[strlen(buff)-1] = 0;
      
      if ((*buff == '#') || (*buff == '+'))
	continue;
      
      for (ip = buff; *ip && *ip != ' ' && *ip != '\t'; ip++);
      for(; *ip && (*ip == ' ' || *ip == '\t'); ip++)
	*ip = 0;
      if (!*ip)
	continue;
      
      if (!sscanf(buff, "%x:%x:%x:%x:%x:%x", &e0, &e1, &e2, &e3, &e4, &e5))
	continue;
      
      /* check for name or dotted-quad */
      for (cp = ip; *cp; cp++)
	if (!(*cp == '.' || (*cp >='0' && *cp <= '9')))
	  break;
      
      if (!*cp)
	{
	  name = NULL;
	  if ((addr.s_addr = inet_addr(ip)) == (in_addr_t)-1)
	    continue;
	  
	  for (config = configs; config; config = config->next)
	    if (config->addr.s_addr == addr.s_addr)
	      break;
	}
      else 
	{
	  if (!canonicalise(ip))
	    continue;
	  name = ip;
	  addr.s_addr = 0;

	  for (config = configs; config; config = config->next)
	    if (config->hostname && hostname_isequal(config->hostname, name))
	      break;
	}
      
      if (!config)
	{ 
	  config = safe_malloc(sizeof(struct dhcp_config));
	  config->clid_len = 0;
	  config->clid = NULL; 
	  config->lease_time = 0;
	  config->hostname = safe_string_alloc(name);
	  config->addr = addr;
	  config->next = configs;
	  configs = config;
	}

      config->hwaddr[0] = e0;
      config->hwaddr[1] = e1;
      config->hwaddr[2] = e2;
      config->hwaddr[3] = e3;
      config->hwaddr[4] = e4;
      config->hwaddr[5] = e5;
    }
  
  fclose(f);
  return configs;
}

void dhcp_update_configs(struct dhcp_config *configs)
{
  /* Some people like to keep all static IP addresses in /etc/hosts.
     This goes through /etc/hosts and sets static addresses for any DHCP config
     records which don't have an address and whose name matches. */
  
  struct dhcp_config *config;
  struct crec *crec;
  
  for (config = configs; config; config = config->next)
    if (config->addr.s_addr == 0 && config->hostname && 
	(crec = cache_find_by_name(NULL, config->hostname, 0, F_IPV4)) &&
	(crec->flags & F_HOSTS))
      config->addr = crec->addr.addr.addr4;
  
}

