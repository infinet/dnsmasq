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

void dhcp_init(struct daemon *daemon)
{
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  struct sockaddr_in saddr;
  int oneopt = 1, zeroopt = 0;
  struct dhcp_config *configs, *cp;

  if (fd == -1)
    die ("cannot create DHCP socket : %s", NULL);
  
  if (
#if defined(IP_PKTINFO)
      setsockopt(fd, SOL_IP, IP_PKTINFO, &oneopt, sizeof(oneopt)) == -1 ||
#elif defined(IP_RECVIF)
      setsockopt(fd, IPPROTO_IP, IP_RECVIF, &oneopt, sizeof(oneopt)) == -1 ||
#endif
      setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &oneopt, sizeof(oneopt)) == -1)  
    die("failed to set options on DHCP socket: %s", NULL);
  
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(DHCP_SERVER_PORT);
  saddr.sin_addr.s_addr = INADDR_ANY;
#ifdef HAVE_SOCKADDR_SA_LEN
  saddr.sin_len = sizeof(struct sockaddr_in);
#endif

  if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)))
    die("failed to bind DHCP server socket: %s", NULL);

  daemon->dhcpfd = fd;

  if ((fd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ||
      setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) ||
      setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1)
    die("cannot create ICMP raw socket: %s.", NULL);

  daemon->dhcp_icmp_fd = fd;

#ifdef HAVE_BPF
  { 
    int i = 0;
    while (1) 
      {
	char filename[50];
	sprintf(filename, "/dev/bpf%d", i++);
	if ((fd = open(filename, O_RDWR, 0)) != -1)
	  break;
	if (errno != EBUSY)
	  die("cannot create DHCP BPF socket: %s", NULL);
      }	    
  }
#else
  /* since we don't ever use the packet socket for reception,
     and it receives copies of _all_ IP packets, then that data
     will build up in kernel buffers, wasting memory. Set the
     socket receive buffer size to one to avoid that. (zero is
     rejected as non-sensical by some BSD kernels) */
  if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_IP))) == -1 ||
      setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) == -1)
    die("cannot create DHCP packet socket: %s. "
	"Is CONFIG_PACKET enabled in your kernel?", NULL);
#endif
  
  daemon->dhcp_raw_fd = fd;
  
  /* If the same IP appears in more than one host config, then DISCOVER
     for one of the hosts will get the address, but REQUEST will be NAKed,
     since the address is reserved by the other one -> protocol loop. */
  for (configs = daemon->dhcp_conf; configs; configs = configs->next)
    for (cp = configs->next; cp; cp = cp->next)
      if ((configs->flags & cp->flags & CONFIG_ADDR) &&	configs->addr.s_addr == cp->addr.s_addr)
	die("duplicate IP address %s in dhcp-config directive.", inet_ntoa(cp->addr));
  
  daemon->dhcp_packet = safe_malloc(sizeof(struct udp_dhcp_packet));
  /* These two each hold a DHCP option max size 256 
     and get a terminating zero added */
  daemon->dhcp_buff = safe_malloc(257);
  daemon->dhcp_buff2 = safe_malloc(257); 

}

void dhcp_packet(struct daemon *daemon, time_t now)
{
  struct udp_dhcp_packet *rawpacket = daemon->dhcp_packet;
  struct dhcp_packet *mess = &rawpacket->data;
  struct dhcp_context *context;
  struct iname *tmp;
  struct ifreq ifr;
  struct msghdr msg;
  struct iovec iov[2];
  struct cmsghdr *cmptr;
  int sz, newlen, iface_index = 0;
  struct in_addr iface_netmask, iface_addr, iface_broadcast;
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
  
  iov[0].iov_base = (char *)mess;
  iov[0].iov_len = sizeof(struct dhcp_packet);

  msg.msg_control = control_u.control;
  msg.msg_controllen = sizeof(control_u);
  msg.msg_flags = 0;
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  
  sz = recvmsg(daemon->dhcpfd, &msg, 0);
  
  if (sz < (int)(sizeof(*mess) - sizeof(mess->options)))
    return;
  
#if defined (IP_PKTINFO)
  if (msg.msg_controllen < sizeof(struct cmsghdr))
    return;
  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
    if (cmptr->cmsg_level == SOL_IP && cmptr->cmsg_type == IP_PKTINFO)
      iface_index = ((struct in_pktinfo *)CMSG_DATA(cmptr))->ipi_ifindex;
  
  if (!(ifr.ifr_ifindex = iface_index) || 
      ioctl(daemon->dhcpfd, SIOCGIFNAME, &ifr) == -1)
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
  {
    struct iname *name;
    for (name = daemon->if_names; names->isloop; names = names->next);
    strcpy(ifr.ifr_name, name->name);
  }
#endif

#ifdef HAVE_BPF
  ifr.ifr_addr.sa_family = AF_LINK;
  if (ioctl(daemon->dhcpfd, SIOCGIFADDR, &ifr) < 0)
    return;
  memcpy(iface_hwaddr, LLADDR((struct sockaddr_dl *)&ifr.ifr_addr), ETHER_ADDR_LEN);
#endif
  
  ifr.ifr_addr.sa_family = AF_INET;
  if (ioctl(daemon->dhcpfd, SIOCGIFADDR, &ifr) < 0 )
    return;
  iface_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

  /* enforce available interface configuration */
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
	  if (tmp->addr.sa.sa_family == AF_INET && 
	      tmp->addr.in.sin_addr.s_addr == iface_addr.s_addr)
	    break;
      if (!tmp)
	return; 
    }
  
  iface_netmask.s_addr = 0;
  iface_broadcast.s_addr = 0;
  
  for (context = daemon->dhcp; context; context = context->next)
    {
      /* Fill in missing netmask and broadcast address values for any approriate
	 dhcp-ranges which match this interface and don't have them. */
      if (!context->netmask.s_addr)
	{
	  if (!iface_netmask.s_addr && ioctl(daemon->dhcpfd, SIOCGIFNETMASK, &ifr) != -1)
	    iface_netmask = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
	  
	  if (iface_netmask.s_addr &&
	      (is_same_net(iface_addr, context->start, iface_netmask) ||
	       is_same_net(iface_addr, context->end, iface_netmask)))
	    {
	      context->netmask = iface_netmask; 
	      if (!(is_same_net(iface_addr, context->start, iface_netmask) &&
		    is_same_net(iface_addr, context->end, iface_netmask)))
		{
		   strcpy(daemon->dhcp_buff, inet_ntoa(context->start));
		   strcpy(daemon->dhcp_buff2, inet_ntoa(context->end));
		   syslog(LOG_WARNING, "DHCP range %s -- %s is not consistent with netmask %s",
			  daemon->dhcp_buff, daemon->dhcp_buff2, inet_ntoa(iface_netmask));
		}
	    }
	}    
	 
      /* Determine "default" default routes. These are to this server or the relay agent.
	 Also broadcast addresses, if not specified */
      if (context->netmask.s_addr)
	{
	  if (is_same_net(iface_addr, context->start, context->netmask))
	    {
	      if (!context->router.s_addr)
		context->router = iface_addr;
	      if (!context->broadcast.s_addr)
		{
		  if (!iface_broadcast.s_addr && ioctl(daemon->dhcpfd, SIOCGIFBRDADDR, &ifr) != -1)
		    iface_broadcast = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
		  if (iface_broadcast.s_addr && 
		      is_same_net(iface_broadcast, context->start, context->netmask))
		    context->broadcast = iface_broadcast;
		  else 
		    context->broadcast.s_addr  = context->start.s_addr | ~context->netmask.s_addr;
		}
	    }	
	  else if (mess->giaddr.s_addr && is_same_net(mess->giaddr, context->start, context->netmask))
	    {
	      if (!context->router.s_addr)
		context->router = mess->giaddr;
	      /* fill in missing broadcast addresses for relayed ranges */
	      if (!context->broadcast.s_addr)
		context->broadcast.s_addr  = context->start.s_addr | ~context->netmask.s_addr;
	    }
	}
    }
  
  lease_prune(NULL, now); /* lose any expired leases */
  newlen = dhcp_reply(daemon, iface_addr, ifr.ifr_name, sz, now);
  lease_update_file(0, now);
  lease_update_dns();
  
  if (newlen == 0)
    return;
  
  if (mess->giaddr.s_addr || mess->ciaddr.s_addr)
    {
      /* To send to BOOTP relay or configured client, use the IP packet */
      
      struct sockaddr_in dest;
      dest.sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_SA_LEN
      dest.sin_len = sizeof(struct sockaddr_in);
#endif
     
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
      
      sendto(daemon->dhcpfd, mess, newlen, 0, (struct sockaddr *)&dest, sizeof(dest));
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
	
	ioctl(daemon->dhcp_raw_fd, BIOCSETIF, &ifr);
	
	iov[0].iov_base = (char *)&header;
	iov[0].iov_len = sizeof(struct ether_header);
	iov[1].iov_base = (char *)rawpacket;
	iov[1].iov_len = ntohs(rawpacket->ip.ip_len);
	writev(daemon->dhcp_raw_fd, iov, 2);
#else
	struct sockaddr_ll dest;
	
	dest.sll_family = AF_PACKET;
	dest.sll_halen =  ETHER_ADDR_LEN;
	dest.sll_ifindex = iface_index;
	dest.sll_protocol = htons(ETHERTYPE_IP);
	memcpy(dest.sll_addr, hwdest, ETHER_ADDR_LEN); 
	sendto(daemon->dhcp_raw_fd, rawpacket, ntohs(rawpacket->ip.ip_len), 
	       0, (struct sockaddr *)&dest, sizeof(dest));
	
#endif
      }
    }
}

int address_available(struct dhcp_context *context, struct in_addr taddr)
{
  /* Check is an address is OK for this network, check all
     possible ranges. */
  
  unsigned int start, end, addr = ntohl(taddr.s_addr);
  
  for (; context; context = context->current)
    {
      start = ntohl(context->start.s_addr);
      end = ntohl(context->end.s_addr);

      if (!context->static_only &&
	  addr >= start &&
	  addr <= end)
	return 1;
    }

  return 0;
}
 
struct dhcp_config *config_find_by_address(struct dhcp_config *configs, struct in_addr addr)
{
  struct dhcp_config *config;
  
  for (config = configs; config; config = config->next)
    if ((config->flags & CONFIG_ADDR) && config->addr.s_addr == addr.s_addr)
      return config;

  return NULL;
}

int address_allocate(struct dhcp_context *context, struct daemon *daemon,
		     struct in_addr *addrp, unsigned char *hwaddr)   
{
  /* Find a free address: exclude anything in use and anything allocated to
     a particular hwaddr/clientid/hostname in our configuration */

  struct in_addr start, addr ;
  unsigned int i, j;
  
  for (; context; context = context->current)
    if (!context->static_only)
      {
	/* pick a seed based on hwaddr then iterate until we find a free address. */
	for (j = context->addr_epoch, i = 0; i < ETHER_ADDR_LEN; i++)
	  j += hwaddr[i] + (hwaddr[i] << 8) + (hwaddr[i] << 16);
	
	start.s_addr = addr.s_addr = 
	  htonl(ntohl(context->start.s_addr) + 
		(j % (1 + ntohl(context->end.s_addr) - ntohl(context->start.s_addr))));
	
	do {
	  if (!lease_find_by_addr(addr) && 
	      !config_find_by_address(daemon->dhcp_conf, addr))
	    {
	      if (icmp_ping(daemon, addr))
		/* perturb address selection so that we are
		   less likely to try this address again. */
		context->addr_epoch++;
	      else
		{
		  *addrp = addr;
		  return 1;
		}
	    }

	  addr.s_addr = htonl(ntohl(addr.s_addr) + 1);
	  
	  if (addr.s_addr == htonl(ntohl(context->end.s_addr) + 1))
	    addr = context->start;
	  
	} while (addr.s_addr != start.s_addr);
      }
  return 0;
}

static int is_addr_in_context(struct dhcp_context *context, struct dhcp_config *config)
{
  if (!context)
    return 1;
  if (!(config->flags & CONFIG_ADDR))
    return 1;
  if (is_same_net(config->addr, context->start, context->netmask))
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
      if (config->flags & CONFIG_CLID)
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
    if ((config->flags & CONFIG_HWADDR) &&
	memcmp(config->hwaddr, hwaddr, ETHER_ADDR_LEN) == 0 &&
	is_addr_in_context(context, config))
      return config;
  
  if (hostname)
    for (config = configs; config; config = config->next)
      if ((config->flags & CONFIG_NAME) && 
	  hostname_isequal(config->hostname, hostname) &&
	  is_addr_in_context(context, config))
	return config;
  
  return NULL;
}

void dhcp_read_ethers(struct daemon *daemon)
{
  FILE *f = fopen(ETHERSFILE, "r");
  unsigned int flags, e0, e1, e2, e3, e4, e5;
  char *buff = daemon->namebuff;
  char *ip, *cp;
  struct in_addr addr;
  unsigned char hwaddr[ETHER_ADDR_LEN];
  struct dhcp_config *config, *configs = daemon->dhcp_conf;
  int count = 0;
  
  if (!f)
    {
      syslog(LOG_ERR, "failed to read " ETHERSFILE ":%m");
      return;
    }

  while (fgets(buff, MAXDNAME, f))
    {
      while (strlen(buff) > 0 && isspace(buff[strlen(buff)-1]))
	buff[strlen(buff)-1] = 0;
      
      if ((*buff == '#') || (*buff == '+'))
	continue;
      
      for (ip = buff; *ip && !isspace(*ip); ip++);
      for(; *ip && isspace(*ip); ip++)
	*ip = 0;
      if (!*ip)
	continue;
      
      if (!sscanf(buff, "%x:%x:%x:%x:%x:%x", &e0, &e1, &e2, &e3, &e4, &e5))
	continue;
      
      hwaddr[0] = e0;
      hwaddr[1] = e1;
      hwaddr[2] = e2;
      hwaddr[3] = e3;
      hwaddr[4] = e4;
      hwaddr[5] = e5;

      /* check for name or dotted-quad */
      for (cp = ip; *cp; cp++)
	if (!(*cp == '.' || (*cp >='0' && *cp <= '9')))
	  break;
      
      if (!*cp)
	{
	  if ((addr.s_addr = inet_addr(ip)) == (in_addr_t)-1)
	    continue;
	  flags = CONFIG_ADDR;
	  
	  for (config = configs; config; config = config->next)
	    if ((config->flags & CONFIG_ADDR) && config->addr.s_addr == addr.s_addr)
	      break;
	}
      else 
	{
	  if (!canonicalise(ip))
	    continue;
	  flags = CONFIG_NAME;

	  for (config = configs; config; config = config->next)
	    if ((config->flags & CONFIG_NAME) && hostname_isequal(config->hostname, ip))
	      break;
	}
      
      if (!config)
	{ 
	  for (config = configs; config; config = config->next)
	    if ((config->flags & CONFIG_HWADDR) && 
		memcmp(config->hwaddr, hwaddr, ETHER_ADDR_LEN) == 0)
	      break;
	  
	  if (!config)
	    {
	      if (!(config = malloc(sizeof(struct dhcp_config))))
		continue;
	      config->flags = 0;
	      config->next = configs;
	      configs = config;
	    }
	  
	  config->flags |= flags;
	  
	  if (flags & CONFIG_NAME)
	    {
	      if ((config->hostname = malloc(strlen(ip)+1)))
		strcpy(config->hostname, ip);
	      else
		config->flags &= ~CONFIG_NAME;
	    }
	  
	  if (flags & CONFIG_ADDR)
	    config->addr = addr;
	}
      
      config->flags |= CONFIG_HWADDR | CONFIG_NOCLID;
      memcpy(config->hwaddr, hwaddr, ETHER_ADDR_LEN);

      count++;
    }
  
  fclose(f);

  syslog(LOG_INFO, "read " ETHERSFILE " - %d addresses", count);
  
  daemon->dhcp_conf =  configs;
}

void dhcp_update_configs(struct dhcp_config *configs)
{
  /* Some people like to keep all static IP addresses in /etc/hosts.
     This goes through /etc/hosts and sets static addresses for any DHCP config
     records which don't have an address and whose name matches. */
  
  struct dhcp_config *config;
  struct crec *crec;
  
  for (config = configs; config; config = config->next)
    if (!(config->flags & CONFIG_ADDR) &&
	(config->flags & CONFIG_NAME) && 
	(crec = cache_find_by_name(NULL, config->hostname, 0, F_IPV4)) &&
	(crec->flags & F_HOSTS))
      {
	config->addr = crec->addr.addr.addr4;
	config->flags |= CONFIG_ADDR;
      }
}

