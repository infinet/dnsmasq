/* dnsmasq is Copyright (c) 2000-2015 Simon Kelley

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

#define ARP_FREE  0
#define ARP_FOUND 1
#define ARP_NEW   2
#define ARP_EMPTY 3

struct arp_record {
  short hwlen, status;
  int family;
  unsigned char hwaddr[DHCP_CHADDR_MAX]; 
  struct all_addr addr;
  struct arp_record *next;
};

static struct arp_record *arps = NULL, *old = NULL;

static int filter_mac(int family, char *addrp, char *mac, size_t maclen, void *parmv)
{
  int match = 0;
  struct arp_record *arp;

  if (maclen > DHCP_CHADDR_MAX)
    return 1;

  /* Look for existing entry */
  for (arp = arps; arp; arp = arp->next)
    {
      if (family != arp->family || arp->status == ARP_NEW)
	continue;
      
      if (family == AF_INET)
	{
	  if (arp->addr.addr.addr4.s_addr != ((struct in_addr *)addrp)->s_addr)
	    continue;
	}
#ifdef HAVE_IPV6
      else
	{
	  if (!IN6_ARE_ADDR_EQUAL(&arp->addr.addr.addr6, (struct in6_addr *)addrp))
	    continue;
	}
#endif

      if (arp->status != ARP_EMPTY && arp->hwlen == maclen && memcmp(arp->hwaddr, mac, maclen) == 0)
	arp->status = ARP_FOUND;
      else
	{
	  /* existing address, MAC changed or arrived new. */
	  arp->status = ARP_NEW;
	  arp->hwlen = maclen;
	  arp->family = family;
	  memcpy(arp->hwaddr, mac, maclen);
	}
      
      break;
    }

  if (!arp)
    {
      /* New entry */
      if (old)
	{
	  arp = old;
	  old = old->next;
	}
      else if (!(arp = whine_malloc(sizeof(struct arp_record))))
	return 1;
      
      arp->next = arps;
      arps = arp;
      arp->status = ARP_NEW;
      arp->hwlen = maclen;
      arp->family = family;
      memcpy(arp->hwaddr, mac, maclen);
      if (family == AF_INET)
	arp->addr.addr.addr4.s_addr = ((struct in_addr *)addrp)->s_addr;
#ifdef HAVE_IPV6
      else
	memcpy(&arp->addr.addr.addr6, addrp, IN6ADDRSZ);
#endif
    }
  
  return 1;
}

/* If in lazy mode, we cache absence of ARP entries. */
int find_mac(union mysockaddr *addr, unsigned char *mac, int lazy)
{
  struct arp_record *arp, **up;
  int updated = 0;

 again:
  
  for (arp = arps; arp; arp = arp->next)
    {
      if (addr->sa.sa_family == arp->family)
	{
	  if (arp->addr.addr.addr4.s_addr != addr->in.sin_addr.s_addr)
	    continue;
	}
#ifdef HAVE_IPV6
      else
	{
	  if (!IN6_ARE_ADDR_EQUAL(&arp->addr.addr.addr6, &addr->in6.sin6_addr))
	    continue;
	}
#endif
      
      /* Only accept poitive entries unless in lazy mode. */
      if (arp->status != ARP_EMPTY || lazy || updated)
	{
	  if (mac && arp->hwlen != 0)
	    memcpy(mac, arp->hwaddr, arp->hwlen);
	  return arp->hwlen;
	}
    }

  /* Not found, try the kernel */
  if (!updated)
     {
       updated = 1;
       
       /* Mark all non-negative entries */
       for (arp = arps, up = &arps; arp; arp = arp->next)
	 if (arp->status != ARP_EMPTY)
	   arp->status = ARP_FREE;
       
       iface_enumerate(AF_UNSPEC, NULL, filter_mac);
       
       /* Remove all unconfirmed entries to old list, announce new ones. */
       for (arp = arps, up = &arps; arp; arp = arp->next)
	 if (arp->status == ARP_FREE)
	   {
	     *up = arp->next;
	     arp->next = old;
	     old = arp;
	   }
	 else
	   {
	     up = &arp->next;
	     if (arp->status == ARP_NEW)
	       {
		 char a[ADDRSTRLEN], m[ADDRSTRLEN];
		 union mysockaddr pa;
		 pa.sa.sa_family = arp->family;
		 pa.in.sin_addr.s_addr = arp->addr.addr.addr4.s_addr;
		 prettyprint_addr(&pa, a);
		 print_mac(m, arp->hwaddr, arp->hwlen);
		 my_syslog(LOG_INFO, _("new arp: %s %s"), a, m);
	       }
	   }

       goto again;
     }

  /* record failure, so we don't consult the kernel each time
     we're asked for this address */
  if (old)
    {
      arp = old;
      old = old->next;
    }
  else
    arp = whine_malloc(sizeof(struct arp_record));
  
  if (arp)
    {      
      arp->next = arps;
      arps = arp;
      arp->status = ARP_EMPTY;
      arp->family = addr->sa.sa_family;
      
      if (addr->sa.sa_family == AF_INET)
	arp->addr.addr.addr4.s_addr = addr->in.sin_addr.s_addr;
#ifdef HAVE_IPV6
      else
	memcpy(&arp->addr.addr.addr6, &addr->in6.sin6_addr, IN6ADDRSZ);
#endif
    }
	  
   return 0;
}


