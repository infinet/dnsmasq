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

static struct dhcp_lease *leases;
static FILE *lease_file;
static int dns_dirty, file_dirty, new_lease;
static int leases_left;

void lease_init(struct daemon *daemon, time_t now)
{
  unsigned int e0, e1, e2, e3, e4, e5, a0, a1, a2, a3;
  unsigned long ei;
  time_t expires;
  unsigned char hwaddr[ETHER_ADDR_LEN];
  struct in_addr addr;
  struct dhcp_lease *lease;
  int clid_len = 0;
  int has_old = 0;
  char *buff = daemon->dhcp_buff;
  char *buff2 = daemon->dhcp_buff2;
  
  leases = NULL;
  leases_left = daemon->dhcp_max;

  /* NOTE: need a+ mode to create file if it doesn't exist */
  if (!(lease_file = fopen(daemon->lease_file, "a+")))
    die("cannot open or create leases file: %s", NULL);
    
  /* a+ mode lease pointer at end. */
  rewind(lease_file);

  while (fscanf(lease_file, "%lu %x:%x:%x:%x:%x:%x %d.%d.%d.%d %257s %257s",
		&ei, &e0, &e1, &e2, &e3, &e4, &e5, &a0, &a1, &a2, &a3, 
		buff, buff2) == 13)
    {
#ifdef HAVE_BROKEN_RTC
      if (ei)
	expires = (time_t)ei + now;
      else
	expires = (time_t)0;
#else 
      /* strictly time_t is opaque, but this hack should work on all sane systems,
	 even when sizeof(time_t) == 8 */
      expires = (time_t)ei;
      
      if (ei != 0  && difftime(now, expires) > 0)
	{
	  has_old = 1;
	  continue; /* expired */
	}
#endif

      hwaddr[0] = e0;
      hwaddr[1] = e1;
      hwaddr[2] = e2;
      hwaddr[3] = e3;
      hwaddr[4] = e4;
      hwaddr[5] = e5;
      
      addr.s_addr = htonl((a0<<24) + (a1<<16) + (a2<<8) + a3);

      /* decode hex in place */
      if (strcmp(buff2, "*") == 0)
	clid_len = 0;
      else
	{ 
	  int s = (strlen(buff2)/3) + 1;
	  for (clid_len = 0; clid_len < s; clid_len++)
	  {
	    buff2[(clid_len*3)+2] = 0;
	    buff2[clid_len] = strtol(&buff2[clid_len*3], NULL, 16);
	  }
	}
      
      if (!(lease = lease_allocate(buff2, clid_len, addr)))
	die ("too many stored leases", NULL);
      
      lease->expires = expires;
      memcpy(lease->hwaddr, hwaddr, ETHER_ADDR_LEN);

      if (strcmp(buff, "*") !=  0)
	  lease_set_hostname(lease, buff, daemon->domain_suffix);
    }
  
  dns_dirty = 1;
  file_dirty = has_old;
  new_lease = 0;

  daemon->lease_fd = fileno(lease_file);
}

void lease_update_from_configs(struct dhcp_config *dhcp_configs, char *domain)
{
  /* changes to the config may change current leases. */
  
  struct dhcp_lease *lease;
  struct dhcp_config *config;
  
  for (lease = leases; lease; lease = lease->next)
    if ((config = find_config(dhcp_configs, NULL, lease->clid, lease->clid_len, lease->hwaddr, NULL)) && 
	(config->flags & CONFIG_NAME))
      lease_set_hostname(lease, config->hostname, domain);
}

void lease_update_file(int force, time_t now)
{
  struct dhcp_lease *lease;
  int i = force; /* avoid warning */
  unsigned long expires;

#ifdef HAVE_BROKEN_RTC
  if (force || new_lease)
    {
      lease_prune(NULL, now);
#else
  if (file_dirty)
    {
#endif
      rewind(lease_file);
      ftruncate(fileno(lease_file), 0);
      
      for (lease = leases; lease; lease = lease->next)
	{
#ifdef HAVE_BROKEN_RTC
	  if (lease->expires)
	    expires = (unsigned long) difftime(lease->expires, now);
	  else
	    expires = 0;
#else
	  expires = now; /* eliminate warning */
	  expires = (unsigned long)lease->expires;
#endif
	  fprintf(lease_file, "%lu %.2x:%.2x:%.2x:%.2x:%.2x:%.2x %s %s ", 
		  expires, lease->hwaddr[0], lease->hwaddr[1],
		  lease->hwaddr[2], lease->hwaddr[3], lease->hwaddr[4],
		  lease->hwaddr[5], inet_ntoa(lease->addr),
		  lease->hostname && strlen(lease->hostname) != 0 ? lease->hostname : "*");
	  
	  if (lease->clid_len)
	    {
	      for (i = 0; i < lease->clid_len - 1; i++)
		fprintf(lease_file, "%.2x:", lease->clid[i]);
	      fprintf(lease_file, "%.2x\n", lease->clid[i]);
	    }
	  else
	    fprintf(lease_file, "*\n");
	  
	}

      fflush(lease_file);
      fsync(fileno(lease_file));
      file_dirty = 0;
      new_lease = 0;
    }
}

void lease_update_dns(void)
{
  struct dhcp_lease *lease;
  
  if (dns_dirty)
    {
      cache_unhash_dhcp();
      
      for (lease = leases; lease; lease = lease->next)
	{
	  cache_add_dhcp_entry(lease->fqdn, &lease->addr, lease->expires);
	  cache_add_dhcp_entry(lease->hostname, &lease->addr, lease->expires);
	}
      
      dns_dirty = 0;
    }
}

void lease_prune(struct dhcp_lease *target, time_t now)
{
  struct dhcp_lease *lease, *tmp, **up;

  for (lease = leases, up = &leases; lease; lease = tmp)
    {
      tmp = lease->next;
      if ((lease->expires != 0 && difftime(now, lease->expires) > 0) || lease == target)
	{
	  file_dirty = 1;

	  *up = lease->next; /* unlink */
	  if (lease->hostname)
	    {
	      free(lease->hostname); 
	      dns_dirty = 1;
	    }
	  if (lease->fqdn)
	    free(lease->fqdn);
	  if (lease->clid)
	    free(lease->clid);
	  free(lease);
	  leases_left++;
	}
      else
	up = &lease->next;
    }
} 
	
  
struct dhcp_lease *lease_find_by_client(unsigned char *clid, int clid_len)
{
  struct dhcp_lease *lease;

  if (clid_len)
    {
      for (lease = leases; lease; lease = lease->next)
	if (lease->clid && clid_len == lease->clid_len &&
	  memcmp(clid, lease->clid, clid_len) == 0)
	return lease;
    }
  else
    {
      for (lease = leases; lease; lease = lease->next)	
	if (memcmp(clid, lease->hwaddr, ETHER_ADDR_LEN) == 0)
	  return lease;
    }
  
  return NULL;
}

struct dhcp_lease *lease_find_by_addr(struct in_addr addr)
{
  struct dhcp_lease *lease;

  for (lease = leases; lease; lease = lease->next)
    if (lease->addr.s_addr == addr.s_addr)
      return lease;
  
  return NULL;
}


struct dhcp_lease *lease_allocate(unsigned char *clid, int clid_len, struct in_addr addr)
{
  struct dhcp_lease *lease;
  if (!leases_left || !(lease = malloc(sizeof(struct dhcp_lease))))
    return NULL;

  lease->clid = NULL;
  lease->clid_len = clid_len;
  
  if (clid_len)
    {
      if (!(lease->clid = malloc(clid_len)))
       {
	 free(lease);
	 return NULL;
       }
      memcpy(lease->clid, clid, clid_len);
    }
  
  lease->hostname = lease->fqdn = NULL;
  lease->addr = addr;
  memset(lease->hwaddr, 0, ETHER_ADDR_LEN);
  lease->expires = 1;
  
  lease->next = leases;
  leases = lease;
  
  file_dirty = 1;
  new_lease = 1;
  leases_left--;

  return lease;
}

void lease_set_expires(struct dhcp_lease *lease, time_t exp)
{
  if (exp != lease->expires)
    file_dirty = dns_dirty = 1;

  lease->expires = exp;
}

void lease_set_hwaddr(struct dhcp_lease *lease, unsigned char *hwaddr)
{
  if (memcmp(lease->hwaddr, hwaddr, ETHER_ADDR_LEN) != 0)
    {
      file_dirty = 1;
      memcpy(lease->hwaddr, hwaddr, ETHER_ADDR_LEN);
    }
}

void lease_set_hostname(struct dhcp_lease *lease, char *name, char *suffix)
{
  struct dhcp_lease *lease_tmp;
  char *new_name = NULL, *new_fqdn = NULL;

  if (lease->hostname && name && hostname_isequal(lease->hostname, name))
    return;

  if (!name && !lease->hostname)
    return;

  /* If a machine turns up on a new net without dropping the old lease,
     or two machines claim the same name, then we end up with two interfaces with
     the same name. Check for that here and remove the name from the old lease. */
  
  if (name)
    {
      for (lease_tmp = leases; lease_tmp; lease_tmp = lease_tmp->next)
	if (lease_tmp->hostname && hostname_isequal(lease_tmp->hostname, name))
	  {
	    new_name = lease_tmp->hostname;
	    lease_tmp->hostname = NULL;
	    if (lease_tmp->fqdn)
	      {
		new_fqdn = lease_tmp->fqdn;
		lease_tmp->fqdn = NULL;
	      }
	  }
     
      if (!new_name && (new_name = malloc(strlen(name) + 1)))
	strcpy(new_name, name);
      
      if (suffix && !new_fqdn && (new_fqdn = malloc(strlen(name) + strlen(suffix) + 2)))
	{
	  strcpy(new_fqdn, name);
	  strcat(new_fqdn, ".");
	  strcat(new_fqdn, suffix);
	}
    }

  if (lease->hostname)
    free(lease->hostname);
  if (lease->fqdn)
    free(lease->fqdn);
  
  lease->hostname = new_name;
  lease->fqdn = new_fqdn;
  
  file_dirty = dns_dirty = 1;
}



