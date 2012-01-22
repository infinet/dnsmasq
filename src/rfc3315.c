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

#ifdef HAVE_DHCP6

static size_t outpacket_counter;

static int make_duid1(unsigned short type, unsigned int flags, char *mac, 
		      size_t maclen, void *parm);
static void do_options6(struct dhcp_context *context, void *oro);

void make_duid(time_t now)
{
  iface_enumerate(AF_LOCAL, &now, make_duid1);

  if (!daemon->duid)
    die("Cannot create DHCPv6 server DUID", NULL, EC_MISC);
}

static int make_duid1(unsigned short type, unsigned int flags, char *mac, 
		      size_t maclen, void *parm)
{
  /* create DUID as specified in RFC3315. We use the MAC of the
     first interface we find that isn't loopback or P-to-P */
  
  unsigned char *p;

  if (flags & (IFF_LOOPBACK | IFF_POINTOPOINT))
    return 1;
  
  daemon->duid = p = safe_malloc(maclen + 8);
  daemon->duid_len = maclen + 8;
  PUTSHORT(1, p); /* DUID_LLT */
  PUTSHORT(type, p); /* address type */
  PUTLONG(*((time_t *)parm), p); /* time */
  memcpy(p, mac, maclen);

  return 0;
}

void *opt6_find (void *opts, void *end, unsigned int search, unsigned int minsize)
{
  u16 opt, opt_len;
  void *start;
  
  if (!opts)
    return NULL;
    
  while (1)
    {
      if (end - opts < 4) 
	return NULL;
      
      start = opts;
      GETSHORT(opt, opts);
      GETSHORT(opt_len, opts);
      
      if (opt_len > (end - opts))
	return NULL;
      
      if (opt == search && (opt_len >= minsize))
	return start;
      
      opts += opt_len;
    }
}

void *opt6_next(void *opts, void *end)
{
  u16 opt_len;
  
  if (end - opts < 4) 
    return NULL;
  
  opts += 2;
  GETSHORT(opt_len, opts);
  
  if (opt_len >= (end - opts))
    return NULL;
  
  return opts + opt_len;
}
 
#define opt6_len(opt) (opt6_uint(opt, -2, 2))
#define opt6_ptr(opt, i) ((void *)&(((unsigned char *)(opt))[4+(i)]))


static unsigned int opt6_uint(unsigned char *opt, int offset, int size)
{
  /* this worries about unaligned data and byte order */
  unsigned int ret = 0;
  int i;
  unsigned char *p = opt6_ptr(opt, offset);
  
  for (i = 0; i < size; i++)
    ret = (ret << 8) | *p++;
  
  return ret;
}

/* 
   set of routines to build arbitrarily nested options: eg

   int o = new_opt(OPTION_IA_NA);
   put_opt_long(IAID);
   put_opt_long(T1);
   put_opt_long(T2);
   int o1 = new_opt(OPTION_IAADDR);
   put_opt(o1, &addr, sizeof(addr));
   put_opt_long(preferred_lifetime);
   put_opt_long(valid_lifetime);
   finalise_opt(o1);
   finalise_opt(o);


   to go back and fill in fields

   int o = new_opt(OPTION_IA_NA);
   put_opt_long(IAID);
   int t1sav = save_counter(-1);
   put_opt_long(0);
   put_opt_long(0);

   int o1 = new_opt(OPTION_IAADDR);
   put_opt(o1, &addr, sizeof(addr));
   put_opt_long(o1, preferred_lifetime);
   put_opt_long(o1, valid_lifetime);
   finalise_opt(o1);

   int sav = save_counter(t1sav);
   put_opt_long(T1);
   save_counter(sav);
   finalise_opt(o);


   to abandon an option

   int o = new_opt(OPTION_IA_NA);
   put_opt_long(IAID);
   put_opt_long(T1);
   put_opt_long(T2);
   if (err)
      save_counter(o);

*/





static void end_opt6(int container)
{
   void *p = daemon->outpacket.iov_base + container + 2;
   u16 len = outpacket_counter - container - 4 ;
   
   PUTSHORT(len, p);
}

static int  save_counter(int newval)
{
  int ret = outpacket_counter;
  if (newval != -1)
    outpacket_counter = newval;

  return ret;
}


        
static void *expand(size_t headroom)
{
  void *ret;

  if (expand_buf(&daemon->outpacket, outpacket_counter + headroom))
    {
      ret = daemon->outpacket.iov_base + outpacket_counter;
      outpacket_counter += headroom;
      return ret;
    }
  
  return NULL;
}
    
static int new_opt6(int opt)
{
  int ret = outpacket_counter;
  void *p;

  if ((p = expand(4)))
    {
      PUTSHORT(opt, p);
      PUTSHORT(0, p);
    }

  return ret;
}


  

static void *put_opt6(void *data, size_t len)
{
  void *p;

  if (data && (p = expand(len)))
    memcpy(p, data, len);   

  return p;
}
  
static void put_opt6_long(unsigned int val)
{
  void *p;
  
  if (( p = expand(4)))  
    PUTLONG(val, p);
}

static void put_opt6_short(unsigned int val)
{
  void *p;

  if ((p = expand(2)))
    PUTSHORT(val, p);   
}

static void put_opt6_byte(unsigned int val)
{
  void *p;

  if ((p = expand(1)))
    *((unsigned char *)p) = val;   
}
 
static void put_opt6_string(char *s)
{
  put_opt6(s, strlen(s));
}

  
size_t dhcp6_reply(struct dhcp_context *context, size_t sz, time_t now)
{
  void *packet_options = ((void *)daemon->dhcp_packet.iov_base) + 4;
  void *end = ((void *)daemon->dhcp_packet.iov_base) + sz;
  void *na_option, *na_end; 
  void *opt, *p;
  int o, msg_type = *((unsigned char *)daemon->dhcp_packet.iov_base);
  int make_lease = (msg_type == DHCP6REQUEST || opt6_find(packet_options, end, OPTION6_RAPID_COMMIT, 0)); 
  unsigned char *clid;
  int clid_len;
  struct dhcp_netid *tags;

  /* copy over transaction-id */
  memcpy(daemon->outpacket.iov_base, daemon->dhcp_packet.iov_base, 4);
  /* set reply message type */
  *((unsigned char *)daemon->outpacket.iov_base) = make_lease ? DHCP6REPLY : DHCP6ADVERTISE;
  /* skip message type and transaction-id */
  outpacket_counter = 4; 
   
  if (!(opt = opt6_find(packet_options, end, OPTION6_CLIENT_ID, 1)))
    return 0;
  
  clid = opt6_ptr(opt, 0);
  clid_len = opt6_len(opt);
  o = new_opt6(OPTION6_CLIENT_ID);
  put_opt6(clid, clid_len);
  end_opt6(o);

  /* server-id must match except for SOLICIT meesages */
  if (msg_type != DHCP6SOLICIT &&
      (!(opt = opt6_find(packet_options, end, OPTION6_SERVER_ID, 1)) ||
       opt6_len(opt) != daemon->duid_len ||
       memcmp(opt6_ptr(opt, 0), daemon->duid, daemon->duid_len) != 0))
    return 0;
  
  o = new_opt6(OPTION6_SERVER_ID);
  put_opt6(daemon->duid, daemon->duid_len);
  end_opt6(o);
  
  switch (msg_type)
    {
    case DHCP6SOLICIT:
    case DHCP6REQUEST:
      {
	u16 *req_options = NULL;

	for (opt = opt6_find(packet_options, end, OPTION6_IA_NA, 12);
	     opt; 
	     opt = opt6_find(opt6_next(opt, end), end, OPTION6_IA_NA, 12))
	  {   
	    void *ia_end = opt6_ptr(opt, opt6_len(opt));
	    void *ia_option = opt6_find(opt6_ptr(opt, 12), ia_end, OPTION6_IAADDR, 24);
	    unsigned int min_time = 0xffffffff;
	    int t1cntr;
	    unsigned int iaid = opt6_uint(opt, 0, 4);
	    int address_assigned = 0;
	    struct dhcp_lease *lease = NULL;

	    o = new_opt6(OPTION6_IA_NA);
	    put_opt6_long(iaid);
	    /* save pointer */
	    t1cntr = save_counter(-1);
	    /* so we can fill these in later */
	    put_opt6_long(0);
	    put_opt6_long(0); 
       
	
	    while (1)
	      {
		struct in6_addr alloced_addr, *addrp = NULL;
		
		if (ia_option)
		  {
		    struct in6_addr *req_addr = opt6_ptr(ia_option, 0);
		    u32 preferred_lifetime = opt6_uint(ia_option, 16, 4);
		    u32 valid_lifetime = opt6_uint(ia_option, 20, 4);
		    
		    if ((lease = lease6_find_by_addr(req_addr, 128, 0)))
		      {
			/* check if existing lease for host */
			if (clid_len == lease->clid_len &&
			    memcmp(clid, lease->clid, clid_len) == 0)
			  addrp = req_addr;
		      }
		    else if (address6_available(context, req_addr, tags))
		      addrp = req_addr;
		  }
		else
		  {
		    /* must have an address to CONFIRM */
		    if (msg_type == DHCP6REQUEST)
		      return 0;
		    
		    /* existing lease */
		    if ((lease = lease6_find_by_client(clid, clid_len, iaid)))
		      addrp = (struct in6_addr *)&lease->hwaddr;
		    else if (address6_allocate(context, clid, clid_len, tags, &alloced_addr))
		      addrp = &alloced_addr;		    
		  }
		
		if (addrp)
		  {
		    unsigned int lease_time;
		    address_assigned = 1;
		    
		    context = narrow_context6(context, addrp, tags);
		    lease_time = context->lease_time;
		    if (lease_time < min_time)
		      min_time = lease_time;
		    
		    /* May fail to create lease */
		    if (!lease && make_lease)
		      lease = lease6_allocate(addrp);
		    
		    if (lease)
		      {
			lease_set_expires(lease, lease_time, now);
			lease_set_hwaddr(lease, NULL, clid, 0, iaid, clid_len);
		      }

		    if (lease || !make_lease)
		      {
			int o1 =  new_opt6(OPTION6_IAADDR);
			put_opt6(addrp, sizeof(*addrp));
			put_opt6_long(lease_time);
			put_opt6_long(lease_time);
			end_opt6(o1);
		      }

		  }
		    
		
		if (!ia_option || 
		    !(ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24)))
		  {
		    if (address_assigned)
		      {
			/* go back an fill in fields in IA_NA option */
			unsigned int t1 = min_time == 0xffffffff ? 0xffffffff : min_time/2;
			unsigned int t2 = min_time == 0xffffffff ? 0xffffffff : (min_time/8) * 7;
			int sav = save_counter(t1cntr);
			put_opt6_long(t1);
			put_opt6_long(t2);
			save_counter(sav);
		      }
		    else
		      { 
			/* no address, return erro */
			int o1 = new_opt6(OPTION6_STATUS_CODE);
			put_opt6_short(DHCP6NOADDRS);
			put_opt6_string("No addresses available");
			end_opt6(o1);
		      }
		    
		    end_opt6(o);
		    break;
		  }
	      }
	  }		  
	
	/* same again for TA */
	for (opt = packet_options; opt; opt = opt6_find(opt6_next(opt, end), end, OPTION6_IA_TA, 4))
	  {
	  }

	do_options6(context, opt6_find(packet_options, end, OPTION6_ORO, 0));


      }	

    }

  return outpacket_counter;
  
}


/* TODO tags to select options, and encapsualted options. */
static void do_options6(struct dhcp_context *context, void *oro)
{
  unsigned char *req_options = NULL;
  int req_options_len, i, o;
  struct dhcp_opt *opt, *config_opts = daemon->dhcp_opts6;

  if (oro)
    {
      req_options = opt6_ptr(oro, 0);
      req_options_len = opt6_len(oro);
    }

  for (opt = config_opts; opt; opt = opt->next)
    {
      if (req_options)
	{
	  /* required options are not aligned... */
	  for (i = 0; i < req_options_len - 1; i += 2)
	    if (((req_options[i] << 8) | req_options[i+1]) == opt->opt)
	      break;
	  
	  /* option not requested */
	  if (i == req_options_len)
	    continue;
	}

      o = new_opt6(opt->opt);
      put_opt6(opt->val, opt->len);
      end_opt6(o);
    }
}



#endif

