/* dnsmasq is Copyright (c) 2000-2011 Simon Kelley

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
 

#define opt6_len(opt) ((int)(((unsigned short *)(opt))[1]))
#define opt6_ptr(opt, i) ((void *)&(((unsigned char *)(opt))[4u+(unsigned int)(i)]))


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
   daemon->outpacket_counter = 4; message type and ID 
   
   elapsed time:
   int o = new_opt(OPTION_ELAPSED_TIME);
   put_opt_short(o, 100)
   finalise_opt(o);

   IA_NA

   int o = new_opt(OPTION_IA_NA);
   put_opt_long(o, IAID);
   put_opt_long(o, T1);
   put_opt_long(0, T2);
   int o1 = new_opt(OPTION_IAADDR);
   put_opt(o1, &addr, sizeof(addr));
   put_opt_long(o1, preferred_lifetime);
   put_opt_long(o1, valid_lifetime);
   finalise_opt(o1);
   finalise_opt(o);


*/





void end_opt6(int container)
{
   void *p = daemon->outpacket.iov_base + container + 2;
   u16 len = outpacket_counter - container - 4 ;
   
   PUTSHORT(len, p);
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
    
int new_opt6(int opt)
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


  

void *put_opt6(void *data, size_t len)
{
  void *p;

  if (data && (p = expand(len)))
    memcpy(p, data, len);   

  return p;
}
  
void put_opt6_long(unsigned int val)
{
  void *p;
  
  if (( p = expand(4)))  
    PUTLONG(p, val);
}

void put_opt6_short(unsigned int val)
{
  void *p;

  if ((p = expand(2)))
    PUTSHORT(val, p);   
}

void put_opt6_byte(unsigned int val)
{
  void *p;

  if ((p = expand(1)))
    *((unsigned char *)p) = val;   
}
  
size_t dhcp6_reply(struct dhcp_context *context, size_t sz)
{
  void *packet_options = ((void *)daemon->dhcp_packet.iov_base) + 4;
  void *end = ((void *)daemon->dhcp_packet.iov_base) + sz;
  void *na_option, *na_end; 
  void *opt, *p;
  int o;
  
  outpacket_counter = 4; /* skip message type and transaction-id */
   
  if (!(opt = opt6_find(packet_options, end, OPTION6_CLIENT_ID, 1)))
    return;
  
  o = new_opt6(OPTION6_CLIENT_ID);
  put_opt6(opt6_ptr(opt, 0), opt6_len(opt));
  end_opt6(o);

  o = new_opt6(OPTION6_SERVER_ID);
  put_opt6(daemon->duid, daemon->duid_len);
  end_opt6(o);

  if ((opt = opt6_find(packet_options, end, OPTION6_IA_NA, 12)))
    {     
      while (opt = opt6_find(opt, end, OPTION6_IA_NA, 12))
	{   
	  void *ia_end = opt6_ptr(opt, opt6_len(opt));
	  void *ia_option = opt6_find(opt6_ptr(opt, 12), ia_end, OPTION6_IAADDR, 24);
	  
	  unsigned int iaid = opt6_uint(opt, 0, 4);
	  unsigned int t1 = opt6_uint(opt, 4, 4);
	  unsigned int t2 = opt6_uint(opt, 8, 4);
	  
	  
	  if (ia_option)
	    while ((ia_option = ia_option, ia_end, OPTION6_IAADDR, 24))
	      {
		/* do address option */
		
		ia_option = opt6_next(ia_option, ia_end);
	      }	  
	  else
	    {
	      /* no preferred address call address allocate */
	      
	    }
	  
	  opt = opt6_next(opt, end);
	}
    }
  else if ((opt = opt6_find(packet_options, end, OPTION6_IA_TA, 4)))
    while (opt = opt6_find(opt, end, OPTION6_IA_TA, 4))
      {   
	void *ia_end = opt6_ptr(opt, opt6_len(opt));
	void *ia_option = opt6_find(opt6_ptr(opt, 4), ia_end, OPTION6_IAADDR, 24);
	
	unsigned int iaid = opt6_uint(opt, 0, 4);
	
	if (ia_option)
	  while ((ia_option = ia_option, ia_end, OPTION6_IAADDR, 24))
	    {
	      /* do address option */
	      
	      ia_option = opt6_next(ia_option, ia_end);
	    }	  
	else
	  {
	    /* no preferred address */
	    
	  }
	
	opt = opt6_next(opt, end);
      }	
  else
    return; /* no IA_NA and no IA_TA */



}

#endif

