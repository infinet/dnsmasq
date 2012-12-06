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

static struct subnet *filter_zone(struct auth_zone *zone, int flag, struct all_addr *addr_u)
{
  struct subnet *subnet;

  for (subnet = zone->subnet; subnet; subnet = subnet->next)
    {
      if (subnet->is6 && (flag & F_IPV4))
	continue;

      if (!subnet->is6)
	{
	  struct in_addr addr = addr_u->addr.addr4;
	  struct in_addr mask;
	  
	  mask.s_addr = htonl(~((1 << (32 - subnet->prefixlen)) - 1));
	  
	  if  (is_same_net(addr, subnet->addr4, mask))
	    return subnet;
	}
#ifdef HAVE_IPV6
      else if (is_same_net6(&(addr_u->addr.addr6), &subnet->addr6, subnet->prefixlen))
	return subnet;
#endif

    }
  return NULL;
}



size_t answer_auth(struct dns_header *header, char *limit, size_t qlen, time_t now) 
{
  char *name = daemon->namebuff;
  unsigned char *p, *ansp;
  int qtype, qclass;
  unsigned int nameoffset;
  int q, anscount = 0, authcount = 0;
  struct crec *crecp;
  int  auth = 1, trunc = 0, nxdomain = 1, soa = 0, ns = 0;
  struct auth_zone *zone = NULL;
  struct subnet *subnet = NULL;

  if (ntohs(header->qdcount) == 0 || OPCODE(header) != QUERY )
    return 0;
  
  /* determine end of question section (we put answers there) */
  if (!(ansp = skip_questions(header, qlen)))
    return 0; /* bad packet */
  
  /* now process each question, answers go in RRs after the question */
  p = (unsigned char *)(header+1);

  for (q = ntohs(header->qdcount); q != 0; q--)
    {
      size_t domainlen, namelen;
      unsigned short flag = 0;
      int found = 0;
      struct mx_srv_record *rec, *move, **up;
      struct txt_record *txt;
      struct interface_name *intr;
      struct naptr *na;
      struct all_addr addr;
      struct cname *a;

      /* save pointer to name for copying into answers */
      nameoffset = p - (unsigned char *)header;

      /* now extract name as .-concatenated string into name */
      if (!extract_name(header, qlen, &p, name, 1, 4))
	return 0; /* bad packet */
 
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      
      if (qclass != C_IN)
	continue;
      
      if (qtype == T_PTR)
	{
	  if (!(flag = in_arpa_name_2_addr(name, &addr)))
	    continue;

	  for (zone = daemon->auth_zones; zone; zone = zone->next)
	    if ((subnet = filter_zone(zone, flag, &addr)))
	      break;

	  if (!zone)
	    {
	      auth = 0;
	      continue;
	    }
 
	  domainlen = strlen(zone->domain);
	  
	  if (flag == F_IPV4)
	    {
	      for (intr = daemon->int_names; intr; intr = intr->next)
		{
		  if (addr.addr.addr4.s_addr == get_ifaddr(intr->intr).s_addr)
		    break;
		  else
		    while (intr->next && strcmp(intr->intr, intr->next->intr) == 0)
		      intr = intr->next;
		}

	      if (intr)
		{
		  namelen = strlen(intr->name);
		  
		  if (namelen >= domainlen && hostname_isequal(zone->domain, &intr->name[namelen - domainlen]) &&
		      (namelen == domainlen || intr->name[namelen - domainlen - 1] == '.'))
		    {	
		      found = 1;
		      log_query(F_IPV4 | F_REVERSE | F_CONFIG, intr->name, &addr, NULL);
		      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					      daemon->auth_ttl, NULL,
					      T_PTR, C_IN, "d", intr->name))
			anscount++;
		    }
		}
	    }

	  if ((crecp = cache_find_by_addr(NULL, &addr, now, flag)))
	    do { 
	      strcpy(name, cache_get_name(crecp));
	      
	      if (crecp->flags & F_DHCP && !option_bool(OPT_DHCP_FQDN))
		{
		  char *p = strchr(name, '.');
		  if (p)
		    *p = 0; /* must be bare name */
		  
		  /* add  external domain */
		  strcat(name, ".");
		  strcat(name, zone->domain);
		  log_query(flag | F_DHCP | F_REVERSE, name, &addr, record_source(crecp->uid));
		  found = 1;
		  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					  daemon->auth_ttl, NULL,
					  T_PTR, C_IN, "d", name))
		    anscount++;
		}
	      else if (crecp->flags & (F_DHCP | F_HOSTS))
		{
		  namelen = strlen(name);
		  
		  if (namelen > domainlen + 1 &&
		      name[namelen - domainlen - 1] != '.')
		    continue;
		  if (namelen < domainlen ||
		      !hostname_isequal(zone->domain, &name[namelen - domainlen]))
		    continue; /* wrong domain */
		  
		  log_query(crecp->flags & ~F_FORWARD, name, &addr, record_source(crecp->uid));
		  found = 1;
		  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					  daemon->auth_ttl, NULL,
					  T_PTR, C_IN, "d", name))
		    anscount++;
		}
	      else
		continue;
		    
	    } while ((crecp = cache_find_by_addr(crecp, &addr, now, flag)));

	  if (!found)
	    log_query(flag | F_NEG | F_NXDOMAIN | F_REVERSE | F_AUTH, NULL, &addr, NULL);

	  continue;
	}
      
    cname_restart:
      namelen = strlen(name);
      
      for (zone = daemon->auth_zones; zone; zone = zone->next)
	{
	  domainlen = strlen(zone->domain);
	  if (namelen >= domainlen && 
	      hostname_isequal(zone->domain, &name[namelen - domainlen]) &&
	      (namelen == domainlen || name[namelen - domainlen - 1] == '.'))
	    break;
	}
      
      if (!zone)
	{
	  auth = 0;
	  continue;
	}

      for (rec = daemon->mxnames; rec; rec = rec->next)
	if (!rec->issrv && hostname_isequal(name, rec->name))
	  {
	    nxdomain = 0;
	         
	    if (qtype == T_MX)
	      {
		found = 1;
		log_query(F_CONFIG | F_RRNAME, name, NULL, "<MX>"); 
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, T_MX, C_IN, "sd", rec->weight, rec->target))
		  anscount++;
	      }
	  }
      
      for (move = NULL, up = &daemon->mxnames, rec = daemon->mxnames; rec; rec = rec->next)
	if (rec->issrv && hostname_isequal(name, rec->name))
	  {
	    nxdomain = 0;
	    
	    if (qtype == T_SRV)
	      {
		found = 1;
		log_query(F_CONFIG | F_RRNAME, name, NULL, "<SRV>"); 
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, T_SRV, C_IN, "sssd", 
					rec->priority, rec->weight, rec->srvport, rec->target))

		  anscount++;
	      } 
	    
	    /* unlink first SRV record found */
	    if (!move)
	      {
		move = rec;
		*up = rec->next;
	      }
	    else
	      up = &rec->next;      
	  }
	else
	  up = &rec->next;
	  
      /* put first SRV record back at the end. */
      if (move)
	{
	  *up = move;
	  move->next = NULL;
	}

      for (txt = daemon->rr; txt; txt = txt->next)
	if (hostname_isequal(name, txt->name))
	  {
	    nxdomain = 0;
	    if (txt->class == qtype)
	      {
		found = 1;
		log_query(F_CONFIG | F_RRNAME, name, NULL, "<RR>"); 
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, txt->class, C_IN, "t", txt->len, txt->txt))
		  anscount++;
	      }
	  }
      
      for (txt = daemon->txt; txt; txt = txt->next)
	if (txt->class == C_IN && hostname_isequal(name, txt->name))
	  {
	    nxdomain = 0;
	    if (qtype == T_TXT)
	      {
		found = 1;
		log_query(F_CONFIG | F_RRNAME, name, NULL, "<TXT>"); 
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, T_TXT, C_IN, "t", txt->len, txt->txt))
		  anscount++;
	      }
	  }

       for (na = daemon->naptr; na; na = na->next)
	 if (hostname_isequal(name, na->name))
	   {
	     nxdomain = 0;
	     if (qtype == T_NAPTR)
	       {
		 found = 1;
		 log_query(F_CONFIG | F_RRNAME, name, NULL, "<NAPTR>");
		 if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl, 
					 NULL, T_NAPTR, C_IN, "sszzzd", 
					 na->order, na->pref, na->flags, na->services, na->regexp, na->replace))
			  anscount++;
	       }
	   }


       for (intr = daemon->int_names; intr; intr = intr->next)
	 if (hostname_isequal(name, intr->name))
	   {
	     nxdomain = 0;
	     if (qtype == T_A && (addr.addr.addr4 = get_ifaddr(intr->intr)).s_addr != (in_addr_t) -1)
	       {
		 found = 1;
		 log_query(F_FORWARD | F_CONFIG | F_IPV4, name, &addr, NULL);
		 if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					 daemon->auth_ttl, NULL, T_A, C_IN, "4", &addr))
		   anscount++;
	       }
	   }
       
       for (a = daemon->cnames; a; a = a->next)
	 if (hostname_isequal(name, a->alias) )
	   {
	     log_query(F_CONFIG | F_CNAME, name, NULL, NULL);
	     strcpy(name, a->target);
	     if (!strchr(name, '.'))
	       {
		 strcat(name, ".");
		 strcat(name, zone->domain);
	       }
	     found = 1;
	     if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				     daemon->auth_ttl, NULL,
				     T_CNAME, C_IN, "d", name))
	       anscount++;
	     
	     goto cname_restart;
	   }

      if (qtype == T_A)
	flag = F_IPV4;

#ifdef HAVE_IPV6
      if (qtype == T_AAAA)
	flag = F_IPV6;
#endif

      if (qtype == T_SOA && namelen == domainlen)
	{
	  soa = 1; /* inhibits auth section */
	  found = 1;
	  log_query(F_RRNAME | F_AUTH, zone->domain, NULL, "<SOA>");
	}
      
      if (qtype == T_NS && namelen == domainlen)
	{
	  ns = 1; /* inhibits auth section */
	  found = 1;
	  log_query(F_RRNAME | F_AUTH, zone->domain, NULL, "<NS>"); 
	}
      
      
      if (!option_bool(OPT_DHCP_FQDN) && namelen > domainlen + 1)
	{	  
	  name[namelen - domainlen - 1] = 0; /* remove domain part */
	  
	  if (!strchr(name, '.') && (crecp = cache_find_by_name(NULL, name, now, F_IPV4 | F_IPV6)))
	    {
	      if (crecp->flags & F_DHCP)
		do
		  { 
		    nxdomain = 0;
		    if ((crecp->flags & flag) && filter_zone(zone, flag, &(crecp->addr.addr)))
		      {
			name[namelen - domainlen - 1] = '.'; /* restore domain part */
			log_query(crecp->flags, name, &crecp->addr.addr, record_source(crecp->uid));
			name[namelen - domainlen - 1] = 0; /* remove domain part */
			found = 1;
			if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
						daemon->auth_ttl, NULL, qtype, C_IN, 
						qtype == T_A ? "4" : "6", &crecp->addr))
			  anscount++;
		      }
		  } while ((crecp = cache_find_by_name(crecp, name, now,  F_IPV4 | F_IPV6)));
	    }
       	  
	  name[namelen - domainlen - 1] = '.'; /* restore domain part */	    
	}
      
      if ((crecp = cache_find_by_name(NULL, name, now, F_IPV4 | F_IPV6)))
	{
	  if ((crecp->flags & F_HOSTS) || (((crecp->flags & F_DHCP) && option_bool(OPT_DHCP_FQDN))))
	    do
	      { 
		 nxdomain = 0;
		 if ((crecp->flags & flag) && filter_zone(zone, flag, &(crecp->addr.addr)))
		   {
		     log_query(crecp->flags, name, &crecp->addr.addr, record_source(crecp->uid));
		     found = 1;
		     if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					     daemon->auth_ttl, NULL, qtype, C_IN, 
					     qtype == T_A ? "4" : "6", &crecp->addr))
		       anscount++;
		   }
	      } while ((crecp = cache_find_by_name(crecp, name, now, F_IPV4 | F_IPV6)));
	}
      
      if (!found)
	log_query(flag | F_NEG | (nxdomain ? F_NXDOMAIN : 0) | F_FORWARD | F_AUTH, name, NULL, NULL);
      
    }
  
  /* Add auth section */
  if (auth)
    {
      if (!subnet)
	name = zone->domain;
      else
	{
	  /* handle NS and SOA for PTR records */
	  if (!subnet->is6)
	    {
	      in_addr_t a = ntohl(subnet->addr4.s_addr) >> 8;
	      char *p = name;
	      
	      if (subnet->prefixlen == 24)
		p += sprintf(p, "%d.", a & 0xff);
	      a = a >> 8;
	      if (subnet->prefixlen != 8)
		p += sprintf(p, "%d.", a & 0xff);
	      a = a >> 8;
	      p += sprintf(p, "%d.in-addr.arpa", a & 0xff);
	      
	    }
#ifdef HAVE_IPV6
	  else
	    {
	      char *p = name;
	      int i;
	      
	      for (i = subnet->prefixlen-1; i >= 0; i -= 4)
		{ 
		  int dig = ((unsigned char *)&subnet->addr6)[i>>3];
		  p += sprintf(p, "%.1x.", (i>>2) & 1 ? dig & 15 : dig >> 4);
		}
	      p += sprintf(p, "ip6.arpa");
	      
	    }
#endif
	}
      
      /* handle NS and SOA in auth section or for explicit queries */
      if ((anscount != 0 || ns) && 
	  add_resource_record(header, limit, &trunc, 0, &ansp, 
			      daemon->auth_ttl, NULL, T_NS, C_IN, "d", name, daemon->authserver))
	{
	  if (ns) 
	    anscount++;
	  else
	    authcount++;
	}
      
      if ((anscount == 0 || soa) &&
	  add_resource_record(header, limit, &trunc, 0, &ansp, 
			      daemon->auth_ttl, NULL, T_SOA, C_IN, "ddlllll",
			      name, daemon->authserver,  daemon->hostmaster,
			      daemon->soa_sn, daemon->soa_refresh, 
			      daemon->soa_retry, daemon->soa_expiry, 
			      daemon->auth_ttl))
	{
	  if (soa)
	    anscount++;
	  else
	    authcount++;
	}
    }
  
  /* done all questions, set up header and return length of result */
  /* clear authoritative and truncated flags, set QR flag */
  header->hb3 = (header->hb3 & ~(HB3_AA | HB3_TC)) | HB3_QR;
  /* clear RA flag */
  header->hb4 &= ~HB4_RA;

  /* authoritive */
  if (auth)
    header->hb3 |= HB3_AA;
  
  /* truncation */
  if (trunc)
    header->hb3 |= HB3_TC;
  
  if (anscount == 0 && auth && nxdomain)
    SET_RCODE(header, NXDOMAIN);
  else
    SET_RCODE(header, NOERROR); /* no error */
  header->ancount = htons(anscount);
  header->nscount = htons(authcount);
  header->arcount = htons(0);
  return ansp - (unsigned char *)header;
}
  
  



