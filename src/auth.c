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

static int filter_zone(struct auth_zone *zone, int flag, struct all_addr *addr_u)
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
	  
	  mask.s_addr = (1 << (32 - subnet->prefixlen)) - 1;
	  
	  if  (is_same_net(addr, subnet->addr4, mask))
	    return 1;
	}
#ifdef HAVE_IPV6
      else if (is_same_net6(&(addr_u->addr.addr6), &subnet->addr6, subnet->prefixlen))
	return 1;
#endif

    }
  return 0;
}



size_t answer_auth(struct dns_header *header, char *limit, size_t qlen, time_t now) 
{
  char *name = daemon->namebuff;
  unsigned char *p, *ansp;
  int qtype, qclass;
  unsigned int nameoffset;
  int q, anscount = 0, authcount = 0;
  struct crec *crecp;
  int  auth = 1, trunc = 0, nxdomain = 1, soa = 0;
  struct auth_zone *zone = NULL;

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
      struct mx_srv_record *rec;

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
	  struct all_addr addr;
	  
	  if (!(flag = in_arpa_name_2_addr(name, &addr)))
	    continue;

	  for (zone = daemon->auth_zones; zone; zone = zone->next)
	    if (filter_zone(zone, flag, &addr))
	      break;

	  if (!zone)
	    {
	      auth = 0;
	      continue;
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
		  domainlen = strlen(zone->domain);
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
      
      namelen = strlen(name);

      for (zone = daemon->auth_zones; zone; zone = zone->next)
	{
	  domainlen = strlen(zone->domain);
	  if (namelen >= domainlen && 
	      hostname_isequal(zone->domain, &name[namelen - domainlen]))
	    break;
	}

      if (!zone || (namelen > domainlen && name[namelen - domainlen - 1] != '.'))
	{
	  auth = 0;
	  continue;
	}

      for (rec = daemon->mxnames; rec; rec = rec->next)
	if (!rec->issrv && hostname_isequal(name, rec->name))
	  break;

      if (rec)
	{
	  nxdomain = 0;
	  if (!found && qtype == T_MX)
	    {
	      found = 1;
	      log_query(F_AUTH | F_RRNAME, name, NULL, "<MX>"); 
	      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
				      NULL, T_MX, C_IN, "sd", rec->weight, rec->target))
		anscount++;
	    }
	}
      
      if (qtype == T_A)
	flag = F_IPV4;

#ifdef HAVE_IPV6
      if (qtype == T_AAAA)
	flag = F_IPV6;
#endif

      if (!found && qtype == T_SOA && namelen == domainlen)
	{
	  soa = 1; /* inhibits auth section */
	  found = 1;
	  log_query(F_RRNAME | F_AUTH, zone->domain, NULL, "<SOA>");
	  if (add_resource_record(header, limit, &trunc, 0, &ansp, 
				  daemon->auth_ttl, NULL, T_SOA, C_IN, "ddlllll",
				  zone->domain, daemon->authserver,  daemon->hostmaster,
				  daemon->soa_sn, daemon->soa_refresh, 
				  daemon->soa_retry, daemon->soa_expiry, 
				  daemon->auth_ttl))
	    anscount++;
	}
      
      if (!found && qtype == T_NS && namelen == domainlen)
	{
	  soa = 1; /* inhibits auth section */
	  found = 1;
	  log_query(F_RRNAME | F_AUTH, zone->domain, NULL, "<NS>"); 
	  if (add_resource_record(header, limit, &trunc, 0, &ansp, 
				  daemon->auth_ttl, NULL, T_NS, C_IN, "d", zone->domain, daemon->authserver))
	    anscount++;
	}
      

      if (!found && !option_bool(OPT_DHCP_FQDN) && namelen > domainlen + 1)
	{	  
	  name[namelen - domainlen - 1] = 0; /* remove domain part */
	  
	  if ((crecp = cache_find_by_name(NULL, name, now, F_IPV4 | F_IPV6)))
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
      
      if (!found && (crecp = cache_find_by_name(NULL, name, now, F_IPV4 | F_IPV6)))
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
  if (auth && !soa)
    {
      if (anscount != 0 && add_resource_record(header, limit, &trunc, 0, &ansp, 
					       daemon->auth_ttl, NULL, T_NS, C_IN, "d", zone->domain, daemon->authserver))
	authcount++;

      if (anscount == 0 && add_resource_record(header, limit, &trunc, 0, &ansp, 
					       daemon->auth_ttl, NULL, T_SOA, C_IN, "ddlllll",
					       zone->domain, daemon->authserver,  daemon->hostmaster,
					       daemon->soa_sn, daemon->soa_refresh, 
					       daemon->soa_retry, daemon->soa_expiry, 
					       daemon->auth_ttl))
	authcount++;
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
  return ansp - (unsigned char *)header;
}
  
  



