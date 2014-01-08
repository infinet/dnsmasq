/* dnssec.c is Copyright (c) 2012 Giovanni Bajo <rasky@develer.com>
           and Copyright (c) 2012-2014 Simon Kelley

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

#ifdef HAVE_DNSSEC

#include "dnssec-crypto.h"
#include <assert.h>

/* Maximum length in octects of a domain name, in wire format */
#define MAXCDNAME  256 

#define MAXRRSET 16

#define SERIAL_UNDEF  -100
#define SERIAL_EQ        0
#define SERIAL_LT       -1
#define SERIAL_GT        1

/* Implement RFC1982 wrapped compare for 32-bit numbers */
static int serial_compare_32(unsigned long s1, unsigned long s2)
{
  if (s1 == s2)
    return SERIAL_EQ;

  if ((s1 < s2 && (s2 - s1) < (1UL<<31)) ||
      (s1 > s2 && (s1 - s2) > (1UL<<31)))
    return SERIAL_LT;
  if ((s1 < s2 && (s2 - s1) > (1UL<<31)) ||
      (s1 > s2 && (s1 - s2) < (1UL<<31)))
    return SERIAL_GT;
  return SERIAL_UNDEF;
}


/* process_domain_name() - do operations with domain names in canonicalized wire format.
 *
 * Handling domain names in wire format can be done with buffers as large as MAXCDNAME (256),
 * while the representation format (as created by, eg., extract_name) requires MAXDNAME (1024).
 *
 * With "canonicalized wire format", we mean the standard DNS wire format, eg:
 *
 *   <3>www<7>example<3>org<0>
 *
 * with all ÅSCII letters converted to lowercase, and no wire-level compression.
 *
 * The function works with two different buffers:
 *    - Input buffer: 'rdata' is a pointer to the actual wire data, and 'rdlen' is
 *      the total length till the end of the rdata or DNS packet section. Both
 *      variables are updated after processing the domain name, so that rdata points
 *      after it, and rdlen is decreased by the amount of the processed octects.
 *    - Output buffer: 'out' points to it. In some cases, this buffer can be prefilled
 *      and used as additional input (see below).
 *
 * The argument "action" decides what to do with the submitted domain name:
 *
 *    PDN_EXTRACT:
 *       Extract the domain name from input buffer into the output buffer, possibly uncompressing it.
 *       Return the length of the domain name in the output buffer in octects, or zero if error.
 *
 *    PDN_COMPARE:
 *       Compare the domain name in the input buffer and the one in the output buffer (ignoring
 *       differences in compression). Returns 0 in case of error, a positive number
 *       if they are equal, or a negative number if they are different. This function always
 *       consumes the whole name in the input buffer (there is no early exit).
 *
 *    PDN_ORDER:
 *       Order between the domain name in the input buffer and the domain name in the output buffer.
 *       Returns 0 if the names are equal, 1 if input > output, or -1 if input < output. This
 *       function early-exits when it finds a difference, so rdata might not be fully updated.
 *
 * Notice: because of compression, rdata/rdlen might be updated with a different quantity than
 * the returned number of octects. For instance, if we extract a compressed domain name, rdata/rdlen
 * might be updated only by 2 bytes (that is, rdata is incresed by 2, and rdlen decreased by 2),
 * because it then reuses existing data elsewhere in the DNS packet, while the return value might be
 * larger, reflecting the total number of octects composing the domain name.
 *
 */
#define PWN_EXTRACT   0
#define PWN_COMPARE   1
#define PWN_ORDER     2
static int process_domain_name(struct dns_header *header, size_t pktlen,
                               unsigned char** rdata, size_t* rdlen,
                               unsigned char *out, int action)
{
  int hops = 0, total = 0, i;
  unsigned char label_type;
  unsigned char *end = (unsigned char *)header + pktlen;
  unsigned char count; unsigned char *p = *rdata;
  int nonequal = 0;

#define PROCESS(ch) \
  do { \
    if (action == PWN_EXTRACT) \
      *out++ = ch; \
    else if (action == PWN_COMPARE) \
      { \
        if (*out++ != ch) \
          nonequal = 1; \
      } \
    else if (action == PWN_ORDER) \
      { \
        char _ch = *out++; \
        if (ch < _ch) \
          return -1; \
        else if (_ch > ch) \
          return 1; \
      } \
  } while (0)

  while (1)
    {
      if (p >= end)
        return 0;
      if (!(count = *p++))
        break;
      label_type = count & 0xC0;
      if (label_type == 0xC0)
        {
          int l2;
          if (p >= end)
            return 0;
          l2 = *p++;
          if (hops == 0)
            {
              if (p - *rdata > *rdlen)
                return 0;
              *rdlen -= p - *rdata;
              *rdata = p;
            }
          if (++hops == 256)
            return 0;
          p = (unsigned char*)header + (count & 0x3F) * 256 + l2;
        }
      else if (label_type == 0x00)
        {
          if (p+count-1 >= end)
            return 0;
          total += count+1;
          if (total >= MAXCDNAME)
            return 0;
          PROCESS(count);
          for (i = 0; i < count; ++i)
            {
              unsigned char ch = *p++;
              if (ch >= 'A' && ch <= 'Z')
                ch += 'a' - 'A';
              PROCESS(ch);
            }
        }
      else
        return 0; /* unsupported label_type */
    }

  if (hops == 0)
    {
      if (p - *rdata > *rdlen)
        return 0;
      *rdlen -= p - *rdata;
      *rdata = p;
    }
  ++total;
  if (total >= MAXCDNAME)
    return 0;
  PROCESS(0);

  /* If we arrived here without early-exit, they're equal */
  if (action == PWN_ORDER)
    return 0;
  return nonequal ? -total : total;

  #undef PROCESS
}


/* RDATA meta-description.
 *
 * RFC4034 §6.2 introduces the concept of a "canonical form of a RR". This canonical
 * form is used in two important points within the DNSSEC protocol/algorithm:
 *
 * 1) When computing the hash for verifying the RRSIG signature, we need to do it on
 *    the canonical form.
 * 2) When ordering a RRset in canonical order (§6.3), we need to lexicographically sort
 *    the RRs in canonical form.
 *
 * The canonical form of a RR is specifically tricky because it also affects the RDATA,
 * which is different for each RR type; in fact, RFC4034 says that "domain names in
 * RDATA must be canonicalized" (= uncompressed and lower-cased).
 *
 * To handle this correctly, we then need a way to describe how the RDATA section is
 * composed for each RR type; we don't need to describe every field, but just to specify
 * where domain names are. The following array contains this description, and it is
 * used by rrset_canonical_order() and verifyalg_add_rdata(), to adjust their behaviour
 * for each RR type.
 *
 * The format of the description is very easy, for instance:
 *
 *   { 12, RDESC_DOMAIN, RDESC_DOMAIN, 4, RDESC_DOMAIN, RDESC_END }
 *
 * This means that this (ficticious) RR type has a RDATA section containing 12 octects
 * (we don't care what they contain), followed by 2 domain names, followed by 4 octects,
 * followed by 1 domain name, and then followed by an unspecificied number of octects (0
 * or more).
 */

#define RDESC_DOMAIN   -1
#define RDESC_END       0
static const int rdata_description[][8] =
{
  /**/            { RDESC_END },
  /* 1: A */      { RDESC_END },
  /* 2: NS */     { RDESC_DOMAIN, RDESC_END },
  /* 3: .. */     { RDESC_END },
  /* 4: .. */     { RDESC_END },
  /* 5: CNAME */  { RDESC_DOMAIN, RDESC_END },
  /* 6: SOA */    { RDESC_DOMAIN, RDESC_DOMAIN, RDESC_END },
  /* 7: */        { RDESC_END },
  /* 8: */        { RDESC_END },
  /* 9: */        { RDESC_END },
  /* 10: */       { RDESC_END },
  /* 11: */       { RDESC_END },
  /* 12: */       { RDESC_END },
  /* 13: */       { RDESC_END },
  /* 14: */       { RDESC_END },
  /* 15: MX */    { 2, RDESC_DOMAIN, RDESC_END },
};


/* On-the-fly rdata canonicalization
 *
 * This set of functions allow the user to iterate over the rdata section of a RR
 * while canonicalizing it on-the-fly. This is a great memory saving since the user
 * doesn't need to allocate memory for a copy of the whole rdata section.
 *
 * Sample usage:
 *
 *    RDataCFrom cf;
 *    rdata_cfrom_init(
 *       &cf,
 *       header, pktlen,     // dns_header
 *       rdata,              // pointer to rdata section
 *       rrtype,             // RR tyep
 *       tmpbuf);            // temporary buf (MAXCDNAME)
 *
 *    while ((p = rdata_cfrom_next(&cf, &len))
 *      {
 *         // Process p[0..len]
 *      }
 *
 *    if (rdata_cfrom_error(&cf))
 *      // error occurred while parsing
 *
 */
typedef struct
{
  struct dns_header *header;
  size_t pktlen;
  unsigned char *rdata;
  unsigned char *tmpbuf;
  size_t rdlen;
  int rrtype;
  int cnt;
} RDataCForm;

static void rdata_cform_init(RDataCForm *ctx, struct dns_header *header, size_t pktlen,
                             unsigned char *rdata, int rrtype, unsigned char *tmpbuf)
{
  if (rrtype >= countof(rdata_description))
    rrtype = 0;
  ctx->header = header;
  ctx->pktlen = pktlen;
  ctx->rdata = rdata;
  ctx->rrtype = rrtype;
  ctx->tmpbuf = tmpbuf;
  ctx->cnt = -1;
  GETSHORT(ctx->rdlen, ctx->rdata);
}

static int rdata_cform_error(RDataCForm *ctx)
{
  return ctx->cnt == -2;
}

static unsigned char *rdata_cform_next(RDataCForm *ctx, size_t *len)
{
  if (ctx->cnt != -1 && rdata_description[ctx->rrtype][ctx->cnt] == RDESC_END)
    return NULL;

  int d = rdata_description[ctx->rrtype][++ctx->cnt];
  if (d == RDESC_DOMAIN)
    {
      *len = process_domain_name(ctx->header, ctx->pktlen, &ctx->rdata, &ctx->rdlen, ctx->tmpbuf, PWN_EXTRACT);
      if (!*len)
        {
          ctx->cnt = -2;
          return NULL;
        }
      return ctx->tmpbuf;
    }
  else if (d == RDESC_END)
    {
      *len = ctx->rdlen;
      return ctx->rdata;
    }
  else
    {
      unsigned char *ret = ctx->rdata;
      ctx->rdlen -= d;
      ctx->rdata += d;
      *len = d;
      return ret;
    }
}


/* Check whether today/now is between date_start and date_end */
static int check_date_range(unsigned long date_start, unsigned long date_end)
{
  /* TODO: double-check that time(0) is the correct time we are looking for */
  /* TODO: dnssec requires correct timing; implement SNTP in dnsmasq? */
  unsigned long curtime = time(0);

  /* We must explicitly check against wanted values, because of SERIAL_UNDEF */
  return serial_compare_32(curtime, date_start) == SERIAL_GT
         && serial_compare_32(curtime, date_end) == SERIAL_LT;
}


/* Sort RRs within a RRset in canonical order, according to RFC4034, §6.3
   Notice that the RRDATA sections have been already normalized, so a memcpy
   is sufficient.
   NOTE: r1/r2 point immediately after the owner name. */

struct {
  struct dns_header *header;
  size_t pktlen;
} rrset_canonical_order_ctx;

static int rrset_canonical_order(const void *r1, const void *r2)
{
  size_t r1len, r2len;
  int rrtype;
  unsigned char *pr1=*(unsigned char**)r1, *pr2=*(unsigned char**)r2;
  unsigned char tmp1[MAXCDNAME], tmp2[MAXCDNAME];   /* TODO: use part of daemon->namebuff */
  
  GETSHORT(rrtype, pr1);
  pr1 += 6; pr2 += 8;

  RDataCForm cf1, cf2;
  rdata_cform_init(&cf1, rrset_canonical_order_ctx.header, rrset_canonical_order_ctx.pktlen,
                   pr1, rrtype, tmp1);
  rdata_cform_init(&cf2, rrset_canonical_order_ctx.header, rrset_canonical_order_ctx.pktlen,
                   pr2, rrtype, tmp2);
  while ((pr1 = rdata_cform_next(&cf1, &r1len)) &&
         (pr2 = rdata_cform_next(&cf2, &r2len)))
    {
      int res = memcmp(pr1, pr2, MIN(r1len,r2len));
      if (res != 0)
        return res;
      if (r1len < r2len)
        return -1;
      if (r2len > r1len)
        return 1;
    }

  /* If we reached this point, the two RRs are identical (or an error occurred).
     RFC2181 says that an RRset is not allowed to contain duplicate
     records. If it happens, it is a protocol error and anything goes. */
  return 1;
}

typedef struct PendingRRSIGValidation
{
  VerifyAlgCtx *alg;
  char *signer_name;
  int keytag;
} PendingRRSIGValidation;


/* Convert from presentation format to wire format, in place.
   Also map UC -> LC.
   Note that using extract_name to get presentation format
   then calling to_wire() removes compression and maps case,
   thus generating names in canonical form.
   Calling to_wire followed by from_wire is almost an identity,
   except that the UC remains mapped to LC. 
*/
static int to_wire(char *name)
{
  unsigned char *l, *p, term;
  int len;

  for (l = (unsigned char*)name; *l != 0; l = p)
    {
      for (p = l; *p != '.' && *p != 0; p++)
	if (*p >= 'A' && *p <= 'Z')
	  *p = *p - 'A' + 'a';
      
      term = *p;
      
      if ((len = p - l) != 0)
	memmove(l+1, l, len);
      *l = len;
      
      p++;
      
      if (term == 0)
	*p = 0;
    }
  
  return l + 1 - (unsigned char *)name;
}

/* Note: no compression  allowed in input. */
static void from_wire(char *name)
{
  unsigned char *l;
  int len;

  for (l = (unsigned char *)name; *l != 0; l += len+1)
    {
      len = *l;
      memmove(l, l+1, len);
      l[len] = '.';
    }

  *(l-1) = 0;
}


/* Pass a resource record's rdata field through the currently-initailized digest algorithm.

   We must pass the record in DNS wire format, but if the record contains domain names,
   they must be uncompressed. This makes things very tricky, because  */
static int digestalg_add_rdata(int sigtype, struct dns_header *header, size_t pktlen,
                               unsigned char *rdata)
{
  size_t len;
  unsigned char *p;
  unsigned short total;
  unsigned char tmpbuf[MAXDNAME]; /* TODO: reuse part of daemon->namebuff */
  RDataCForm cf1, cf2;

  /* Initialize two iterations over the canonical form*/
  rdata_cform_init(&cf1, header, pktlen, rdata, sigtype, tmpbuf);
  cf2 = cf1;

  /* Iteration 1: go through the canonical record and count the total octects.
     This number might be different from the non-canonical rdata length
     because of domain names compression. */
  total = 0;
  while ((p = rdata_cform_next(&cf1, &len)))
    total += len;
  if (rdata_cform_error(&cf1))
    return 0;

  /* Iteration 2: process the canonical record through the hash function */
  total = htons(total);
  digestalg_add_data(&total, 2);

  while ((p = rdata_cform_next(&cf2, &len)))
    digestalg_add_data(p, len);

  return 1;
}

size_t dnssec_generate_query(struct dns_header *header, char *name, int class, int type, union mysockaddr *addr)
{
  unsigned char *p;
  char types[20];
  
  querystr("dnssec", types, type);

  if (addr->sa.sa_family == AF_INET) 
    log_query(F_DNSSEC | F_IPV4, name, (struct all_addr *)&addr->in.sin_addr, types);
#ifdef HAVE_IPV6
  else
    log_query(F_DNSSEC | F_IPV6, name, (struct all_addr *)&addr->in6.sin6_addr, types);
#endif
  
  header->qdcount = htons(1);
  header->ancount = htons(0);
  header->nscount = htons(0);
  header->arcount = htons(0);

  header->hb3 = HB3_RD; 
  SET_OPCODE(header, QUERY);
  header->hb4 = HB4_CD;

  /* ID filled in later */

  p = (unsigned char *)(header+1);
	
  p = do_rfc1035_name(p, name);
  *p++ = 0;
  PUTSHORT(type, p);
  PUTSHORT(class, p);

  return add_do_bit(header, p - (unsigned char *)header, ((char *) header) + PACKETSZ);
}
  
/* The DNS packet is expected to contain the answer to a DNSKEY query.
   Leave name of qury in name.
   Put all DNSKEYs in the answer which are valid into the cache.
   return codes:
         STAT_INSECURE bad packet, no DNSKEYs in reply.
	 STAT_SECURE   At least one valid DNSKEY found and in cache.
	 STAT_BOGUS    No DNSKEYs found, which  can be validated with DS,
	               or self-sign for DNSKEY RRset is not valid.
	 STAT_NEED_DS  DS records to validate a key not found, name in keyname 
*/
int dnssec_validate_by_ds(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, int class)
{
  unsigned char *psave, *p = (unsigned char *)(header+1);
  struct crec *crecp, *recp1;
  int rc, j, qtype, qclass, ttl, rdlen, flags, algo, valid, keytag;
  struct blockdata *key;

  if (ntohs(header->qdcount) != 1)
    return STAT_INSECURE;
 
  if (!extract_name(header, plen, &p, name, 1, 4))
    return STAT_INSECURE;
  
  GETSHORT(qtype, p);
  GETSHORT(qclass, p);
  
  if (qtype != T_DNSKEY || qclass != class || ntohs(header->ancount) == 0)
    return STAT_INSECURE;

   /* See if we have cached a DS record which validates this key */
  if (!(crecp = cache_find_by_name(NULL, name, now, F_DS)))
    {
      strcpy(keyname, name);
      return STAT_NEED_DS;
    }

  cache_start_insert();

  /* NOTE, we need to find ONE DNSKEY which matches the DS */
  for (valid = 0, j = ntohs(header->ancount); j != 0; j--) 
    {
      /* Ensure we have type, class  TTL and length */
      if (!(rc = extract_name(header, plen, &p, name, 0, 10)))
	return STAT_INSECURE; /* bad packet */
  
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);

      if (qclass != class || qtype != T_DNSKEY || rc == 2)
	{
	  if (ADD_RDLEN(header, p, plen, rdlen))
	    continue;

	  return STAT_INSECURE; /* bad packet */
	}
      
      if (!CHECK_LEN(header, p, plen, rdlen) || rdlen < 4)
	return STAT_INSECURE; /* bad packet */
      
      psave = p;
      
      /* length at least covers flags, protocol and algo now. */
      GETSHORT(flags, p);
      if (*p++ != 3)
	return STAT_INSECURE;
      algo = *p++;
      keytag = dnskey_keytag(algo, flags, p, rdlen - 4);
      
      /* Put the key into the cache. Note that if the validation fails, we won't
	 call cache_end_insert() and this will never be committed. */
      if ((key = blockdata_alloc((char*)p, rdlen - 4)) &&
	  (recp1 = cache_insert(name, NULL, now, ttl, F_FORWARD | F_DNSKEY)))
	{
	  recp1->uid = rdlen - 4;
	  recp1->addr.key.keydata = key;
	  recp1->addr.key.algo = algo;
	  recp1->addr.key.keytag = keytag;
	}
      
      p = psave;
      if (!ADD_RDLEN(header, p, plen, rdlen))
	return STAT_INSECURE; /* bad packet */
      
      /* Already determined that message is OK. Just loop stuffing cache */ 
      if (valid || !key)
	continue;
      
      for (recp1 = crecp; recp1; recp1 = cache_find_by_name(recp1, name, now, F_DS))
	if (recp1->addr.key.algo == algo && 
	    recp1->addr.key.keytag == keytag &&
	    (flags & 0x100) && /* zone key flag */
	    digestalg_supported(recp1->addr.key.digest))
	  {
	    int wire_len = to_wire(name);
	    
	    digestalg_begin(recp1->addr.key.digest);
	    digestalg_add_data(name, wire_len);
	    digestalg_add_data((char *)psave, rdlen);
	    
	    from_wire(name);

	    /* TODO fragented digest */
	    if (memcmp(digestalg_final(), recp1->addr.key.keydata->key, digestalg_len()) == 0 &&
		validate_rrset(now, header, plen, class, T_DNSKEY, name, keyname, key, rdlen - 4, algo, keytag))
	      {
		struct all_addr a;
		valid = 1;
		a.addr.keytag = keytag;
		log_query(F_KEYTAG | F_UPSTREAM, name, &a, "DNSKEY keytag %u");
		break;
	      }
	  }
    }

  if (valid)
    {
      /* commit cache insert. */
      cache_end_insert();
      return STAT_SECURE;
    }

  log_query(F_UPSTREAM, name, NULL, "BOGUS DNSKEY");
  return STAT_BOGUS;
}


/* The DNS packet is expected to contain the answer to a DS query
   Leave name of DS query in name.
   Put all DSs in the answer which are valid into the cache.
   return codes:
   STAT_INSECURE    bad packet, no DS in reply.
   STAT_SECURE      At least one valid DS found and in cache.
   STAT_BOGUS       At least one DS found, which fails validation.
   STAT_NEED_DNSKEY DNSKEY records to validate a DS not found, name in keyname
*/

int dnssec_validate_ds(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, int class)
{
  unsigned char *psave, *p = (unsigned char *)(header+1);
  struct crec *crecp;
  int qtype, qclass, val, j, gotone;
  struct blockdata *key;

  if (ntohs(header->qdcount) != 1)
    return STAT_INSECURE;
 
  if (!extract_name(header, plen, &p, name, 1, 4))
    return STAT_INSECURE;
   
  GETSHORT(qtype, p);
  GETSHORT(qclass, p);

  if (qtype != T_DS || qclass != class || ntohs(header->ancount) == 0)
    return STAT_INSECURE;
  
  val = validate_rrset(now, header, plen, class, T_DS, name, keyname, NULL, 0, 0, 0);
 
  if (val == STAT_BOGUS)
    log_query(F_UPSTREAM, name, NULL, "BOGUS DS");

  /* failed to validate or missing key. */
  if (val != STAT_SECURE)
    return val;
  
  cache_start_insert();

  for (gotone = 0, j = ntohs(header->ancount); j != 0; j--) 
    {
      int ttl, rdlen, rc, algo, digest, keytag;
      
      /* Ensure we have type, class  TTL and length */
      if (!(rc = extract_name(header, plen, &p, name, 0, 10)))
	return STAT_INSECURE; /* bad packet */
      
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);
      
      /* check type, class and name, skip if not in DS rrset */
      if (qclass == class && qtype == T_DS && rc == 1)
	{
	  if (!CHECK_LEN(header, p, plen, rdlen) || rdlen < 4)
	    return STAT_INSECURE; /* bad packet */
	  
	  psave = p;
	  GETSHORT(keytag, p);
	  algo = *p++;
	  digest = *p++;
	  
	  /* We've proved that the DS is OK, store it in the cache */
	  if ((key = blockdata_alloc((char*)p, rdlen - 4)) &&
	      (crecp = cache_insert(name, NULL, now, ttl, F_FORWARD | F_DS)))
	    {
	      struct all_addr a;
	      a.addr.keytag = keytag;
	      log_query(F_KEYTAG | F_UPSTREAM, name, &a, "DS keytag %u");
	      crecp->addr.key.digest = digest;
	      crecp->addr.key.keydata = key;
	      crecp->addr.key.algo = algo;
	      crecp->addr.key.keytag = keytag;
	    }
	  else
	    return STAT_INSECURE; /* cache problem */
	  
	  p = psave;
	}

      if (!ADD_RDLEN(header, p, plen, rdlen))
	return STAT_INSECURE; /* bad packet */
     
    }
  
  cache_end_insert();  
  
  return STAT_SECURE;
}



/* Validate a single RRset (class, type, name) in the supplied DNS reply 
   Return code:
   STAT_SECURE   if it validates.
   STAT_INSECURE can't validate (no RRSIG, bad packet).
   STAT_BOGUS    signature is wrong.
   STAT_NEED_KEY need DNSKEY to complete validation (name is returned in keyname)

   if key is non-NULL, use that key, which has the algo and tag given in the params of those names,
   otherwise find the key in the cache.
*/
int validate_rrset(time_t now, struct dns_header *header, size_t plen, int class, 
		   int type, char *name, char *keyname, struct blockdata *key, int keylen, int algo_in, int keytag_in)
{
  unsigned char *p;
  int rrsetidx, sigidx, res, rdlen, j;
  struct crec *crecp = NULL;
  void *rrset[MAXRRSET], *sigs[MAXRRSET];  /* TODO: max RRset size? */
  int type_covered, algo, labels, orig_ttl, sig_expiration, sig_inception, key_tag;

  if (!(p = skip_questions(header, plen)))
    return STAT_INSECURE;

  /* look for an RRSIG record for this RRset and get pointers to each record */
  for (rrsetidx = 0, sigidx = 0, j = ntohs(header->ancount) + ntohs(header->nscount); 
       j != 0; j--) 
    {
      unsigned char *pstart;
      int stype, sclass, sttl;

      if (!(res = extract_name(header, plen, &p, name, 0, 10)))
	return STAT_INSECURE; /* bad packet */
      
      pstart = p;
      
      GETSHORT(stype, p);
      GETSHORT(sclass, p);
      GETLONG(sttl, p);
      GETSHORT(rdlen, p);
      
      (void)sttl;
        
      if (!CHECK_LEN(header, p, plen, rdlen))
	 return STAT_INSECURE; /* bad packet */

      if (res == 1 && sclass == class)
	{
	  if (stype == type)
	    {
	      rrset[rrsetidx++] = pstart;
	      if (rrsetidx == MAXRRSET)
		return STAT_INSECURE; /* RRSET too big TODO */
	    }
	  
	  if (stype == T_RRSIG)
	    {
	      sigs[sigidx++] = pstart;
	      if (sigidx == MAXRRSET)
		return STAT_INSECURE; /* RRSET too big TODO */
	    }
	}
     
      if (!ADD_RDLEN(header, p, plen, rdlen))
	return STAT_INSECURE;
    }
  
  /* RRset empty, no RRSIGs */
  if (rrsetidx == 0 || sigidx == 0)
    return STAT_INSECURE;
     
  /* Now try all the sigs to try and find one which validates */
  for (j = 0; j <sigidx; j++)
    {
      unsigned char *psav;
      int i, wire_len;
      VerifyAlgCtx *alg;
      u16 ntype, nclass;
      u32 nsigttl;
      
      p = sigs[j] + 8; /* skip type, class and ttl */
      
      GETSHORT(rdlen, p);
      
      if (rdlen < 18)
	return STAT_INSECURE; /* bad packet */ 
      
      psav = p;
      
      GETSHORT(type_covered, p);
      algo = *p++;
      labels = *p++;
      GETLONG(orig_ttl, p);
      GETLONG(sig_expiration, p);
      GETLONG(sig_inception, p);
      GETSHORT(key_tag, p);
      
      if (type_covered != type ||
	  !check_date_range(sig_inception, sig_expiration) ||
	  !verifyalg_supported(algo))
	{
	  /* covers wrong type or out of date - skip */
	  p = psav;
	  if (!ADD_RDLEN(header, p, plen, rdlen))
	    return STAT_INSECURE;
	  continue;
	}
      
      if (!extract_name(header, plen, &p, keyname, 1, 0))
	return STAT_INSECURE;
      
      /* OK, we have the signature record, see if the relevant DNSKEY is in the cache. */
      if (!key && !(crecp = cache_find_by_name(NULL, keyname, now, F_DNSKEY)))
	return STAT_NEED_KEY;
      
      /* Sort RRset records in canonical order. */
      rrset_canonical_order_ctx.header = header;
      rrset_canonical_order_ctx.pktlen = plen;
      qsort(rrset, rrsetidx, sizeof(void*), rrset_canonical_order);
      
      alg = verifyalg_alloc(algo);
      alg->sig = p;
      alg->siglen = rdlen - (p - psav);
       
      ntype = htons(type);
      nclass = htons(class);
      nsigttl = htonl(orig_ttl);
      
      digestalg_begin(alg->vtbl->digest_algo);
      digestalg_add_data(psav, 18);
      wire_len = to_wire(keyname);
      digestalg_add_data(keyname, wire_len);
      from_wire(keyname);
      
      /* TODO wildcard rules : 4035 5.3.2 */
      for (i = 0; i < rrsetidx; ++i)
	{
	  p = (unsigned char*)(rrset[i]);
	  
	  wire_len = to_wire(name);
	  digestalg_add_data(name, wire_len);
	  from_wire(name);
	  digestalg_add_data(&ntype, 2);
	  digestalg_add_data(&nclass, 2);
	  digestalg_add_data(&nsigttl, 4);
	  
	  p += 8;
	  if (!digestalg_add_rdata(type, header, plen, p))
	    return STAT_INSECURE;
	}
    
      memcpy(alg->digest, digestalg_final(),  digestalg_len());

      if (key)
	{
	  if (algo_in == algo && keytag_in == key_tag &&
	      alg->vtbl->verify(alg, key, keylen))
	    return STAT_SECURE;
	}
      else
	{
	  /* iterate through all possible keys 4035 5.3.1 */
	  for (; crecp; crecp = cache_find_by_name(crecp, keyname, now, F_DNSKEY))
	    if (crecp->addr.key.algo == algo && crecp->addr.key.keytag == key_tag &&
		alg->vtbl->verify(alg, crecp->addr.key.keydata, crecp->uid))
	      return STAT_SECURE;
	}
    }

  return STAT_BOGUS;
}
 

/* Validate all the RRsets in the answer and authority sections of the reply (4035:3.2.3) */
int dnssec_validate_reply(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, int *class)
{
  unsigned char *ans_start, *p1, *p2;
  int type1, class1, rdlen1, type2, class2, rdlen2;
  int i, j, rc;

  if (!(ans_start = skip_questions(header, plen)))
    return STAT_INSECURE;
   
  for (p1 = ans_start, i = 0; i < ntohs(header->ancount) + ntohs(header->nscount); i++)
    {
      if (!extract_name(header, plen, &p1, name, 1, 10))
	return STAT_INSECURE; /* bad packet */
      
      GETSHORT(type1, p1);
      GETSHORT(class1, p1);
      p1 += 4; /* TTL */
      GETSHORT(rdlen1, p1);
      
      /* Don't try and validate RRSIGs! */
      if (type1 != T_RRSIG)
	{
	  /* Check if we've done this RRset already */
	  for (p2 = ans_start, j = 0; j < i; j++)
	    {
	      if (!(rc = extract_name(header, plen, &p2, name, 0, 10)))
		return STAT_INSECURE; /* bad packet */
	      
	      GETSHORT(type2, p2);
	      GETSHORT(class2, p2);
	      p2 += 4; /* TTL */
	      GETSHORT(rdlen2, p2);
	      
	      if (type2 == type1 && class2 == class1 && rc == 1)
		break; /* Done it before: name, type, class all match. */
	      
	      if (!ADD_RDLEN(header, p2, plen, rdlen2))
		return STAT_INSECURE;
	    }
	  
	  /* Not done, validate now */
	  if (j == i && (rc = validate_rrset(now, header, plen, class1, type1, name, keyname, NULL, 0, 0, 0)) != STAT_SECURE)
	    {
	      *class = class1; /* Class for DS or DNSKEY */
	      return rc;
	    }
	}

      if (!ADD_RDLEN(header, p1, plen, rdlen1))
	return STAT_INSECURE;
    }

  return STAT_SECURE;
}


/* Compute keytag (checksum to quickly index a key). See RFC4034 */
int dnskey_keytag(int alg, int flags, unsigned char *key, int keylen)
{
  if (alg == 1)
    {
      /* Algorithm 1 (RSAMD5) has a different (older) keytag calculation algorithm.
         See RFC4034, Appendix B.1 */
      return key[keylen-4] * 256 + key[keylen-3];
    }
  else
    {
      unsigned long ac;
      int i;

      ac = ((htons(flags) >> 8) | ((htons(flags) << 8) & 0xff00)) + 0x300 + alg;
      for (i = 0; i < keylen; ++i)
        ac += (i & 1) ? key[i] : key[i] << 8;
      ac += (ac >> 16) & 0xffff;
      return ac & 0xffff;
    }
}


#endif /* HAVE_DNSSEC */
