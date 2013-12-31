/* dnssec.c is Copyright (c) 2012 Giovanni Bajo <rasky@develer.com>

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
#include "dnssec-crypto.h"
#include <assert.h>

/* Maximum length in octects of a domain name, in wire format */
#define MAXCDNAME  256

#define MAXRRSET 16

#define SERIAL_UNDEF  -100
#define SERIAL_EQ        0
#define SERIAL_LT       -1
#define SERIAL_GT        1

static int dnskey_keytag(int alg, unsigned char *rdata, int rdlen);

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

/* Extract a DNS name from wire format, without handling compression. This is
   faster than extract_name() and does not require access to the full dns
   packet. */
static int extract_name_no_compression(unsigned char *rr, int maxlen, char *buf)
{
  unsigned char *start=rr, *end = rr+maxlen;
  int count;
  
  while (rr < end && *rr != 0)
    {
      count = *rr++;
      while (count-- > 0 && rr < end)
        {
          *buf = *rr++;
          if (!isascii(*buf) || iscntrl(*buf) || *buf == '.')
            return 0;
          if (*buf >= 'A' && *buf <= 'Z')
            *buf += 'a' - 'A';
          buf++;
        }
      *buf++ = '.';
    }
  /* Remove trailing dot (if any) */
  if (rr != start)
    *(--buf) = 0;
  if (rr == end)
    return 0;
  /* Trailing \0 in source data must be consumed */
  return rr-start+1;
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

/* strchrnul - like strchr, but when character is not found, returns a pointer to the terminating \0.

   This is an existing C GNU extension, but it's easier to reimplement it,
   rather than tweaking with configure. */
static char *my_strchrnul(char *str, char ch)
{
  while (*str && *str != ch)
    str++;
  return str;
}

/* Convert a domain name to wire format */
static int convert_domain_to_wire(char *name, unsigned char* out)
{
  unsigned char len;
  unsigned char *start = out;
  char *p;

  do
    {
      p = my_strchrnul(name, '.');
      if ((len = p-name))
        {
          *out++ = len;
          while (len--)
            {
              char ch = *name++;
              /* TODO: this will not be required anymore once we
                 remove all usages of extract_name() from DNSSEC code */
              if (ch >= 'A' && ch <= 'Z')
                ch = ch - 'A' + 'a';
              *out++ = ch;
            }
        }
      name = p+1;
    }
  while (*p);

  *out++ = '\0';
  return out-start;
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

size_t dnssec_generate_query(struct dns_header *header, char *name, int class, int type)
{
  unsigned char *p;

  header->qdcount = htons(1);
  header->ancount = htons(0);
  header->nscount = htons(0);
  header->arcount = htons(0);

  header->hb3 =  HB3_RD; 
  SET_OPCODE(header, QUERY);
  header->hb4 = 0;

  /* ID filled in later */

  p = (unsigned char *)(header+1);
	
  p = do_rfc1035_name(p, name);
  PUTSHORT(type, p);
  PUTSHORT(class, p);

  return add_do_bit(header, p - (unsigned char *)header, ((char *) header) + PACKETSZ);
}
  
/* The DNS packet is expected to contain the answer to a DNSKEY query
   Put all DNSKEYs in the answer which are valid into the cache.
   return codes:
         STAT_INSECURE bad packet, no DNSKEYs in reply.
	 STAT_SECURE   At least one valid DNSKEY found and in cache.
	 STAT_BOGUS    At least one DNSKEY found, which fails validation.
	 STAT_NEED_DS  DS records to validate a key not found, name in namebuff 
*/
int dnssec_validate_by_ds(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, int class)
{
  unsigned char *p;
  struct crec *crecp, *recp1;
  int j, qtype, qclass, ttl, rdlen, flags, protocol, algo, gotone;
  struct blockdata *key;

  if (ntohs(header->qdcount) != 1)
    return STAT_INSECURE;
 
  if (!extract_name(header, plen, &p, name, 1, 4))
    return STAT_INSECURE;
  
  GETSHORT(qtype, p);
  GETSHORT(qclass, p);
  
  if (qtype != T_DNSKEY || qclass != class)
    return STAT_INSECURE;

  cache_start_insert();

  for (gotone = 0, j = ntohs(header->ancount); j != 0; j--) 
    {
      /* Ensure we have type, class  TTL and length */
      if (!extract_name(header, plen, &p, name, 1, 10))
	return STAT_INSECURE; /* bad packet */
  
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);

      if (qclass != class || qtype != T_DNSKEY || rdlen < 4)
	{
	  /* skip all records other than DNSKEY */
	  p += rdlen;
	  continue;
	}
      
      crecp = cache_find_by_name(NULL, name, now, F_DS);
      
      /* length at least covers flags, protocol and algo now. */
      GETSHORT(flags, p);
      protocol = *p++;
      algo = *p++;

      /* See if we have cached a DS record which validates this key */
      for (recp1 = crecp; recp1; recp1 = cache_find_by_name(recp1, name, now, F_DS))
	if (recp1->addr.key.algo == algo && is_supported_digest(recp1->addr.key.digest))
	  break;
      
      /* DS record needed to validate key is missing, return name of DS in namebuff */
      if (!recp1)
	return STAT_NEED_DS;
      else
	{
	  int valid = 1;
	  /* calculate digest of canonicalised DNSKEY data using digest in  (recp1->addr.key.digest) 
	     and see if it equals digest stored in recp1
	  */
	  
	  if (!valid)
	    return STAT_BOGUS;
	}
      
      if ((key = blockdata_alloc((char*)p, rdlen)))
	{
	  
	  /* We've proved that the KEY is OK, store it in the cache */
	  if ((crecp = cache_insert(name, NULL, now, ttl, F_FORWARD | F_DNSKEY)))
	    {
	      crecp->uid = rdlen;
	      crecp->addr.key.keydata = key;
	      crecp->addr.key.algo = algo;
	      crecp->addr.key.keytag = dnskey_keytag(algo, (char*)p, rdlen);
	      gotone = 1;
	    }
	}
      
    }
  
  cache_end_insert();  

      
  return gotone ? STAT_SECURE : STAT_INSECURE;
}
/* The DNS packet is expected to contain the answer to a DS query
   Put all DSs in the answer which are valid into the cache.
   return codes:
   STAT_INSECURE    bad packet, no DNSKEYs in reply.
   STAT_SECURE      At least one valid DS found and in cache.
   STAT_BOGUS       At least one DS found, which fails validation.
   STAT_NEED_DNSKEY DNSKEY records to validate a DS not found, name in keyname
*/

int dnssec_validate_ds(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, int class)
{
  unsigned char *p = (unsigned char *)(header+1);
  struct crec *crecp, *recp1;
  int qtype, qclass, val, j, gotone;
  struct blockdata *key;

  if (ntohs(header->qdcount) != 1)
    return STAT_INSECURE;
 
  if (!extract_name(header, plen, &p, name, 1, 4))
    return STAT_INSECURE;
   
  GETSHORT(qtype, p);
  GETSHORT(qclass, p);

  if (qtype != T_DS || qclass != class)
    return STAT_INSECURE;

  val = validate_rrset(header, plen, class, T_DS, name, keyname);

  /* failed to validate or missing key. */
  if (val != STAT_SECURE)
    return val;
  
  cache_start_insert();

  for (gotone = 0, j = ntohs(header->ancount); j != 0; j--) 
    {
      int ttl, rdlen, rc, algo;
      
      /* Ensure we have type, class  TTL and length */
      if (!(rc = extract_name(header, plen, &p, name, 0, 10)))
	return STAT_INSECURE; /* bad packet */
      
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);
      
      /* check type, class and name, skip if not in DS rrset */
      if (qclass != class || qtype != T_DS || rc == 2)
	{
	  p += rdlen;
	  continue;
	}
      
      if ((key = blockdata_alloc((char*)p, rdlen)))
	{
	  
	  /* We've proved that the DS is OK, store it in the cache */
	  if ((crecp = cache_insert(name, NULL, now, ttl, F_FORWARD | F_DS)))
	    {
	      crecp->uid = rdlen;
	      crecp->addr.key.keydata = key;
	      crecp->addr.key.algo = algo;
	      crecp->addr.key.keytag = dnskey_keytag(algo, (char*)p, rdlen);
	      gotone = 1;
	    }
	}
      
    }
  
  cache_end_insert();  
  
  
  return gotone ? STAT_SECURE : STAT_INSECURE;
}



/* Validate a single RRset (class, type, name) in the supplied DNS reply 
   Return code:
   STAT_SECURE   if it validates.
   STAT_INSECURE can't validate (no RRSIG, bad packet).
   STAT_BOGUS    signature is wrong.
   STAT_NEED_KEY need DNSKEY to complete validation (name is returned in keyname)
*/
int validate_rrset(time_t now, struct dns_header *header, size_t plen, int class, int type, char *name, char *keyname)
{
  unsigned char *p, *psav, *sig;
  int rrsetidx, res, sigttl, sig_data_len, j;
  struct crec *crecp;
  void *rrset[MAXRRSET];  /* TODO: max RRset size? */
  int type_covered, algo, labels, orig_ttl, sig_expiration, sig_inception, key_tag;

  if (!(p = skip_questions(header, plen)))
    return STAT_INSECURE;

  /* look for an RRSIG record for this RRset and get pointers to each record */
  for (rrsetidx = 0, sig = NULL, j = ntohs(header->ancount) + ntohs(header->nscount); 
       j != 0; j--) 
    {
      unsigned char *pstart = p;
      int stype, sclass, sttl, rdlen;

      if (!(res = extract_name(header, plen, &p, name, 0, 10)))
	return STAT_INSECURE; /* bad packet */
      
      GETSHORT(stype, p);
      GETSHORT(sclass, p);
      GETLONG(sttl, p);
      GETSHORT(rdlen, p);
        
      if (!CHECK_LEN(header, p, plen, rdlen))
	 return STAT_INSECURE; /* bad packet */

      if (res == 2 || htons(stype) != T_RRSIG || htons(sclass) != class)
	continue;

      if (htons(stype) == type)
	{
	  rrset[rrsetidx++] = pstart;
          if (rrsetidx == MAXRRSET)
	    return STAT_INSECURE; /* RRSET too big TODO */
	}

      if (htons(stype) == T_RRSIG)
	{
	  /* name matches, RRSIG for correct class */
	  /* enough data? */
	  if (rdlen < 18)
	    return STAT_INSECURE; 
	  
	  GETSHORT(type_covered, p);
	  algo = *p++;
	  labels = *p++;
	  GETLONG(orig_ttl, p);
	  GETLONG(sig_expiration, p);
	  GETLONG(sig_inception, p);
	  GETSHORT(key_tag, p);
	  
	  if (type_covered != type ||
	      !check_date_range(sig_inception, sig_expiration))
	    {
	      /* covers wrong type or out of date - skip */
	      p = psav;
	      if (!ADD_RDLEN(header, p, plen, rdlen))
		return STAT_INSECURE;
	      continue;
	    }
	  
	  if (!extract_name(header, plen, &p, keyname, 1, 0))
	    return STAT_INSECURE;

	  /* OK, we have the signature record, see if the 
	     relevant DNSKEY is in the cache. */
	  for (crecp = cache_find_by_name(NULL, keyname, now, F_DNSKEY);
	       crecp;
	       crecp = cache_find_by_name(crecp, keyname, now, F_DNSKEY))
	    if (crecp->addr.key.algo == algo && crecp->addr.key.keytag == key_tag)
	      break;
	  
	  /* No, abort for now whilst we get it */
	  if (!crecp)
	    return STAT_NEED_KEY;

	  /* Save point to signature data */
	  sig = p;
	  sig_data_len = rdlen - (p - psav);
	  sigttl = sttl;

	  /* next record */
	  p = psav;
	  if (!ADD_RDLEN(header, p, plen, rdlen))
	    return STAT_INSECURE;
	}    
    }
  
  /* Didn't find RRSIG or RRset is empty */
  if (!sig || rrsetidx == 0)
    return STAT_INSECURE;
  
  /* OK, we have an RRSIG and an RRset and we have a the DNSKEY that validates them. */
  
  /* Sort RRset records in canonical order. */
  rrset_canonical_order_ctx.header = header;
  rrset_canonical_order_ctx.pktlen = plen;
  qsort(rrset, rrsetidx, sizeof(void*), rrset_canonical_order);

  /* Now initialize the signature verification algorithm and process the whole
     RRset */
  VerifyAlgCtx *alg = verifyalg_alloc(algo);
  if (!alg)
    return STAT_INSECURE;
 
  alg->sig = sig;
  alg->siglen = sig_data_len;
  
  u16 ntype = htons(type);
  u16 nclass = htons(class);
  u32 nsigttl = htonl(sigttl);

  /* TODO: we shouldn't need to convert this to wire here. Best solution would be:
     - Use process_name() instead of extract_name() everywhere in dnssec code
     - Convert from wire format to representation format only for querying/storing cache
  */
  unsigned char owner_wire[MAXCDNAME];
  int owner_wire_len = convert_domain_to_wire(name, owner_wire);
  
  digestalg_begin(alg->vtbl->digest_algo);
  digestalg_add_data(sigrdata, 18+signer_name_rdlen);
  for (i = 0; i < rrsetidx; ++i)
    {
      p = (unsigned char*)(rrset[i]);
      
      digestalg_add_data(owner_wire, owner_wire_len);
      digestalg_add_data(&ntype, 2);
      digestalg_add_data(&nclass, 2);
      digestalg_add_data(&nsigttl, 4);
    
      p += 8;
      if (!digestalg_add_rdata(ntohs(sigtype), header, pktlen, p))
        return 0;
    }
  int digest_len = digestalg_len();
  memcpy(alg->digest, digestalg_final(), digest_len);

  if (alg->vtbl->verify(alg,  crecp->addr.key.keydata, crecp_uid))
    return STAT_SECURE;
  
  return STAT_INSECURE;
}


#if 0
static int begin_rrsig_validation(struct dns_header *header, size_t pktlen,
                                  unsigned char *reply, int count, char *owner,
                                  int sigclass, int sigrdlen, unsigned char *sig,
                                  PendingRRSIGValidation *out)
{
  int i, res;
  int sigtype, sigalg, siglbl;
  unsigned char *sigrdata = sig;
  unsigned long sigttl, date_end, date_start;
  unsigned char* p = reply;
  char* signer_name = daemon->namebuff;
  int signer_name_rdlen;
  int keytag;
  void *rrset[16];  /* TODO: max RRset size? */
  int rrsetidx = 0;
  
  if (sigrdlen < 18)
    return 0;
  GETSHORT(sigtype, sig);
  sigalg = *sig++;
  siglbl = *sig++;
  GETLONG(sigttl, sig);
  GETLONG(date_end, sig);
  GETLONG(date_start, sig);
  GETSHORT(keytag, sig);
  sigrdlen -= 18;
  
  if (!verifyalg_supported(sigalg))
    {
      printf("ERROR: RRSIG algorithm not supported: %d\n", sigalg);
      return 0;
    }

  if (!check_date_range(date_start, date_end))
    {
      printf("ERROR: RRSIG outside date range\n");
      return 0;
    }

  /* Iterate within the answer and find the RRsets matching the current RRsig */
  for (i = 0; i < count; ++i)
    {    
      int qtype, qclass, rdlen;
      if (!(res = extract_name(header, pktlen, &p, owner, 0, 10)))
        return 0;
      rrset[rrsetidx] = p;
      GETSHORT(qtype, p);
      GETSHORT(qclass, p);
      p += 4; /* skip ttl */
      GETSHORT(rdlen, p);
      if (res == 1 && qtype == sigtype && qclass == sigclass)
        {
          ++rrsetidx;
          if (rrsetidx == countof(rrset))
            {
              /* Internal buffer too small */
              printf("internal buffer too small for this RRset\n");
              return 0;
            }
        }
      p += rdlen;
    }
  
  /* Sort RRset records in canonical order. */
  rrset_canonical_order_ctx.header = header;
  rrset_canonical_order_ctx.pktlen = pktlen;
  qsort(rrset, rrsetidx, sizeof(void*), rrset_canonical_order);
  
  /* Skip through the signer name; we don't extract it right now because
     we don't want to overwrite the single daemon->namebuff which contains
     the owner name. We'll get to this later. */
  if (!(p = skip_name(sig, header, pktlen, 0)))
    return 0;
  signer_name_rdlen = p - sig;
  sig = p; sigrdlen -= signer_name_rdlen;

  /* Now initialize the signature verification algorithm and process the whole
     RRset */
  VerifyAlgCtx *alg = verifyalg_alloc(sigalg);
  if (!alg)
    return 0;
  alg->sig = sig;
  alg->siglen = sigrdlen;
  
  sigtype = htons(sigtype);
  sigclass = htons(sigclass);
  sigttl = htonl(sigttl);

  /* TODO: we shouldn't need to convert this to wire here. Best solution would be:
     - Use process_name() instead of extract_name() everywhere in dnssec code
     - Convert from wire format to representation format only for querying/storing cache
   */
  unsigned char owner_wire[MAXCDNAME];
  int owner_wire_len = convert_domain_to_wire(owner, owner_wire);

  digestalg_begin(alg->vtbl->digest_algo);
  digestalg_add_data(sigrdata, 18+signer_name_rdlen);
  for (i = 0; i < rrsetidx; ++i)
    {
      p = (unsigned char*)(rrset[i]);

      digestalg_add_data(owner_wire, owner_wire_len);
      digestalg_add_data(&sigtype, 2);
      digestalg_add_data(&sigclass, 2);
      digestalg_add_data(&sigttl, 4);
    
      p += 8;
      if (!digestalg_add_rdata(ntohs(sigtype), header, pktlen, p))
        return 0;
    }
  int digest_len = digestalg_len();
  memcpy(alg->digest, digestalg_final(), digest_len);

  /* We don't need the owner name anymore; now extract the signer name */
  if (!extract_name_no_compression(sigrdata+18, signer_name_rdlen, signer_name))
    return 0;

  out->alg = alg;
  out->keytag = keytag;
  out->signer_name = signer_name;
  return 1;
}

static int end_rrsig_validation(PendingRRSIGValidation *val, struct crec *crec_dnskey)
{
  /* FIXME: keydata is non-contiguous */
  return val->alg->vtbl->verify(val->alg, crec_dnskey->addr.key.keydata, crec_dnskey->uid);
}


static void dnssec_parserrsig(struct dns_header *header, size_t pktlen,
                              unsigned char *reply, int count, char *owner,
                              int sigclass, int sigrdlen, unsigned char *sig)
{
  PendingRRSIGValidation val;

  /* Initiate the RRSIG validation process. The pending state is returned into val. */
  if (!begin_rrsig_validation(header, pktlen, reply, count, owner, sigclass, sigrdlen, sig, &val))
    return;

  printf("RRSIG: querying cache for DNSKEY %s (keytag: %d)\n", val.signer_name, val.keytag);

  /* Look in the cache for *all* the DNSKEYs with matching signer_name and keytag */
  char onekey = 0;
  struct crec *crecp = NULL;
  while ((crecp = cache_find_by_name(crecp, val.signer_name, time(0), F_DNSKEY)))  /* TODO: time(0) */
    {
      onekey = 1;

      if (crecp->addr.key.keytag == val.keytag
          && crecp->addr.key.algo == verifyalg_algonum(val.alg))
        {
          printf("RRSIG: found DNSKEY %d in cache, attempting validation\n", val.keytag);

          if (end_rrsig_validation(&val, crecp))
            printf("Validation OK\n");
          else
            printf("ERROR: Validation FAILED (%s, keytag:%d, algo:%d)\n", owner, val.keytag, verifyalg_algonum(val.alg));
        }
    }

  if (!onekey)
    {
      printf("DNSKEY not found, need to fetch it\n");
      /* TODO: store PendingRRSIGValidation in routing table,
         fetch key (and make it go through dnssec_parskey), then complete validation. */
    }
}

#endif /* comment out */

/* Compute keytag (checksum to quickly index a key). See RFC4034 */
static int dnskey_keytag(int alg, unsigned char *rdata, int rdlen)
{
  if (alg == 1)
    {
      /* Algorithm 1 (RSAMD5) has a different (older) keytag calculation algorithm.
         See RFC4034, Appendix B.1 */
      return rdata[rdlen-3] * 256 + rdata[rdlen-2];
    }
  else
    {
      unsigned long ac;
      int i;

      ac = 0;
      for (i = 0; i < rdlen; ++i)
        ac += (i & 1) ? rdata[i] : rdata[i] << 8;
      ac += (ac >> 16) & 0xFFFF;
      return ac & 0xFFFF;
    }
}

/* Check if the DS record (from cache) points to the DNSKEY record (from cache) */
static int dnskey_ds_match(struct crec *dnskey, struct crec *ds)
{
  if (dnskey->addr.key.keytag != ds->addr.key.keytag)
    return 0;
  if (dnskey->addr.key.algo != ds->addr.key.algo)
    return 0;

  unsigned char owner[MAXCDNAME];  /* TODO: user part of daemon->namebuff */
  int owner_len = convert_domain_to_wire(cache_get_name(ds), owner);
  size_t keylen = dnskey->uid;
  int dig = ds->uid;
  int digsize;

  if (!digestalg_begin(dig))
    return 0;
  digsize = digestalg_len();
  digestalg_add_data(owner, owner_len);
  digestalg_add_data("\x01\x01\x03", 3);
  digestalg_add_data(&ds->addr.key.algo, 1);
  digestalg_add_keydata(dnskey->addr.key.keydata, keylen);
  return (memcmp(digestalg_final(), ds->addr.key.keydata->key, digsize) == 0);
}

int dnssec_parsekey(struct dns_header *header, size_t pktlen, char *owner, unsigned long ttl,
                    int rdlen, unsigned char *rdata)
{
  int flags, proto, alg;
  struct blockdata *key; struct crec *crecp;
  unsigned char *ordata = rdata; int ordlen = rdlen;

  CHECKED_GETSHORT(flags, rdata, rdlen);
  CHECKED_GETCHAR(proto, rdata, rdlen);
  CHECKED_GETCHAR(alg, rdata, rdlen);

  if (proto != 3)
    return 0;
  /* Skip non-signing keys (as specified in RFC4034 */
  if (!(flags & 0x100))
    return 0;

  key = blockdata_alloc((char*)rdata, rdlen);

  /* TODO: time(0) is correct here? */
  crecp = cache_insert(owner, NULL, time(0), ttl, F_FORWARD | F_DNSKEY);
  if (crecp)
    {
      /* TODO: improve union not to name "uid" this field */
      crecp->uid = rdlen;
      crecp->addr.key.keydata = key;
      crecp->addr.key.algo = alg;
      crecp->addr.key.keytag = dnskey_keytag(alg, ordata, ordlen);
      printf("DNSKEY: storing key for %s (keytag: %d)\n", owner, crecp->addr.key.keytag);
    }
  else
    {
      blockdata_free(key);
      /* TODO: if insertion really might fail, verify we don't depend on cache
         insertion success for validation workflow correctness */
      printf("DNSKEY: cache insertion failure\n");
      return 0;
    }
  return 1;
}

int dnssec_parseds(struct dns_header *header, size_t pktlen, char *owner, unsigned long ttl,
                   int rdlen, unsigned char *rdata)
{
  int keytag, algo, dig;
  struct blockdata *key; struct crec *crec_ds, *crec_key;

  CHECKED_GETSHORT(keytag, rdata, rdlen);
  CHECKED_GETCHAR(algo, rdata, rdlen);
  CHECKED_GETCHAR(dig, rdata, rdlen);

  if (!digestalg_supported(dig))
    return 0;

  key = blockdata_alloc((char*)rdata, rdlen);

  /* TODO: time(0) is correct here? */
  crec_ds = cache_insert(owner, NULL, time(0), ttl, F_FORWARD | F_DS);
  if (!crec_ds)
    {
      blockdata_free(key);
      /* TODO: if insertion really might fail, verify we don't depend on cache
         insertion success for validation workflow correctness */
      printf("DS: cache insertion failure\n");
      return 0;
    }

  /* TODO: improve union not to name "uid" this field */
  crec_ds->uid = dig;
  crec_ds->addr.key.keydata = key;
  crec_ds->addr.key.algo = algo;
  crec_ds->addr.key.keytag = keytag;
  printf("DS: storing key for %s (digest: %d)\n", owner, dig);

  /* Now try to find a DNSKEY which matches this DS digest. */
  printf("Looking for a DNSKEY matching DS %d...\n", keytag);
  crec_key = NULL;
  while ((crec_key = cache_find_by_name(crec_key, owner, time(0), F_DNSKEY)))  /* TODO: time(0) */
    {
      if (dnskey_ds_match(crec_key, crec_ds))
        {
          /* TODO: create a link within the cache: ds => dnskey */
          printf("MATCH FOUND for keytag %d\n", keytag);
          return 1;
        }
    }

  printf("ERROR: match not found for DS %d (owner: %s)\n", keytag, owner);
  return 0;
}

int dnssec1_validate(struct dns_header *header, size_t pktlen)
{
  unsigned char *p, *reply;
  char *owner = daemon->namebuff;
  int i, s, qtype, qclass, rdlen;
  unsigned long ttl;
  int slen[3] = { ntohs(header->ancount), ntohs(header->nscount), ntohs(header->arcount) };

  if (slen[0] + slen[1] + slen[2] == 0)
    return 0;
  if (!(reply = p = skip_questions(header, pktlen)))
    return 0;

  /* First, process DNSKEY/DS records and add them to the cache. */
  cache_start_insert();
  for (i = 0; i < slen[0]; i++)
    {
      if (!extract_name(header, pktlen, &p, owner, 1, 10))
      	return 0;
      GETSHORT(qtype, p);
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);
      if (qtype == T_DS)
        {
          printf("DS found\n");
          dnssec_parseds(header, pktlen, owner, ttl, rdlen, p);
        }
      else if (qtype == T_DNSKEY)
        {
          printf("DNSKEY found\n");
          dnssec_parsekey(header, pktlen, owner, ttl, rdlen, p);
        }
      p += rdlen;
    }
  cache_end_insert();

  /* After we have cached DNSKEY/DS records, start looking for RRSIGs.
     We want to do this in a separate step because we want the cache
     to be already populated with DNSKEYs before parsing signatures. */
  p = reply;
  for (s = 0; s < 3; ++s)
    {
      reply = p;
      for (i = 0; i < slen[s]; i++)
        {
          if (!extract_name(header, pktlen, &p, owner, 1, 10))
            return 0;
          GETSHORT(qtype, p);
          GETSHORT(qclass, p);
          GETLONG(ttl, p);
          GETSHORT(rdlen, p);
          if (qtype == T_RRSIG)
            {
              printf("RRSIG found (owner: %s)\n", owner);
              /* TODO: missing logic. We should only validate RRSIGs for which we
                 have a valid DNSKEY that is referenced by a DS record upstream.
                 There is a memory vs CPU conflict here; should we validate everything
                 to save memory and thus waste CPU, or better first acquire all information
                 (wasting memory) and then doing the minimum CPU computations required? */
              dnssec_parserrsig(header, pktlen, reply, slen[s], owner, qclass, rdlen, p);
            }
          p += rdlen;
        }
    }

  return 1;
}
