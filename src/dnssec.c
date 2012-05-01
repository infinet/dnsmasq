
#include "dnsmasq.h"
#include "dnssec-crypto.h"
#include <assert.h>

/* Maximum length in octects of a domain name, in wire format */
#define MAXCDNAME  256

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
static char *strchrnul(char *str, char ch)
{
  while (*str && *str != ch)
    str++;
  return str;
}

/* Pass a domain name through a verification hash function.

   We must pass domain names in DNS wire format, but uncompressed.
   This means that we cannot directly use raw data from the original
   message since it might be compressed. */
static void verifyalg_add_data_domain(VerifyAlgCtx *alg, char* name)
{
  unsigned char len; char *p;

  do
    {
      p = strchrnul(name, '.');
      if ((len = p-name))
        {
          alg->vtbl->add_data(alg, &len, 1);
          alg->vtbl->add_data(alg, name, len);
        }
      name = p+1;
    }
  while (*p);

  alg->vtbl->add_data(alg, "\0", 1);
}


/* Pass a resource record's rdata field through a verification hash function.

   We must pass the record in DNS wire format, but if the record contains domain names,
   they must be uncompressed. This makes things very tricky, because  */
static int verifyalg_add_rdata(VerifyAlgCtx *alg, int sigtype, struct dns_header *header, size_t pktlen,
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
  alg->vtbl->add_data(alg, &total, 2);

  while ((p = rdata_cform_next(&cf2, &len)))
    alg->vtbl->add_data(alg, p, len);

  return 1;
}


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
      printf("RRSIG algorithm not supported: %d\n", sigalg);
      return 0;
    }

  if (!check_date_range(date_start, date_end))
    {
      printf("RRSIG outside date range\n");
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
  if (!alg->vtbl->set_signature(alg, sig, sigrdlen))
    return 0;
  
  sigtype = htons(sigtype);
  sigclass = htons(sigclass);
  sigttl = htonl(sigttl);

  alg->vtbl->begin_data(alg);
  alg->vtbl->add_data(alg, sigrdata, 18+signer_name_rdlen);
  for (i = 0; i < rrsetidx; ++i)
    {
      p = (unsigned char*)(rrset[i]);

      verifyalg_add_data_domain(alg, owner);
      alg->vtbl->add_data(alg, &sigtype, 2);
      alg->vtbl->add_data(alg, &sigclass, 2);
      alg->vtbl->add_data(alg, &sigttl, 4);
    
      p += 8;
      if (!verifyalg_add_rdata(alg, ntohs(sigtype), header, pktlen, p))
        return 0;
    }
  alg->vtbl->end_data(alg);

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
            printf("Validation FAILED\n");
        }
    }

  if (!onekey)
    {
      printf("DNSKEY not found, need to fetch it\n");
      /* TODO: store PendingRRSIGValidation in routing table,
         fetch key (and make it go through dnssec_parskey), then complete validation. */
    }
}

/* Compute keytag (checksum to quickly index a key). See RFC4034 */
static int dnskey_keytag(unsigned char *rdata, int rdlen)
{
  unsigned long ac;
  int i;

  ac = 0;
  for (i = 0; i < rdlen; ++i)
    ac += (i & 1) ? rdata[i] : rdata[i] << 8;
  ac += (ac >> 16) & 0xFFFF;
  return ac & 0xFFFF;
}

int dnssec_parsekey(struct dns_header *header, size_t pktlen, char *owner, unsigned long ttl,
                    int rdlen, unsigned char *rdata)
{
  int flags, proto, alg;
  struct keydata *key; struct crec *crecp;
  unsigned char *ordata = rdata; int ordlen = rdlen;

  CHECKED_GETSHORT(flags, rdata, rdlen);
  CHECKED_GETCHAR(proto, rdata, rdlen);
  CHECKED_GETCHAR(alg, rdata, rdlen);

  if (proto != 3)
    return 0;
  /* Skip non-signing keys (as specified in RFC4034 */
  if (!(flags & 0x100))
    return 0;

  key = keydata_alloc((char*)rdata, rdlen);

  /* TODO: time(0) is correct here? */
  crecp = cache_insert(owner, NULL, time(0), ttl, F_FORWARD | F_DNSKEY);
  if (crecp)
    {
      /* TODO: improve union not to name "uid" this field */
      crecp->uid = rdlen;
      crecp->addr.key.keydata = key;
      crecp->addr.key.algo = alg;
      crecp->addr.key.keytag = dnskey_keytag(ordata, ordlen);
      printf("DNSKEY: storing key for %s (keytag: %d)\n", owner, crecp->addr.key.keytag);
    }
  else
    {
      keydata_free(key);
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
  return 0;
}

int dnssec_validate(struct dns_header *header, size_t pktlen)
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
