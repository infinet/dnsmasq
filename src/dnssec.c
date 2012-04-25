
#include "dnsmasq.h"
#include "dnssec-crypto.h"
#include <assert.h>

#define CHECKED_GETCHAR(var, ptr, len) do { \
    if ((len) < 1) return 0; \
    var = *ptr++; \
    (len) -= 1; \
  } while (0)

#define CHECKED_GETSHORT(var, ptr, len) do { \
    if ((len) < 2) return 0; \
    GETSHORT(var, ptr); \
    (len) -= 2; \
  } while (0)

#define CHECKED_GETLONG(var, ptr, len) do { \
    if ((len) < 4) return 0; \
    GETLONG(var, ptr); \
    (len) -= 4; \
  } while (0)


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
  // Remove trailing dot (if any)
  if (rr != start)
    *(--buf) = 0;
  rr++;
  if (rr == end)
    return 0;
  return rr-start;
}

/* Check whether today/now is between date_start and date_end */
static int check_date_range(unsigned long date_start, unsigned long date_end)
{
  /* TODO: double-check that time(0) is the correct time we are looking for */
  /* TODO: dnssec requires correct timing; implement SNTP in dnsmasq? */
  unsigned long curtime = time(0);

  /* We must explicitly check against wanted values, because of SERIAL_UNDEF */
  if (serial_compare_32(curtime, date_start) != SERIAL_GT)
    return 0;
  if (serial_compare_32(curtime, date_end) != SERIAL_LT)
    return 0;
  return 1;
}

/* Sort RRs within a RRset in canonical order, according to RFC4034, §6.3
   Notice that the RRDATA sections have been already normalized, so a memcpy
   is sufficient.
   NOTE: r1/r2 point immediately after the owner name. */
static int rrset_canonical_order(const void *r1, const void *r2)
{
  int r1len, r2len, res;
  const unsigned char *pr1=*(unsigned char**)r1, *pr2=*(unsigned char**)r2;
  
  pr1 += 8; pr2 += 8;
  GETSHORT(r1len, pr1); GETSHORT(r2len, pr2);

  /* Lexicographically compare RDATA (thus, if equal, smaller length wins) */
  res = memcmp(pr1, pr2, MIN(r1len, r2len));
  if (res == 0)
    {
      if (r1len < r2len)
        return -1;
      else
        /* NOTE: RFC2181 says that an RRset is not allowed to contain duplicate
           records. If it happens, it is a protocol error and anything goes. */
        return 1;
    }
  
  return res;
}

typedef struct PendingRRSIGValidation
{
  VerifyAlgCtx *alg;
  char *signer_name;
  int keytag;
} PendingRRSIGValidation;

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
  qsort(rrset, rrsetidx, sizeof(void*), rrset_canonical_order);
  
  /* Extract the signer name (we need to query DNSKEY of this name) */
  if (!(res = extract_name_no_compression(sig, sigrdlen, signer_name)))
    return 0;
  sig += res; sigrdlen -= res;
  
  /* Now initialize the signature verification algorithm and process the whole
     RRset */
  VerifyAlgCtx *alg = verifyalg_alloc(sigalg);
  if (!alg)
    return 0;
  if (!alg->vtbl->set_signature(alg, sig, sigrdlen))
    return 0;
  
  alg->vtbl->begin_data(alg);
  alg->vtbl->add_data(alg, sigrdata, 18);
  alg->vtbl->add_data(alg, signer_name, strlen(signer_name));
  for (i = 0; i < rrsetidx; ++i)
    {
      int rdlen;
      
      alg->vtbl->add_data(alg, owner, strlen(owner));
      alg->vtbl->add_data(alg, &sigtype, 2);
      alg->vtbl->add_data(alg, &sigclass, 2);
      alg->vtbl->add_data(alg, &sigttl, 4);
    
      p = (unsigned char*)(rrset[i]);
      p += 8;
      GETSHORT(rdlen, p);
      /* TODO: instead of a direct add_data(), we must call a RRtype-specific 
         function, that extract and canonicalizes domain names within RDATA. */
      alg->vtbl->add_data(alg, p-2, rdlen+2);
    }
  alg->vtbl->end_data(alg);

  out->alg = alg;
  out->keytag = keytag;
  out->signer_name = signer_name;
  return 1;
}

static int end_rrsig_validation(PendingRRSIGValidation *val, struct crec *crec_dnskey)
{

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
  /* Look in the cache for all the DNSKEYs with matching signer_name and keytag */
  char onekey = 0;
  struct crec *crecp = NULL;
  while (crecp = cache_find_by_name(crecp, val.signer_name, time(0), F_DNSKEY))  /* TODO: time(0) */
    {
      onekey = 1;

      if (crecp->addr.key.keytag != val.keytag)
        continue;

      printf("RRSIG: found DNSKEY %d in cache, attempting validation\n", val.keytag);

      if (end_rrsig_validation(&val, crecp))
        printf("Validation OK\n");
      else
        printf("Validation FAILED\n");
    }

  if (!onekey)
    {
      printf("DNSKEY not found, need to fetch it");
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
  int explen, keytag;
  unsigned long exp;
  unsigned char *ordata = rdata; int ordlen = rdlen;

  CHECKED_GETSHORT(flags, rdata, rdlen);
  CHECKED_GETCHAR(proto, rdata, rdlen);
  CHECKED_GETCHAR(alg, rdata, rdlen);

  if (proto != 3)
    return 0;

  switch (alg)
    {
      case 5: /* RSASHA1 */
        CHECKED_GETCHAR(explen, rdata, rdlen);
        if (explen == 0)
          {
            printf("DNSKEY: RSASHA1: Unsupported huge exponents\n");
            return 0;
          }

        if (rdlen < explen)
          return 0;
        printf("Alloc'ing: %d bytes\n", rdlen);
        key = keydata_alloc(rdata, rdlen);
        printf("Done\n");
        break;

      default:
        printf("DNSKEY: Unsupported algorithm: %d\n", alg);
        return 0;
    }

  cache_start_insert();
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
  cache_end_insert();
  printf("DNSKEY record inserted\n");
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
  int i, qtype, qclass, rdlen;
  unsigned long ttl;

  if (header->ancount == 0)
    return 0;
  if (!(reply = p = skip_questions(header, pktlen)))
    return 0;
  for (i = 0; i < ntohs(header->ancount); i++)
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
          dnssec_parsekey(header, pktlen, owner, qclass, rdlen, p);
        }
      else if (qtype == T_RRSIG)
        {
      	  printf("RRSIG found\n");
          /* TODO: missing logic. We should only validate RRSIGs for which we
             have a valid DNSKEY that is referenced by a DS record upstream. 
             There is a memory vs CPU conflict here; should we validate everything
             to save memory and thus waste CPU, or better first acquire all information
             (wasting memory) and then doing the minimum CPU computations required? */
          dnssec_parserrsig(header, pktlen, reply, ntohs(header->ancount), owner, qclass, rdlen, p);
      	}
      p += rdlen;
    }
  return 1;
}
