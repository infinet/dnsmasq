
#include "dnsmasq.h"
#include "dnssec-crypto.h"
#include <assert.h>

#define SERIAL_UNDEF  -100
#define SERIAL_EQ        0
#define SERIAL_LT       -1
#define SERIAL_GT        1

#define countof(x)      (long)(sizeof(x) / sizeof(x[0]))
#define MIN(a,b)        ((a) < (b) ? (a) : (b))

/* Updated registry that merges various RFCs:
   https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml */
static const VerifyAlg valgs[] =
{
  {0,0,0,0,0},            /*  0: reserved */
  {0,0,0,0,0},            /*  1: RSAMD5 */
  {0,0,0,0,0},            /*  2: DH */
  {0,0,0,0,0},            /*  3: DSA */
  {0,0,0,0,0},            /*  4: ECC */
  VALG_VTABLE(rsasha1),   /*  5: RSASHA1 */
  {0,0,0,0,0},            /*  6: DSA-NSEC3-SHA1 */
  {0,0,0,0,0},            /*  7: RSASHA1-NSEC3-SHA1 */
  {0,0,0,0,0},            /*  8: RSASHA256 */
  {0,0,0,0,0},            /*  9: unassigned */
  {0,0,0,0,0},            /* 10: RSASHA512 */
  {0,0,0,0,0},            /* 11: unassigned */
  {0,0,0,0,0},            /* 12: ECC-GOST */
  {0,0,0,0,0},            /* 13: ECDSAP256SHA256 */
  {0,0,0,0,0},            /* 14: ECDSAP384SHA384 */
};

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
      while (count-- >= 0 && rr < end)
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
  rr++;
  *buf = 0;
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
  const unsigned char *pr1=r1, *pr2=r2;
  
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

static int validate_rrsig(struct dns_header *header, size_t pktlen,
                          unsigned char *reply, int count, char *owner,
                          int sigclass, int sigrdlen, unsigned char *sig)
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
  
  if (sigalg >= countof(valgs) || !valgs[sigalg].set_signature)
    {
      printf("RRSIG algorithm not supported: %d\n", sigalg);
      return 0;
    }

  if (!check_date_range(ntohl(date_start), ntohl(date_end)))
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
          assert(rrsetidx < countof(rrset));
          /* TODO: here we should convert to lowercase domain names within 
             RDATA. We can do it in place. */
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
  const VerifyAlg *alg = &valgs[sigalg];
  if (!alg->set_signature(sig, sigrdlen))
    return 0;
  
  alg->begin_data();
  alg->add_data(sigrdata, 18);
  alg->add_data(signer_name, strlen(signer_name)-1); /* remove trailing dot */
  for (i = 0; i < rrsetidx; ++i)
    {
      int rdlen;
      
      alg->add_data(owner, strlen(owner));
      alg->add_data(&sigtype, 2);
      alg->add_data(&sigclass, 2);
      alg->add_data(&sigttl, 4);
    
      p = (unsigned char*)(rrset[i]);
      p += 8;
      GETSHORT(rdlen, p);
      alg->add_data(p-2, rdlen+2);
    }
  alg->end_data();
  
  /* TODO: now we need to fetch the DNSKEY of signer_name with the specified
     keytag, and check whether it validates with the current algorithm. */
  /*
    pseudo-code:

    char *key; int keylen;
    if (!fetch_dnskey(signer_name, keytag, &key, &keylen))
      return 0;
    return alg->verify(key, keylen);
   */
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
      if (qtype == T_RRSIG)
        {
      	  printf("RRSIG found\n");
          /* TODO: missing logic. We should only validate RRSIGs for which we
             have a valid DNSKEY that is referenced by a DS record upstream. 
             There is a memory vs CPU conflict here; should we validate everything
             to save memory and thus waste CPU, or better first acquire all information
             (wasting memory) and then doing the minimum CPU computations required? */
          validate_rrsig(header, pktlen, reply, ntohs(header->ancount), owner, qclass, rdlen, p);
      	}
      p += rdlen;
    }
  return 1;
}
