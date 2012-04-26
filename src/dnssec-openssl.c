#include <string.h>
#include "dnsmasq.h"
#include "dnssec-crypto.h"
#include <openssl/evp.h>

typedef struct VACTX_rsasha1
{
  VerifyAlgCtx base;
  unsigned char *sig;
  unsigned siglen;
  union
    {
      EVP_MD_CTX hash;
      unsigned char digest[20];
    };
} VACTX_rsasha1;

typedef struct VACTX_rsasha256
{
  VerifyAlgCtx base;
  unsigned char *sig;
  unsigned siglen;
  union
    {
      EVP_MD_CTX hash;
      unsigned char digest[32];
    };
} VACTX_rsasha256;

#define POOL_SIZE 1
static union _Pool
{
  VACTX_rsasha1 rsasha1;
  VACTX_rsasha256 rsasha256;
} Pool[POOL_SIZE];
static char pool_used = 0;

static int rsasha1_set_signature(VerifyAlgCtx *ctx_, unsigned char *data, unsigned len)
{
  VACTX_rsasha1 *ctx = (VACTX_rsasha1 *)ctx_;
  ctx->sig = data;
  ctx->siglen = len;
  return 1;
}

static int rsasha256_set_signature(VerifyAlgCtx *ctx_, unsigned char *data, unsigned len)
{
  VACTX_rsasha256 *ctx = (VACTX_rsasha256 *)ctx_;
  ctx->sig = data;
  ctx->siglen = len;
  return 1;
}

static void rsasha1_begin_data(VerifyAlgCtx *ctx_)
{
  VACTX_rsasha1 *ctx = (VACTX_rsasha1 *)ctx_;
  EVP_MD_CTX_init(&ctx->hash);
  EVP_DigestInit_ex(&ctx->hash, EVP_sha1(), NULL);
}
static void rsasha256_begin_data(VerifyAlgCtx *ctx_)
{
  VACTX_rsasha256 *ctx = (VACTX_rsasha256 *)ctx_;
  EVP_MD_CTX_init(&ctx->hash);
  EVP_DigestInit_ex(&ctx->hash, EVP_sha256(), NULL);
}

static void rsasha1_add_data(VerifyAlgCtx *ctx_, void *data, unsigned len)
{
  VACTX_rsasha1 *ctx = (VACTX_rsasha1 *)ctx_;
  EVP_DigestUpdate(&ctx->hash, data, len);
}
static void rsasha256_add_data(VerifyAlgCtx *ctx_, void *data, unsigned len)
{
  VACTX_rsasha256 *ctx = (VACTX_rsasha256 *)ctx_;
  EVP_DigestUpdate(&ctx->hash, data, len);
}

static void rsasha1_end_data(VerifyAlgCtx *ctx_)
{
  VACTX_rsasha1 *ctx = (VACTX_rsasha1 *)ctx_;
  unsigned char digest[20];
  EVP_DigestFinal(&ctx->hash, digest, NULL);
  memcpy(ctx->digest, digest, 20);
}
static void rsasha256_end_data(VerifyAlgCtx *ctx_)
{
  VACTX_rsasha256 *ctx = (VACTX_rsasha256 *)ctx_;
  unsigned char digest[32];
  EVP_DigestFinal(&ctx->hash, digest, NULL);
  memcpy(ctx->digest, digest, 32);
}

static int rsasha1_verify(VerifyAlgCtx *ctx_, unsigned char *key, unsigned key_len)
{
  VACTX_rsasha1 *ctx = (VACTX_rsasha1 *)ctx_;
  return 0;
}

static int rsasha256_verify(VerifyAlgCtx *ctx_, unsigned char *key, unsigned key_len)
{
  VACTX_rsasha256 *ctx = (VACTX_rsasha256 *)ctx_;
  return 0;
}

#define DEFINE_VALG(alg) \
  int alg ## _set_signature(VerifyAlgCtx *ctx, unsigned char *data, unsigned len); \
  void alg ## _begin_data(VerifyAlgCtx *ctx); \
  void alg ## _add_data(VerifyAlgCtx *ctx, void *data, unsigned len); \
  void alg ## _end_data(VerifyAlgCtx *ctx); \
  int alg ## _verify(VerifyAlgCtx *ctx, unsigned char *key, unsigned key_len) \
  /**/

#define VALG_VTABLE(alg) { \
  alg ## _set_signature, \
  alg ## _begin_data, \
  alg ## _add_data, \
  alg ## _end_data, \
  alg ## _verify \
  } /**/

DEFINE_VALG(rsasha1);
DEFINE_VALG(rsasha256);

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
  VALG_VTABLE(rsasha256), /*  8: RSASHA256 */
  {0,0,0,0,0},            /*  9: unassigned */
  {0,0,0,0,0},            /* 10: RSASHA512 */
  {0,0,0,0,0},            /* 11: unassigned */
  {0,0,0,0,0},            /* 12: ECC-GOST */
  {0,0,0,0,0},            /* 13: ECDSAP256SHA256 */
  {0,0,0,0,0},            /* 14: ECDSAP384SHA384 */
};

static const int valgctx_size[] =
{
  0,                        /*  0: reserved */
  0,                        /*  1: RSAMD5 */
  0,                        /*  2: DH */
  0,                        /*  3: DSA */
  0,                        /*  4: ECC */
  sizeof(VACTX_rsasha1),    /*  5: RSASHA1 */
  0,                        /*  6: DSA-NSEC3-SHA1 */
  0,                        /*  7: RSASHA1-NSEC3-SHA1 */
  sizeof(VACTX_rsasha256),  /*  8: RSASHA256 */
  0,                        /*  9: unassigned */
  0,                        /* 10: RSASHA512 */
  0,                        /* 11: unassigned */
  0,                        /* 12: ECC-GOST */
  0,                        /* 13: ECDSAP256SHA256 */
  0,                        /* 14: ECDSAP384SHA384 */
};

int verifyalg_supported(int algo)
{
  return (algo < countof(valgctx_size) && valgctx_size[algo] != 0);
}

VerifyAlgCtx* verifyalg_alloc(int algo)
{
  int i;
  VerifyAlgCtx *ret = 0;

  if (!verifyalg_supported(algo))
    return 0;

  if (pool_used == (1<<POOL_SIZE)-1)
      ret = whine_malloc(valgctx_size[algo]);
  else
    for (i = 0; i < POOL_SIZE; ++i)
      if (!(pool_used & (1 << i)))
        {
          ret = (VerifyAlgCtx*)&Pool[i];
          pool_used |= 1 << i;
          break;
        }

  if (ret)
    ret->vtbl = &valgs[algo];
  return ret;
}

void verifyalg_free(VerifyAlgCtx *a)
{
  int pool_idx = ((char*)a - (char*)&Pool[0]) / sizeof(Pool[0]);
  if (pool_idx < 0 || pool_idx >= POOL_SIZE)
    {
      free(a);
      return;
    }

  pool_used &= ~(1 << pool_idx);
}

int verifyalg_algonum(VerifyAlgCtx *a)
{
  int num = a->vtbl - valgs;
  if (num < 0 || num >= countof(valgs))
    return -1;
  return num;
}
