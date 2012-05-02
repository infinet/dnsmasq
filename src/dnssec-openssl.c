#include <string.h>
#include "dnsmasq.h"
#include "dnssec-crypto.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>

typedef struct VACTX_rsasha1
{
  VerifyAlgCtx base;
  unsigned char *sig;
  unsigned siglen;
  unsigned char digest[20];
} VACTX_rsasha1;

typedef struct VACTX_rsasha256
{
  VerifyAlgCtx base;
  unsigned char *sig;
  unsigned siglen;
  unsigned char digest[32];
} VACTX_rsasha256;

#define POOL_SIZE 1
static union _Pool
{
  VACTX_rsasha1 rsasha1;
  VACTX_rsasha256 rsasha256;
} Pool[POOL_SIZE];
static char pool_used = 0;

static void print_hex(unsigned char *data, unsigned len)
{
  while (len > 0)
    {
      printf("%02x", *data++);
      --len;
    }
  printf("\n");
}

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

static int rsasha1_get_digestalgo(VerifyAlgCtx *ctx_)
{
  (void)ctx_;
  return DIGESTALG_SHA1;
}
static int rsasha256_get_digestalgo(VerifyAlgCtx *ctx_)
{
  (void)ctx_;
  return DIGESTALG_SHA256;
}

static void rsasha1_set_digest(VerifyAlgCtx *ctx_, unsigned char *digest)
{
  VACTX_rsasha1 *ctx = (VACTX_rsasha1 *)ctx_;
  memcpy(ctx->digest, digest, sizeof(ctx->digest));
}
static void rsasha256_set_digest(VerifyAlgCtx *ctx_, unsigned char *digest)
{
  VACTX_rsasha256 *ctx = (VACTX_rsasha256 *)ctx_;
  memcpy(ctx->digest, digest, sizeof(ctx->digest));
}

static int keydata_to_bn(BIGNUM *ret, struct keydata **key_data, unsigned char **p, unsigned len)
{
  size_t cnt;
  BIGNUM temp;

  BN_init(ret);

  cnt = keydata_walk(key_data, p, len);
  BN_bin2bn(*p, cnt, ret);
  len -= cnt;
  *p += cnt;
  while (len > 0)
    {
      if (!(cnt = keydata_walk(key_data, p, len)))
        return 0;
      BN_lshift(ret, ret, cnt*8);
      BN_init(&temp);
      BN_bin2bn(*p, cnt, &temp);
      BN_add(ret, ret, &temp);
      len -= cnt;
      *p += cnt;
    }
  return 1;
}

static int rsasha1_parse_key(BIGNUM *exp, BIGNUM *mod, struct keydata *key_data, unsigned key_len)
{
  unsigned char *p = key_data->key;
  size_t exp_len, mod_len;

  CHECKED_GETCHAR(exp_len, p, key_len);
  if (exp_len == 0)
    CHECKED_GETSHORT(exp_len, p, key_len);
  if (exp_len >= key_len)
    return 0;
  mod_len = key_len - exp_len;

  return keydata_to_bn(exp, &key_data, &p, exp_len) &&
      keydata_to_bn(mod, &key_data, &p, mod_len);
}

static int rsasha1_verify(VerifyAlgCtx *ctx_, struct keydata *key_data, unsigned key_len)
{
  VACTX_rsasha1 *ctx = (VACTX_rsasha1 *)ctx_;
  int validated = 0;

  RSA *rsa = RSA_new();
  rsa->e = BN_new();
  rsa->n = BN_new();
  if (rsasha1_parse_key(rsa->e, rsa->n, key_data, key_len)
      && RSA_verify(NID_sha1, ctx->digest, 20, ctx->sig, ctx->siglen, rsa))
    validated = 1;

  RSA_free(rsa);
  return validated;
}

static int rsasha256_verify(VerifyAlgCtx *ctx_, struct keydata *key_data, unsigned key_len)
{
  VACTX_rsasha256 *ctx = (VACTX_rsasha256 *)ctx_;
  int validated = 0;

  RSA *rsa = RSA_new();
  rsa->e = BN_new();
  rsa->n = BN_new();
  if (rsasha1_parse_key(rsa->e, rsa->n, key_data, key_len)
      && RSA_verify(NID_sha256, ctx->digest, 32, ctx->sig, ctx->siglen, rsa))
    validated = 1;

  RSA_free(rsa);
  return validated;
}

#define VALG_UNSUPPORTED() { \
    0,0,0,0 \
  } /**/

#define VALG_VTABLE(alg) { \
  alg ## _set_signature, \
  alg ## _get_digestalgo, \
  alg ## _set_digest, \
  alg ## _verify \
  } /**/

/* Updated registry that merges various RFCs:
   https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml */
static const VerifyAlg valgs[] =
{
  VALG_UNSUPPORTED(),            /*  0: reserved */
  VALG_UNSUPPORTED(),            /*  1: RSAMD5 */
  VALG_UNSUPPORTED(),            /*  2: DH */
  VALG_UNSUPPORTED(),            /*  3: DSA */
  VALG_UNSUPPORTED(),            /*  4: ECC */
  VALG_VTABLE(rsasha1),          /*  5: RSASHA1 */
  VALG_UNSUPPORTED(),            /*  6: DSA-NSEC3-SHA1 */
  VALG_VTABLE(rsasha1),          /*  7: RSASHA1-NSEC3-SHA1 */
  VALG_VTABLE(rsasha256),        /*  8: RSASHA256 */
  VALG_UNSUPPORTED(),            /*  9: unassigned */
  VALG_UNSUPPORTED(),            /* 10: RSASHA512 */
  VALG_UNSUPPORTED(),            /* 11: unassigned */
  VALG_UNSUPPORTED(),            /* 12: ECC-GOST */
  VALG_UNSUPPORTED(),            /* 13: ECDSAP256SHA256 */
  VALG_UNSUPPORTED(),            /* 14: ECDSAP384SHA384 */
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
  sizeof(VACTX_rsasha1),    /*  7: RSASHA1-NSEC3-SHA1 */
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

static EVP_MD_CTX digctx;

int digestalg_supported(int algo)
{
  return (algo == DIGESTALG_SHA1 || algo == DIGESTALG_SHA256);
}

int digestalg_begin(int algo)
{
  EVP_MD_CTX_init(&digctx);
  if (algo == 1)
    EVP_DigestInit_ex(&digctx, EVP_sha1(), NULL);
  else if (algo == 2)
    EVP_DigestInit_ex(&digctx, EVP_sha256(), NULL);
  else
    return 0;
  return 1;
}

int digestalg_len()
{
  return EVP_MD_CTX_size(&digctx);
}

void digestalg_add_data(void *data, unsigned len)
{
  EVP_DigestUpdate(&digctx, data, len);
}

void digestalg_add_keydata(struct keydata *key, size_t len)
{
  size_t cnt; unsigned char *p = NULL;
  while (len)
    {
      cnt = keydata_walk(&key, &p, len);
      EVP_DigestUpdate(&digctx, p, cnt);
      p += cnt;
      len -= cnt;
    }
}

unsigned char* digestalg_final(void)
{
  static unsigned char digest[32];
  EVP_DigestFinal(&digctx, digest, NULL);
  return digest;
}

