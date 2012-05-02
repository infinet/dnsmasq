#include <string.h>
#include "dnsmasq.h"
#include "dnssec-crypto.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/err.h>

#define POOL_SIZE 1
static union _Pool
{
  VerifyAlgCtx ctx;
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

static int dsasha1_parse_key(BIGNUM *Q, BIGNUM *P, BIGNUM *G, BIGNUM *Y, struct keydata *key_data, unsigned key_len)
{
  unsigned char *p = key_data->key;
  int T;

  CHECKED_GETCHAR(T, p, key_len);
  return
      keydata_to_bn(Q, &key_data, &p, 20) &&
      keydata_to_bn(P, &key_data, &p, 64+T*8)  &&
      keydata_to_bn(G, &key_data, &p, 64+T*8)  &&
      keydata_to_bn(Y, &key_data, &p, 64+T*8);
}

static int rsa_verify(VerifyAlgCtx *ctx, struct keydata *key_data, unsigned key_len, int nid, int dlen)
{
  int validated = 0;

  RSA *rsa = RSA_new();
  rsa->e = BN_new();
  rsa->n = BN_new();
  if (rsasha1_parse_key(rsa->e, rsa->n, key_data, key_len)
      && RSA_verify(nid, ctx->digest, dlen, ctx->sig, ctx->siglen, rsa))
    validated = 1;

  RSA_free(rsa);
  return validated;
}

static int rsamd5_verify(VerifyAlgCtx *ctx, struct keydata *key_data, unsigned key_len)
{
  return rsa_verify(ctx, key_data, key_len, NID_md5, 16);
}

static int rsasha1_verify(VerifyAlgCtx *ctx, struct keydata *key_data, unsigned key_len)
{
  return rsa_verify(ctx, key_data, key_len, NID_sha1, 20);
}

static int rsasha256_verify(VerifyAlgCtx *ctx, struct keydata *key_data, unsigned key_len)
{
  return rsa_verify(ctx, key_data, key_len, NID_sha256, 32);
}

static int rsasha512_verify(VerifyAlgCtx *ctx, struct keydata *key_data, unsigned key_len)
{
  return rsa_verify(ctx, key_data, key_len, NID_sha512, 64);
}

static int dsasha1_verify(VerifyAlgCtx *ctx, struct keydata *key_data, unsigned key_len)
{
  static unsigned char asn1_signature[] =
  {
    0x30, 0x2E,   // sequence
    0x02, 21,     // large integer (21 bytes)
    0x00, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   // R
    0x02, 21,     // large integer (21 bytes)
    0x00, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   // S
  };
  int validated = 0;

  /* A DSA signature is made of 2 bignums (R & S). We could parse them manually with BN_bin2bn(),
     but OpenSSL does not have an API to verify a DSA signature given R and S, and insists
     in having a ASN.1 BER sequence (as per RFC3279).
     We prepare a hard-coded ASN.1 sequence, and just fill in the R&S numbers in it. */
  memcpy(asn1_signature+5,  ctx->sig+1, 20);
  memcpy(asn1_signature+28, ctx->sig+21, 20);

  DSA *dsa = DSA_new();
  dsa->q = BN_new();
  dsa->p = BN_new();
  dsa->g = BN_new();
  dsa->pub_key = BN_new();

  if (dsasha1_parse_key(dsa->q, dsa->p, dsa->g, dsa->pub_key, key_data, key_len)
      && DSA_verify(0, ctx->digest, 20, asn1_signature, countof(asn1_signature), dsa) > 0)
    validated = 1;

  DSA_free(dsa);
  return validated;
}

#define VALG_UNSUPPORTED() { \
    0,0 \
  } /**/

#define VALG_VTABLE(alg, digest) { \
  digest, \
  alg ## _verify \
  } /**/

/* Updated registry that merges various RFCs:
   https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml */
static const VerifyAlg valgs[] =
{
  VALG_UNSUPPORTED(),                        /*  0: reserved */
  VALG_VTABLE(rsamd5, DIGESTALG_MD5),        /*  1: RSAMD5 */
  VALG_UNSUPPORTED(),                        /*  2: DH */
  VALG_VTABLE(dsasha1, DIGESTALG_SHA1),      /*  3: DSA */
  VALG_UNSUPPORTED(),                        /*  4: ECC */
  VALG_VTABLE(rsasha1, DIGESTALG_SHA1),      /*  5: RSASHA1 */
  VALG_VTABLE(dsasha1, DIGESTALG_SHA1),      /*  6: DSA-NSEC3-SHA1 */
  VALG_VTABLE(rsasha1, DIGESTALG_SHA1),      /*  7: RSASHA1-NSEC3-SHA1 */
  VALG_VTABLE(rsasha256, DIGESTALG_SHA256),  /*  8: RSASHA256 */
  VALG_UNSUPPORTED(),                        /*  9: unassigned */
  VALG_VTABLE(rsasha512, DIGESTALG_SHA512),  /* 10: RSASHA512 */
  VALG_UNSUPPORTED(),                        /* 11: unassigned */
  VALG_UNSUPPORTED(),                        /* 12: ECC-GOST */
  VALG_UNSUPPORTED(),                        /* 13: ECDSAP256SHA256 */
  VALG_UNSUPPORTED(),                        /* 14: ECDSAP384SHA384 */
};

/* TODO: remove if we don't need this anymore
   (to be rechecked if we ever remove OpenSSL) */
static const int valgctx_size[] =
{
  0,                        /*  0: reserved */
  sizeof(VerifyAlgCtx),     /*  1: RSAMD5 */
  0,                        /*  2: DH */
  sizeof(VerifyAlgCtx),     /*  3: DSA */
  0,                        /*  4: ECC */
  sizeof(VerifyAlgCtx),     /*  5: RSASHA1 */
  0,                        /*  6: DSA-NSEC3-SHA1 */
  sizeof(VerifyAlgCtx),     /*  7: RSASHA1-NSEC3-SHA1 */
  sizeof(VerifyAlgCtx),     /*  8: RSASHA256 */
  0,                        /*  9: unassigned */
  sizeof(VerifyAlgCtx),     /* 10: RSASHA512 */
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
  return (algo == DIGESTALG_SHA1 ||
          algo == DIGESTALG_SHA256 ||
          algo == DIGESTALG_MD5 ||
          algo == DIGESTALG_SHA512);
}

int digestalg_begin(int algo)
{
  EVP_MD_CTX_init(&digctx);
  if (algo == DIGESTALG_SHA1)
    EVP_DigestInit_ex(&digctx, EVP_sha1(), NULL);
  else if (algo == DIGESTALG_SHA256)
    EVP_DigestInit_ex(&digctx, EVP_sha256(), NULL);
  else if (algo == DIGESTALG_SHA512)
    EVP_DigestInit_ex(&digctx, EVP_sha512(), NULL);
  else if (algo == DIGESTALG_MD5)
    EVP_DigestInit_ex(&digctx, EVP_md5(), NULL);
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

