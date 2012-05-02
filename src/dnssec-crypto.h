#ifndef DNSSEC_CRYPTO_H
#define DNSSEC_CRYPTO_H

struct keydata;

/* 
 * vtable for a signature verification algorithm.
 *
 * Each algorithm verifies that a certain signature over a (possibly non-contigous)
 * array of data has been made with the specified key.
 *
 * Sample of usage:
 *
 *    // First, set the signature we need to check. Notice: data is not copied
 *    // nor consumed, so the pointer must stay valid.
 *    alg->set_signature(sig, 16);
 *
 *    // Second, get push the data through the corresponding digest algorithm;
 *    // data is consumed immediately, so the buffers can be freed or modified.
 *    digestalg_begin(alg->get_digestalgo());
 *    digestalg_add_data(buf1, 123);
 *    digestalg_add_data(buf2, 45);
 *    digestalg_add_data(buf3, 678);
 *    alg->set_digest(digestalg_final());
 *
 *    // Third, verify if we got the correct key for this signature.
 *    alg->verify(key1, 16);
 *    alg->verify(key2, 16);
 */ 

typedef struct VerifyAlgCtx VerifyAlgCtx;

typedef struct
{
  int digest_algo;
  int (*verify)(VerifyAlgCtx *ctx, struct keydata *key, unsigned key_len);
} VerifyAlg;

struct VerifyAlgCtx
{
   const VerifyAlg *vtbl;
   unsigned char *sig;
   size_t siglen;
   unsigned char digest[32];
};

int verifyalg_supported(int algo);
VerifyAlgCtx* verifyalg_alloc(int algo);
void verifyalg_free(VerifyAlgCtx *a);
int verifyalg_algonum(VerifyAlgCtx *a);

/* Functions to calculate the digest of a key */

/* RFC4034 digest algorithms */
#define DIGESTALG_SHA1     1
#define DIGESTALG_SHA256   2
#define DIGESTALG_MD5      256

int digestalg_supported(int algo);
int digestalg_begin(int algo);
void digestalg_add_data(void *data, unsigned len);
void digestalg_add_keydata(struct keydata *key, size_t len);
unsigned char *digestalg_final(void);
int digestalg_len(void);

#endif /* DNSSEC_CRYPTO_H */
