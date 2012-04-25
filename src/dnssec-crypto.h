#ifndef DNSSEC_CRYPTO_H
#define DNSSEC_CRYPTO_H

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
 *    // Second, push the data in; data is consumed immediately, so the buffer
 *    // can be freed or modified.
 *    alg->begin_data();
 *    alg->add_data(buf1, 123);
 *    alg->add_data(buf2, 45);
 *    alg->add_data(buf3, 678);
 *    alg->end_data();
 *
 *    // Third, verify if we got the correct key for this signature.
 *    alg->verify(key1, 16);
 *    alg->verify(key2, 16);
 */ 

typedef struct VerifyAlgCtx VerifyAlgCtx;

typedef struct
{
  int (*set_signature)(VerifyAlgCtx *ctx, unsigned char *data, unsigned len);
  void (*begin_data)(VerifyAlgCtx *ctx);
  void (*add_data)(VerifyAlgCtx *ctx, void *data, unsigned len);
  void (*end_data)(VerifyAlgCtx *ctx);
  int (*verify)(VerifyAlgCtx *ctx, unsigned char *key, unsigned key_len);
} VerifyAlg;

struct VerifyAlgCtx
{
   const VerifyAlg *vtbl;
};

int verifyalg_supported(int algo);
VerifyAlgCtx* verifyalg_alloc(int algo);
void verifyalg_free(VerifyAlgCtx *a);

#endif /* DNSSEC_CRYPTO_H */
