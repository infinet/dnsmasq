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
typedef struct
{
  int (*set_signature)(unsigned char *data, unsigned len);
  void (*begin_data)(void);
  void (*add_data)(void *data, unsigned len);
  void (*end_data)(void);
  int (*verify)(unsigned char *key, unsigned key_len);
} VerifyAlg;

#define DEFINE_VALG(alg) \
  void alg ## _set_signature(unsigned char *data, unsigned len); \
  void alg ## _begin_data(void); \
  void alg ## _add_data(void *data, unsigned len); \
  void alg ## _end_data(void); \
  int alg ## _verify(unsigned char *key, unsigned key_len) \
  /**/

#define VALG_VTABLE(alg) { \
  alg ## _set_signature, \
  alg ## _begin_data, \
  alg ## _add_data, \
  alg ## _end_data, \
  alg ## _verify \
  } /**/

/* Algorithm 5: RSASHA1 */
DEFINE_VALG(rsasha1);

#endif /* DNSSEC_CRYPTO_H */
