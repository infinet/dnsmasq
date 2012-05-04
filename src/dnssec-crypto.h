/* dnssec-crypto.h is Copyright (c) 2012 Giovanni Bajo <rasky@develer.com>

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
   unsigned char digest[64];  /* TODO: if memory problems, use VLA */
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
#define DIGESTALG_SHA512   257

int digestalg_supported(int algo);
int digestalg_begin(int algo);
void digestalg_add_data(void *data, unsigned len);
void digestalg_add_keydata(struct keydata *key, size_t len);
unsigned char *digestalg_final(void);
int digestalg_len(void);

#endif /* DNSSEC_CRYPTO_H */
