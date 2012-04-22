#include <string.h>
#include <openssl/evp.h>

struct rsasha1_state
{
  union
    {
      EVP_MD_CTX hash;
      unsigned char digest[20];
    };
  unsigned char *sig;
  unsigned siglen;

} RSASHA1;

int rsasha1_set_signature(unsigned char *data, unsigned len)
{
  RSASHA1.sig = data;
  RSASHA1.siglen = len;
  return 1;
}

void rsasha1_begin_data(void)
{
  EVP_MD_CTX_init(&RSASHA1.hash);
  EVP_DigestInit_ex(&RSASHA1.hash, EVP_sha1(), NULL);
}

void rsasha1_add_data(void *data, unsigned len)
{
  EVP_DigestUpdate(&RSASHA1.hash, data, len);
}

void rsasha1_end_data(void)
{
  unsigned char digest[20];
  EVP_DigestFinal(&RSASHA1.hash, digest, NULL);
  memcpy(RSASHA1.digest, digest, 20);
}

int rsasha1_verify(unsigned char *key, unsigned key_len)
{
  return 0;
}

