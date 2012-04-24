#include <string.h>
#include <openssl/evp.h>

struct rsasha_state
{
  union
    {
      EVP_MD_CTX hash;
      unsigned char digest[32];
    };
  unsigned char *sig;
  unsigned siglen;

} RSASHA;

int rsasha1_set_signature(unsigned char *data, unsigned len)
{
  RSASHA.sig = data;
  RSASHA.siglen = len;
  return 1;
}

int rsasha256_set_signature(unsigned char *data, unsigned len)
{
  RSASHA.sig = data;
  RSASHA.siglen = len;
  return 1;
}

void rsasha1_begin_data(void)
{
  EVP_MD_CTX_init(&RSASHA.hash);
  EVP_DigestInit_ex(&RSASHA.hash, EVP_sha1(), NULL);
}
void rsasha256_begin_data(void)
{
  EVP_MD_CTX_init(&RSASHA.hash);
  EVP_DigestInit_ex(&RSASHA.hash, EVP_sha256(), NULL);
}

void rsasha1_add_data(void *data, unsigned len)
{
  EVP_DigestUpdate(&RSASHA.hash, data, len);
}
void rsasha256_add_data(void *data, unsigned len)
{
  EVP_DigestUpdate(&RSASHA.hash, data, len);
}

void rsasha1_end_data(void)
{
  unsigned char digest[20];
  EVP_DigestFinal(&RSASHA.hash, digest, NULL);
  memcpy(RSASHA.digest, digest, 20);
}
void rsasha256_end_data(void)
{
  unsigned char digest[32];
  EVP_DigestFinal(&RSASHA.hash, digest, NULL);
  memcpy(RSASHA.digest, digest, 32);
}

int rsasha1_verify(unsigned char *key, unsigned key_len)
{
  return 0;
}

int rsasha256_verify(unsigned char *key, unsigned key_len)
{
  return 0;
}

