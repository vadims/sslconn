#include <openssl/err.h>
#include <openssl/ssl.h>

#include "cgo_binding.h"

EVP_PKEY *SSLConn_EVP_PKEY_new(void *buf, int len, SSLConnError *err) {
  BIO *bio;
  EVP_PKEY *key;

  bio = BIO_new_mem_buf(buf, len);
  key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

  if (key == NULL) {
    handle_error(err);
  }

  BIO_free(bio);
  ERR_remove_state(0);
  return key;
}
