#include <openssl/err.h>
#include <openssl/ssl.h>

#include "cgo_binding.h"

X509 *SSLConn_X509_new (void *buf, int len, SSLConnError *err) {
  BIO *bio;
  X509 *cert;

  bio = BIO_new_mem_buf(buf, len);
  cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

  if (cert == NULL) {
    handle_error(err);
  }

  BIO_free(bio);
  ERR_remove_state(0);
  return cert;
}
