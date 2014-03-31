#ifndef sslconn_cgo_binding_h
#define sslconn_cgo_binding_h

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <errno.h>
#include <stdbool.h>
#include <openssl/ssl.h>

typedef struct {
  SSL *ssl;
  SSL_CTX *ctx;
  bool is_server;
} SSLConn;

typedef struct {
  long options;
  int verify_mode;
  EVP_PKEY *private_key;
  X509 *cert;
  char *cipher_list;
  long sess_cache_size;
  char *session_id_context;
  bool is_server;
  void *ptr;
} SSLConnConfig;

typedef struct {
  long code;
  char string[256];
} SSLConnError;

extern const int SSLConn_EIO;
extern const int SSLConn_EAGAIN;
extern const int SSLConn_SSL_ERROR;
extern const int SSLConn_WANT_READ;
extern const int SSLConn_WANT_WRITE;
extern const int SSLConn_ZERO_RETURN;
extern const int SSLConn_SYSCALL;

extern void SSLConn_init();
extern SSLConn *SSLConn_new(SSLConnConfig *config, SSLConnError *err);
extern int SSLConn_read(SSLConn *conn, void *buf, int num, 
  SSLConnError *err);
extern int SSLConn_write(SSLConn *conn, const void *buf, int num, 
  SSLConnError *err);
extern void SSLConn_free(SSLConn *conn);
extern int SSLConn_do_handshake(SSLConn *conn, SSLConnError *err);
extern int SSLConn_shutdown(SSLConn *conn, SSLConnError *err);
extern int SSLConn_get_finished(SSLConn *conn, void *buf, int count);
extern int SSLConn_get_peer_finished(SSLConn *conn, void *buf, int count);

extern EVP_PKEY *SSLConn_EVP_PKEY_new(void *buf, int len, SSLConnError *err);
extern X509 *SSLConn_X509_new(void *buf, int len, SSLConnError *err);

#endif