#include "error.h"

#include <assert.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "cgo_binding.h"
#include "error.h"
#include "thread.h"
#include "_cgo_export.h"

void handle_error(SSLConnError *err) {
    err->code = ERR_get_error();
    ERR_error_string_n(err->code, err->string, sizeof(err->string));
}

int handle_ret_code(SSLConn *conn, SSLConnError *err, int code) {
    int result;

    switch (SSL_get_error(conn->ssl, code)) {
    case SSL_ERROR_NONE:
        result = code;
        break;
    case SSL_ERROR_ZERO_RETURN:
        result = SSLConn_ZERO_RETURN;
        break;
    case SSL_ERROR_WANT_READ:
        result = SSLConn_WANT_READ;
        break;
    case SSL_ERROR_WANT_WRITE:
        result = SSLConn_WANT_WRITE;
        break;
    case SSL_ERROR_SYSCALL:
        result = SSLConn_SYSCALL;
        break;
    default:
        goto error;
    }

    ERR_remove_state(0);
    return result;

error:
    handle_error(err);
    ERR_remove_state(0);
    return SSLConn_SSL_ERROR;
}