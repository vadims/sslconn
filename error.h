#ifndef sslconn_error_h
#define sslconn_error_h

#include "cgo_binding.h"

int handle_ret_code(SSLConn *conn, SSLConnError *err, int code);
void handle_error(SSLConnError *err);

#endif