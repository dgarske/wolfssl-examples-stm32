/* dhuk_key.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * Use a DHUK-wrapped ECC private key as the client key of a TLS mutual-auth
 * handshake. See dhuk_key.c for how the pieces fit together.
 */
#ifndef DEMO_DHUK_KEY_H
#define DEMO_DHUK_KEY_H

#include "wolfssl/ssl.h"

int  dhuk_client_key_provision(const unsigned char* keyDer, word32 keyDerSz,
                               int curveId);
int  dhuk_client_key_use(WOLFSSL_CTX* ctx);
void dhuk_client_key_cleanup(void);

#endif /* DEMO_DHUK_KEY_H */
