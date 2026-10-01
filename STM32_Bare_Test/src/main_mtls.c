/* main_mtls.c
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
 * TLS 1.3 mutual authentication, client and server both in this image.
 *
 * On a board with SAES + DHUK + PKA the client's private key exists only as a
 * DHUK-wrapped blob, unwrapped inside SAES for each signature. On every other
 * board the same handshake runs with an ordinary in-memory client key, so this
 * target doubles as a plain TLS 1.3 mutual-auth regression test. MTLS_HAVE_DHUK
 * selects between the two.
 *
 * Client and server both run in this image and talk over a pair of in-memory
 * buffers, so the handshake is exercised with no network stack, no sockets and
 * no host. That keeps the test identical across every board that has SAES,
 * DHUK and PKA -- the point being that nothing here is family-specific.
 *
 * The connecting piece is the crypto-callback device below.
 * wc_ecc_import_wrapped_private() puts the blob on an ecc_key this file owns,
 * but TLS builds its own key internally -- from a DER buffer, or for an opaque
 * key from a key id -- and that key carries no blob, so the DHUK device
 * declines it and the handshake would fall back to the software signer and
 * fail. Handing TLS a key id bound to this second device routes the
 * CertificateVerify signature to the provisioned key instead.
 */

#include "board.h"
#include <stdio.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/version.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/aes.h"
/* Must precede the guard below: WC_STM32_HAS_DHUK is defined here. */
#include "wolfssl/wolfcrypt/port/st/stm32.h"

#ifdef STM32_BARE_MTLS

/* The device-bound key path needs all three blocks; without them this target
 * still exercises the full mutual-auth handshake with an ordinary key. */
#if defined(WOLFSSL_DHUK) && defined(WC_STM32_HAS_DHUK) && \
    defined(WOLFSSL_STM32_PKA)
    #define MTLS_HAVE_DHUK
#endif

#include "wolfssl/ssl.h"
#include "wolfssl/certs_test.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

#define MTLS_KEYSZ   32               /* P-256 scalar */
#define MTLS_BUFSZ   (16 * 1024)      /* one direction of the transport */

#ifdef MTLS_HAVE_DHUK
/* Must differ from WC_DHUK_DEVID so the sign below dispatches to the DHUK
 * device instead of re-entering this callback. */
#ifndef MTLS_SHIM_DEVID
    #define MTLS_SHIM_DEVID 901
#endif


/* DHUK derivation seed: mixed with the silicon DHUK inside SAES to derive the
 * key that wraps the scalar. Not itself a secret, and the blob it produces
 * only unwraps on the part that made it. */
static const byte g_seed[32] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
    0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01
};

/* This device binds one key, so the id is never looked up; it only has to be
 * non-empty. A product with several device keys keys a table off it. */
static const byte g_keyId[] = { 'd','h','u','k','-','m','t','l','s' };

static ecc_key g_dhukKey;
static int     g_keyReady;
#endif /* MTLS_HAVE_DHUK */

/* ---- in-memory transport ------------------------------------------------ */

typedef struct {
    byte   buf[MTLS_BUFSZ];
    word32 len;
    word32 rd;
} MemChan;

static MemChan g_c2s;   /* client -> server */
static MemChan g_s2c;   /* server -> client */

static int mem_send(MemChan* ch, const char* in, int sz)
{
    if ((word32)sz > sizeof(ch->buf) - ch->len) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    XMEMCPY(ch->buf + ch->len, in, (size_t)sz);
    ch->len += (word32)sz;
    return sz;
}

static int mem_recv(MemChan* ch, char* out, int sz)
{
    word32 avail = ch->len - ch->rd;

    if (avail == 0u) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    if ((word32)sz > avail) {
        sz = (int)avail;
    }
    XMEMCPY(out, ch->buf + ch->rd, (size_t)sz);
    ch->rd += (word32)sz;
    if (ch->rd == ch->len) {
        ch->rd = 0;
        ch->len = 0;
    }
    return sz;
}

static int cli_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl; (void)ctx;
    return mem_send(&g_c2s, buf, sz);
}
static int cli_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl; (void)ctx;
    return mem_recv(&g_s2c, buf, sz);
}
static int srv_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl; (void)ctx;
    return mem_send(&g_s2c, buf, sz);
}
static int srv_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl; (void)ctx;
    return mem_recv(&g_c2s, buf, sz);
}

/* ---- the DHUK TLS key --------------------------------------------------- */

#ifdef MTLS_HAVE_DHUK
static int mtls_sign_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret;

    (void)devId;
    (void)ctx;

    if (info == NULL || info->algo_type != WC_ALGO_TYPE_PK ||
            info->pk.type != WC_PK_TYPE_ECDSA_SIGN || !g_keyReady) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* info->pk.eccsign.key came from the key id and holds no scalar. */
    ret = wc_ecc_sign_hash(info->pk.eccsign.in, info->pk.eccsign.inlen,
                           info->pk.eccsign.out, info->pk.eccsign.outlen,
                           info->pk.eccsign.rng, &g_dhukKey);
    if (ret == 0) {
        printf("  CertificateVerify signed on the device (%u-byte sig)\n",
               (unsigned int)*info->pk.eccsign.outlen);
    }
    return ret;
}

/* Wrap the test client key under the DHUK-derived KEK and import the blob.
 * Stands in for a factory step: a product wraps once during provisioning and
 * ships only the blob and the seed. */
static int mtls_provision(void)
{
    ecc_key plain;
    Aes     aes;
    byte    priv[MTLS_KEYSZ];
    byte    wrapped[MTLS_KEYSZ];
    word32  privSz = (word32)sizeof(priv);
    word32  idx = 0;
    int     ret;

    ret = wc_ecc_init(&plain);
    if (ret == 0) {
        ret = wc_EccPrivateKeyDecode(ecc_clikey_der_256, &idx, &plain,
                                     (word32)sizeof_ecc_clikey_der_256);
        if (ret == 0) {
            ret = wc_ecc_export_private_only(&plain, priv, &privSz);
        }
        wc_ecc_free(&plain);
    }
    if (ret == 0 && privSz != (word32)MTLS_KEYSZ) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
        if (ret == 0) {
            ret = wc_AesSetKey(&aes, g_seed, (word32)sizeof(g_seed), NULL,
                               AES_ENCRYPTION);
            if (ret == 0) {
                ret = wc_AesEcbEncrypt(&aes, wrapped, priv, MTLS_KEYSZ);
            }
            wc_AesFree(&aes);
        }
    }
    wc_ForceZero(priv, sizeof(priv));
    if (ret != 0) {
        printf("  provisioning failed: %d\n", ret);
        return ret;
    }

    ret = wc_ecc_init_ex(&g_dhukKey, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_ecc_import_wrapped_private(&g_dhukKey, ECC_SECP256R1, g_seed,
                                            (word32)sizeof(g_seed), wrapped,
                                            MTLS_KEYSZ, MTLS_KEYSZ);
        if (ret != 0) {
            wc_ecc_free(&g_dhukKey);
        }
    }
    if (ret != 0) {
        printf("  import_wrapped_private failed: %d\n", ret);
        return ret;
    }
    g_keyReady = 1;
    printf("  client key wrapped and imported (no scalar in software)\n");
    return 0;
}
#endif /* MTLS_HAVE_DHUK */

/* ---- the handshake ------------------------------------------------------ */

static int mtls_handshake(void)
{
    WOLFSSL_CTX* cliCtx = NULL;
    WOLFSSL_CTX* srvCtx = NULL;
    WOLFSSL*     cli = NULL;
    WOLFSSL*     srv = NULL;
    int cliRet = WOLFSSL_FATAL_ERROR;
    int srvRet = WOLFSSL_FATAL_ERROR;
    int ret = -1;
    int i;

    XMEMSET(&g_c2s, 0, sizeof(g_c2s));
    XMEMSET(&g_s2c, 0, sizeof(g_s2c));

    cliCtx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    srvCtx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (cliCtx == NULL || srvCtx == NULL) {
        printf("  CTX_new failed\n");
        goto cleanup;
    }

    /* Server: cert + ordinary private key, and it demands a client cert. The
     * wolfSSL ECC client test certificate is self-signed, so it is its own
     * trust anchor -- that is what the server loads to verify the client. */
    if (wolfSSL_CTX_use_certificate_buffer(srvCtx, serv_ecc_der_256,
            (long)sizeof_serv_ecc_der_256, WOLFSSL_FILETYPE_ASN1)
                != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_buffer(srvCtx, ecc_key_der_256,
            (long)sizeof_ecc_key_der_256, WOLFSSL_FILETYPE_ASN1)
                != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_load_verify_buffer(srvCtx, cliecc_cert_der_256,
            (long)sizeof_cliecc_cert_der_256, WOLFSSL_FILETYPE_ASN1)
                != WOLFSSL_SUCCESS) {
        printf("  server cert/key load failed\n");
        goto cleanup;
    }
    wolfSSL_CTX_set_verify(srvCtx,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* Client: cert as usual, but the key is the DHUK blob behind a key id.
     * The certificate load must come first -- it is what sets the CTX private
     * key type and size, which the id path does not carry. */
    if (wolfSSL_CTX_use_certificate_buffer(cliCtx, cliecc_cert_der_256,
            (long)sizeof_cliecc_cert_der_256, WOLFSSL_FILETYPE_ASN1)
                != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_load_verify_buffer(cliCtx, ca_ecc_cert_der_256,
            (long)sizeof_ca_ecc_cert_der_256, WOLFSSL_FILETYPE_ASN1)
                != WOLFSSL_SUCCESS) {
        printf("  client cert load failed\n");
        goto cleanup;
    }
#ifdef MTLS_HAVE_DHUK
    /* The devId belongs on the key, not on the CTX: a CTX-wide devId would
     * also route the ephemeral ECDHE keygen to the device. */
    if (wolfSSL_CTX_use_PrivateKey_Id(cliCtx, g_keyId, (long)sizeof(g_keyId),
            MTLS_SHIM_DEVID) != WOLFSSL_SUCCESS) {
        printf("  use_PrivateKey_Id failed\n");
        goto cleanup;
    }
#else
    /* No device key on this part: ordinary in-memory client key, so the
     * handshake itself is still covered. */
    if (wolfSSL_CTX_use_PrivateKey_buffer(cliCtx, ecc_clikey_der_256,
            (long)sizeof_ecc_clikey_der_256, WOLFSSL_FILETYPE_ASN1)
                != WOLFSSL_SUCCESS) {
        printf("  client key load failed\n");
        goto cleanup;
    }
#endif
    wolfSSL_CTX_set_verify(cliCtx, WOLFSSL_VERIFY_PEER, NULL);

    wolfSSL_CTX_SetIOSend(cliCtx, cli_send);
    wolfSSL_CTX_SetIORecv(cliCtx, cli_recv);
    wolfSSL_CTX_SetIOSend(srvCtx, srv_send);
    wolfSSL_CTX_SetIORecv(srvCtx, srv_recv);

    cli = wolfSSL_new(cliCtx);
    srv = wolfSSL_new(srvCtx);
    if (cli == NULL || srv == NULL) {
        printf("  wolfSSL_new failed\n");
        goto cleanup;
    }

    /* Pump both ends until each reports a finished handshake. Neither side
     * blocks: the transport returns WANT_READ when its buffer is empty. */
    for (i = 0; i < 40; i++) {
        if (cliRet != WOLFSSL_SUCCESS) {
            cliRet = wolfSSL_connect(cli);
            if (cliRet != WOLFSSL_SUCCESS) {
                int err = wolfSSL_get_error(cli, cliRet);
                if (err != WOLFSSL_ERROR_WANT_READ &&
                        err != WOLFSSL_ERROR_WANT_WRITE) {
                    printf("  wolfSSL_connect failed: %d\n", err);
                    ret = (err != 0) ? err : -1;
                    goto cleanup;
                }
            }
        }
        if (srvRet != WOLFSSL_SUCCESS) {
            srvRet = wolfSSL_accept(srv);
            if (srvRet != WOLFSSL_SUCCESS) {
                int err = wolfSSL_get_error(srv, srvRet);
                if (err != WOLFSSL_ERROR_WANT_READ &&
                        err != WOLFSSL_ERROR_WANT_WRITE) {
                    printf("  wolfSSL_accept failed: %d\n", err);
                    ret = (err != 0) ? err : -1;
                    goto cleanup;
                }
            }
        }
        if (cliRet == WOLFSSL_SUCCESS && srvRet == WOLFSSL_SUCCESS) {
            break;
        }
    }
    if (cliRet != WOLFSSL_SUCCESS || srvRet != WOLFSSL_SUCCESS) {
        printf("  handshake did not complete (cli=%d srv=%d)\n",
               cliRet, srvRet);
        goto cleanup;
    }
    printf("  handshake OK: %s / %s\n", wolfSSL_get_version(cli),
           wolfSSL_get_cipher(cli));

    /* The server runs with VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT against a
     * loaded CA, so wolfSSL_accept() cannot reach this point unless it received
     * a client certificate that chained to that CA and a CertificateVerify that
     * validated against it -- which is the signature produced above from the
     * wrapped scalar where the part has one. Handshake completion is the
     * mutual-auth proof; test [3] shows it failing when the device key is
     * taken away. */
    printf("  server required and verified the client certificate\n");
    ret = 0;

cleanup:
    if (cli != NULL) wolfSSL_free(cli);
    if (srv != NULL) wolfSSL_free(srv);
    if (cliCtx != NULL) wolfSSL_CTX_free(cliCtx);
    if (srvCtx != NULL) wolfSSL_CTX_free(srvCtx);
    return ret;
}
#endif /* STM32_BARE_MTLS */

int main(void)
{
    int ret = 0;

    board_init();
    SystemCoreClockUpdate();

    printf("\n");
    printf("========================================\n");
    printf("wolfSSL DHUK mTLS test - %s (CONFIG=%s)\n",
           board_name(), BUILD_CONFIG_NAME);
    printf("wolfSSL version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("========================================\n\n");

#ifdef STM32_BARE_MTLS
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        printf("wolfSSL_Init failed: %d\n", ret);
        ret = -1;
        goto done;
    }
#ifdef MTLS_HAVE_DHUK
    ret = wc_Stm32_DhukRegister(WC_DHUK_DEVID);
    if (ret != 0) {
        printf("DhukRegister failed: %d\n", ret);
        goto done;
    }
    ret = wc_CryptoCb_RegisterDevice(MTLS_SHIM_DEVID, mtls_sign_cb, NULL);
    if (ret != 0) {
        printf("shim register failed: %d\n", ret);
        goto done;
    }

    printf("[1] Provision the DHUK-wrapped client key:\n");
    ret = mtls_provision();
    if (ret != 0) {
        goto done;
    }
#else
    printf("[1] No SAES/DHUK/PKA on this part -- ordinary client key.\n");
#endif

    printf("\n[2] TLS 1.3 mutual-auth handshake over an in-memory transport:\n");
    ret = mtls_handshake();
    if (ret != 0) {
        goto done;
    }

#ifdef MTLS_HAVE_DHUK
    /* Negative control: take the device away and the same handshake must fail.
     * Without it, a passing [2] would not prove the wrapped key was what
     * authenticated the client. The key TLS builds from the id has no curve,
     * so the software signer rejects it with ECC_BAD_ARG_E; any other failure
     * is not this test passing. */
    printf("\n[3] Same handshake with the device key removed "
           "(must fail):\n");
    wc_CryptoCb_UnRegisterDevice(MTLS_SHIM_DEVID);
    ret = mtls_handshake();
    if (ret == 0) {
        printf("  handshake completed without the device -- FAIL\n");
        ret = -1;
    }
    else if (ret == WC_NO_ERR_TRACE(ECC_BAD_ARG_E)) {
        printf("  refused with ECC_BAD_ARG_E, as expected\n");
        ret = 0;
    }
    else {
        printf("  failed with %d, expected %d -- FAIL\n", ret,
               WC_NO_ERR_TRACE(ECC_BAD_ARG_E));
    }
#endif /* MTLS_HAVE_DHUK */

done:
#ifdef MTLS_HAVE_DHUK
    if (g_keyReady) {
        wc_ecc_free(&g_dhukKey);
        g_keyReady = 0;
    }
    /* no-op when test [3] already removed the shim */
    wc_CryptoCb_UnRegisterDevice(MTLS_SHIM_DEVID);
    wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
#endif
    wolfSSL_Cleanup();
#else
    printf("mTLS test not enabled in this build (needs STM32_BARE_MTLS).\n");
    ret = -1;
#endif

    printf("\nResult: %d (%s)\n", ret, ret == 0 ? "PASS" : "FAIL");
    printf("Test complete\n");

    for (;;) { }
}
