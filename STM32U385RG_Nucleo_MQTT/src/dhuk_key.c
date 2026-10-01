/* dhuk_key.c
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
 * TLS client authentication with a DHUK-wrapped ECC private key.
 *
 * wc_ecc_import_wrapped_private() puts the wrapped scalar on an ecc_key the
 * application owns, but TLS never signs with an application-supplied ecc_key:
 * it builds its own, either by decoding a DER private key or, for an opaque
 * key, from an id (wolfSSL_CTX_use_PrivateKey_Id -> wc_ecc_init_id). That key
 * carries no DHUK blob, so the STM32 DHUK device declines it and the handshake
 * falls back to the software signer, which fails with ECC_BAD_ARG_E (-170).
 *
 * The gap is closed with a second crypto-callback device. TLS is given a key
 * id bound to that device; the callback ignores the key TLS built and signs
 * with the provisioned key instead, whose devId is WC_DHUK_DEVID and so
 * dispatches to the real DHUK device. No wolfSSL change is needed.
 *
 * Only the client's CertificateVerify signature is device-bound. The ephemeral
 * ECDHE key, chain verification and record crypto are all ordinary.
 *
 * Provisioning stands in for a factory step, so it starts from the plaintext
 * client key: that scalar is in flash for the life of the image and in RAM
 * while it is wrapped, scrubbed with wc_ForceZero once the blob exists. A
 * product wraps the key off-device and ships only the blob and the seed, and
 * from that point the scalar never enters software at all.
 */

#include "wolfssl/wolfcrypt/settings.h"

#if defined(WOLFMQTT_DEMO) && defined(DEMO_DHUK_CLIENT_KEY)

#include <stdio.h>

#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/port/st/stm32.h"

#include "dhuk_key.h"

/* Device id for the TLS-facing shim. It must differ from WC_DHUK_DEVID so the
 * shim's own wc_ecc_sign_hash() dispatches to the DHUK device rather than
 * re-entering this callback. */
#ifndef DEMO_TLS_DHUK_DEVID
    #define DEMO_TLS_DHUK_DEVID 900
#endif

/* Largest scalar this demo provisions (P-384). */
#define DEMO_DHUK_MAX_KEYSZ 48

/* DHUK derivation seed. Mixed with the silicon DHUK inside SAES to derive the
 * key that wraps the scalar; it is not itself a secret key, and the wrapped
 * blob it produces only unwraps on the part that provisioned it. A product
 * stores this alongside the blob in flash. */
static const byte g_dhukSeed[32] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
    0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01
};

/* The id handed to wolfSSL_CTX_use_PrivateKey_Id(). This device binds exactly
 * one key, so the value is never looked up -- it only has to be non-empty. A
 * product with several device keys would key a lookup table off it. */
static const byte g_keyId[] = { 'd','h','u','k','-','c','l','i','e','n','t' };

/* The HAL build expects the application to own the PKA handle. */
PKA_HandleTypeDef hpka;

/* Bring up the PKA that the ECDSA sign path drives. wolfSSL's CubeMX port also
 * initialises it lazily, but that is internal to the port; doing it here makes
 * the dependency visible and reports a dead peripheral at startup instead of
 * mid-handshake. */
static int dhuk_pka_init(void)
{
    hpka.Instance = PKA;
    __HAL_RCC_PKA_CLK_ENABLE();
    if (HAL_PKA_Init(&hpka) != HAL_OK) {
        return WC_HW_E;
    }
    return 0;
}

static ecc_key g_dhukKey;
static int     g_keyReady;
static int     g_dhukRegistered;
static int     g_shimRegistered;

/* Sign the TLS CertificateVerify with the provisioned DHUK key. */
static int dhuk_tls_cryptocb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret;

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (info->algo_type != WC_ALGO_TYPE_PK ||
            info->pk.type != WC_PK_TYPE_ECDSA_SIGN) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (!g_keyReady) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* info->pk.eccsign.key was built from the key id and holds no scalar, so
     * it is deliberately not used here. */
    ret = wc_ecc_sign_hash(info->pk.eccsign.in, info->pk.eccsign.inlen,
                           info->pk.eccsign.out, info->pk.eccsign.outlen,
                           info->pk.eccsign.rng, &g_dhukKey);
    if (ret == 0) {
        printf("[dhuk] CertificateVerify signed on the device (%u-byte sig)\n",
               (unsigned int)*info->pk.eccsign.outlen);
    }
    else {
        printf("[dhuk] device sign failed: %d\n", ret);
    }
    return ret;
}

/* Provision the wrapped key and bring both devices up.
 *
 * keyDer is the plaintext client key, which stands in for a factory step: a
 * product wraps the scalar once during provisioning and ships only the blob
 * plus the seed, never this DER. */
int dhuk_client_key_provision(const unsigned char* keyDer, word32 keyDerSz,
                              int curveId)
{
    ecc_key plain;
    Aes     aes;
    byte    priv[DEMO_DHUK_MAX_KEYSZ];
    byte    wrapped[DEMO_DHUK_MAX_KEYSZ];
    word32  privSz = (word32)sizeof(priv);
    word32  idx = 0;
    int     keySz;
    int     ret;

    if (keyDer == NULL) {
        return BAD_FUNC_ARG;
    }
    keySz = wc_ecc_get_curve_size_from_id(curveId);
    if (keySz <= 0 || (word32)keySz > sizeof(priv)) {
        return BAD_FUNC_ARG;
    }
    /* The scalar is wrapped with AES-ECB, so its length has to be a whole
     * number of blocks. True for P-256 and P-384; P-192/P-224 are not. */
    if (((word32)keySz % WC_AES_BLOCK_SIZE) != 0u) {
        return BAD_FUNC_ARG;
    }

    ret = wc_Stm32_DhukRegister(WC_DHUK_DEVID);
    if (ret != 0) {
        printf("[dhuk] DhukRegister failed: %d\n", ret);
        return ret;
    }
    g_dhukRegistered = 1;

    ret = dhuk_pka_init();
    if (ret != 0) {
        printf("[dhuk] PKA init failed: %d\n", ret);
        goto err;
    }

    /* Factory half: recover the scalar, then wrap it under the DHUK-derived
     * key. The wrap runs inside SAES -- the KEK never exists in software. */
    ret = wc_ecc_init(&plain);
    if (ret == 0) {
        ret = wc_EccPrivateKeyDecode(keyDer, &idx, &plain, keyDerSz);
        if (ret == 0) {
            ret = wc_ecc_export_private_only(&plain, priv, &privSz);
        }
        wc_ecc_free(&plain);
    }
    if (ret == 0 && privSz != (word32)keySz) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
        if (ret == 0) {
            ret = wc_AesSetKey(&aes, g_dhukSeed, (word32)sizeof(g_dhukSeed),
                               NULL, AES_ENCRYPTION);
            if (ret == 0) {
                ret = wc_AesEcbEncrypt(&aes, wrapped, priv, (word32)keySz);
            }
            wc_AesFree(&aes);
        }
    }
    wc_ForceZero(priv, sizeof(priv));
    if (ret != 0) {
        printf("[dhuk] wrap failed: %d\n", ret);
        goto err;
    }

    /* Runtime half: the shape a product boots into -- only the blob and the
     * seed reach the key, and the scalar never enters software again. */
    ret = wc_ecc_init_ex(&g_dhukKey, NULL, WC_DHUK_DEVID);
    if (ret != 0) {
        goto err;
    }
    ret = wc_ecc_import_wrapped_private(&g_dhukKey, curveId, g_dhukSeed,
                                        (word32)sizeof(g_dhukSeed), wrapped,
                                        (word32)keySz, (word32)keySz);
    if (ret != 0) {
        printf("[dhuk] import_wrapped_private failed: %d\n", ret);
        wc_ecc_free(&g_dhukKey);
        goto err;
    }
    g_keyReady = 1;

    ret = wc_CryptoCb_RegisterDevice(DEMO_TLS_DHUK_DEVID, dhuk_tls_cryptocb,
                                     NULL);
    if (ret != 0) {
        printf("[dhuk] shim register failed: %d\n", ret);
        g_keyReady = 0;
        wc_ecc_free(&g_dhukKey);
        goto err;
    }
    g_shimRegistered = 1;

    printf("[dhuk] client key provisioned (%d-byte wrapped scalar)\n", keySz);
    return 0;

err:
    wc_ForceZero(wrapped, sizeof(wrapped));
    dhuk_client_key_cleanup();
    return ret;
}

/* Point the CTX at the device key.
 *
 * The client certificate must already be loaded: loading it is what sets the
 * CTX private key type and size, and the id path carries neither. The devId
 * belongs on the key, not on the CTX -- wolfSSL_CTX_SetDevId() would also send
 * the ephemeral ECDHE keygen to the device. */
int dhuk_client_key_use(WOLFSSL_CTX* ctx)
{
    int rc;

    if (ctx == NULL || !g_keyReady) {
        return BAD_FUNC_ARG;
    }
    rc = wolfSSL_CTX_use_PrivateKey_Id(ctx, g_keyId, (long)sizeof(g_keyId),
                                       DEMO_TLS_DHUK_DEVID);
    if (rc != WOLFSSL_SUCCESS) {
        printf("[dhuk] use_PrivateKey_Id failed: %d\n", rc);
        return WOLFSSL_FATAL_ERROR;
    }
    return 0;
}

void dhuk_client_key_cleanup(void)
{
    if (g_shimRegistered) {
        wc_CryptoCb_UnRegisterDevice(DEMO_TLS_DHUK_DEVID);
        g_shimRegistered = 0;
    }
    if (g_keyReady) {
        wc_ecc_free(&g_dhukKey);
        g_keyReady = 0;
    }
    if (g_dhukRegistered) {
        wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
        g_dhukRegistered = 0;
    }
}

#endif /* WOLFMQTT_DEMO && DEMO_DHUK_CLIENT_KEY */
