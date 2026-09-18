/* main_ccb.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * wolfSSL CCB (Coupling and Chaining Bridge) ECDSA test -- STM32U3 (u3 = U385).
 * Exercises the *transparent* path through the standard ECC API: a key bound
 * to WC_DHUK_DEVID is provisioned with the normal wc_ecc_make_key() -- the STM32
 * crypto callback intercepts keygen and binds a CCB-protected blob -- and then
 * signs through wc_ecc_sign_hash(). The P-256 private scalar is unwrapped
 * SAES->PKA in hardware and never enters software. No CCB-specific API is used.
 * Works on both build paths:
 *   make BOARD=u3 BUILD=cubemx TARGET=ccb   (HAL_CCB backend)
 *   make BOARD=u3 CONFIG=bare  TARGET=ccb   (bare-metal OPSTEP backend)
 *
 *   [1] wc_ecc_make_key    -- provision a device-bound CCB key (crypto callback).
 *   [2] wc_ecc_sign_hash   -- transparent sign via the crypto callback.
 *   [3] wc_ecc_verify_hash -- verify (r,s) against the CCB-derived pubkey.
 */

#include <stdio.h>

#include "board.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/version.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/port/st/stm32.h"

#ifndef BUILD_CONFIG_NAME
#define BUILD_CONFIG_NAME "unknown"
#endif

/* Fixed message hash to sign (arbitrary 32-byte test value). */
static const byte test_hash[32] = {
    0x44,0xac,0xf6,0xb7,0xe3,0x6c,0x13,0x42,0xc2,0xc5,0x89,0x72,0x04,0xfe,0x09,0x50,
    0x4e,0x1e,0x2e,0xfb,0x1a,0x90,0x03,0x77,0xdb,0xc4,0xe7,0xa6,0xa1,0x33,0xec,0x56};

#if defined(WOLFSSL_STM32_CCB) && defined(WOLFSSL_DHUK) && defined(WOLF_CRYPTO_CB)
/* Argument-validation (negative) checks for the public device-wrapped key
 * import API wc_ecc_import_wrapped_private_ex. Each call passes exactly one
 * invalid argument and must be rejected with BAD_FUNC_ARG before any hardware
 * is touched. Returns 0 if every malformed call was rejected, else -1 (or the
 * wc_ecc_init error). P-256: modSz = 32, so a valid pub is qx||qy = 64 bytes. */
static int ccb_import_arg_checks(void)
{
    ecc_key key;
    byte    wrapped[96];
    byte    iv[16];
    byte    tag[16];
    byte    pub[64];        /* qx || qy, P-256 (2 * 32) */
    int     ret;
    int     fails = 0;

    XMEMSET(wrapped, 0, sizeof(wrapped));
    XMEMSET(iv,  0, sizeof(iv));
    XMEMSET(tag, 0, sizeof(tag));
    XMEMSET(pub, 0, sizeof(pub));

    ret = wc_ecc_init(&key);
    if (ret != 0) {
        return ret;
    }

#define CCB_EXPECT_BADARG(call)                                              \
    do { if ((call) != BAD_FUNC_ARG) { fails++; } } while (0)

    /* NULL pointer arguments. */
    CCB_EXPECT_BADARG(wc_ecc_import_wrapped_private_ex(NULL, ECC_SECP256R1,
        wrapped, sizeof(wrapped), iv, sizeof(iv), tag, sizeof(tag),
        pub, sizeof(pub)));
    CCB_EXPECT_BADARG(wc_ecc_import_wrapped_private_ex(&key, ECC_SECP256R1,
        NULL, sizeof(wrapped), iv, sizeof(iv), tag, sizeof(tag),
        pub, sizeof(pub)));
    CCB_EXPECT_BADARG(wc_ecc_import_wrapped_private_ex(&key, ECC_SECP256R1,
        wrapped, sizeof(wrapped), NULL, sizeof(iv), tag, sizeof(tag),
        pub, sizeof(pub)));
    CCB_EXPECT_BADARG(wc_ecc_import_wrapped_private_ex(&key, ECC_SECP256R1,
        wrapped, sizeof(wrapped), iv, sizeof(iv), NULL, sizeof(tag),
        pub, sizeof(pub)));
    CCB_EXPECT_BADARG(wc_ecc_import_wrapped_private_ex(&key, ECC_SECP256R1,
        wrapped, sizeof(wrapped), iv, sizeof(iv), tag, sizeof(tag),
        NULL, sizeof(pub)));
    /* Wrong iv / tag length (must be 16 each). */
    CCB_EXPECT_BADARG(wc_ecc_import_wrapped_private_ex(&key, ECC_SECP256R1,
        wrapped, sizeof(wrapped), iv, 15, tag, sizeof(tag),
        pub, sizeof(pub)));
    CCB_EXPECT_BADARG(wc_ecc_import_wrapped_private_ex(&key, ECC_SECP256R1,
        wrapped, sizeof(wrapped), iv, sizeof(iv), tag, 17,
        pub, sizeof(pub)));
    /* Invalid curve id (modSz <= 0). */
    CCB_EXPECT_BADARG(wc_ecc_import_wrapped_private_ex(&key, ECC_CURVE_INVALID,
        wrapped, sizeof(wrapped), iv, sizeof(iv), tag, sizeof(tag),
        pub, sizeof(pub)));
    /* wrappedLen 0 / above the fixed blob buffer. */
    CCB_EXPECT_BADARG(wc_ecc_import_wrapped_private_ex(&key, ECC_SECP256R1,
        wrapped, 0, iv, sizeof(iv), tag, sizeof(tag),
        pub, sizeof(pub)));
    CCB_EXPECT_BADARG(wc_ecc_import_wrapped_private_ex(&key, ECC_SECP256R1,
        wrapped, sizeof(wrapped) + 1u, iv, sizeof(iv), tag, sizeof(tag),
        pub, sizeof(pub)));
    /* Wrong public-key length (pubLen != 2 * modSz). */
    CCB_EXPECT_BADARG(wc_ecc_import_wrapped_private_ex(&key, ECC_SECP256R1,
        wrapped, sizeof(wrapped), iv, sizeof(iv), tag, sizeof(tag),
        pub, sizeof(pub) - 1u));

#undef CCB_EXPECT_BADARG

#if defined(WOLFSSL_STM32_BARE) && defined(WC_STM32_HAS_DHUK)
    /* A DHUK seed (non-CCB) import must clear any CCB routing left on the key,
     * so a re-imported non-CCB key does not dispatch to the CCB sign path. */
    {
        byte seed[32];
        XMEMSET(seed, 0x5a, sizeof(seed));
        key.dhuk_is_ccb = 1;
        if (wc_ecc_import_wrapped_private(&key, ECC_SECP256R1, seed,
                sizeof(seed),
                wrapped, 32, 32) != 0 || key.dhuk_is_ccb != 0) {
            fails++;
        }
    }
#endif

    wc_ecc_free(&key);
    return (fails == 0) ? 0 : -1;
}

/* Positive / state test for wc_ecc_import_wrapped_private_ex: persist the blob
 * from the provisioned CCB key, re-import it onto a fresh key, confirm the
 * on-key state was populated and routed to the CCB path, then verify a signature
 * made by the original key against the re-imported one. Returns 0 on success. */
static int ccb_import_roundtrip(ecc_key* prov, const byte* sig, word32 sigLen)
{
    ecc_key key2;
    byte    pub[64];                 /* qx || qy, P-256 */
    word32  qxLen = 32, qyLen = 32;
    int     ret;
    int     verified = 0;

    /* Only applicable when keygen actually produced a CCB-protected blob; if the
     * device fell back to software keygen there is no blob to re-import. */
    if (prov->dhuk_is_ccb != 1 || prov->dhuk_wrapped_priv_len == 0) {
        printf("    (skipped: provisioned key is not CCB-backed)\n");
        return 0;
    }
    ret = wc_ecc_export_public_raw(prov, pub, &qxLen, pub + 32, &qyLen);
    if (ret != 0) {
        return ret;
    }
    ret = wc_ecc_init_ex(&key2, NULL, WC_DHUK_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_ecc_import_wrapped_private_ex(&key2, ECC_SECP256R1,
            prov->dhuk_wrapped_priv, prov->dhuk_wrapped_priv_len,
            prov->ccb_iv, 16, prov->ccb_tag, 16, pub, 64);
    if (ret == 0) {
        /* State must reflect the imported blob and select the CCB sign path. */
        if (key2.dhuk_wrapped_priv_len != prov->dhuk_wrapped_priv_len ||
            XMEMCMP(key2.ccb_iv,  prov->ccb_iv,  16) != 0 ||
            XMEMCMP(key2.ccb_tag, prov->ccb_tag, 16) != 0 ||
            key2.dhuk_is_ccb != 1) {
            ret = -1;
        }
    }
    if (ret == 0) {
        /* The re-imported key must verify a signature from the original. */
        ret = wc_ecc_verify_hash(sig, sigLen, test_hash, sizeof(test_hash),
                                 &verified, &key2);
        if (ret == 0 && verified != 1) {
            ret = -1;
        }
    }
    wc_ecc_free(&key2);
    return ret;
}
#endif /* WOLFSSL_STM32_CCB && WOLFSSL_DHUK && WOLF_CRYPTO_CB */

int main(void)
{
    int ret = 0;

    board_init();

    printf("\n========================================\n");
    printf("wolfCrypt CCB ECDSA test - %s (CONFIG=%s)\n",
           board_name(), BUILD_CONFIG_NAME);
    printf("wolfSSL version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("========================================\n\n");

    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("wolfCrypt_Init failed: %d\n", ret);
        for (;;) { }
    }

#if defined(WOLFSSL_STM32_CCB) && defined(WOLFSSL_DHUK) && defined(WOLF_CRYPTO_CB)
    {
        ecc_key key;
        WC_RNG  rng;
        byte    sig[72];
        word32  sigLen = (word32)sizeof(sig);
        int     verified = 0;
        int     haveKey = 0;
        int     haveRng = 0;

        ret = wc_InitRng(&rng);
        if (ret == 0) {
            haveRng = 1;
            /* Register the STM32 DHUK/CCB crypto-callback device. */
            ret = wc_Stm32_DhukRegister(WC_DHUK_DEVID);
        }
        if (ret == 0) {
            ret = wc_ecc_init_ex(&key, NULL, WC_DHUK_DEVID);
        }
        if (ret == 0) {
            haveKey = 1;
            printf("[1] wc_ecc_make_key (provision P-256 CCB key on-device):\n");
            /* Standard ECC keygen -- the STM32 crypto callback intercepts it
             * and binds a fresh CCB-protected blob to the key. No CCB API. */
            ret = wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1);
            printf("    ret = %d\n", ret);
        }
        if (ret == 0 && key.dhuk_is_ccb != 1) {
            /* make/sign/verify still succeed if the callback fell back to
             * software keygen; require the real CCB-protected key. */
            printf("    ERROR: CCB fell back to software keygen "
                   "(dhuk_is_ccb=%d)\n", key.dhuk_is_ccb);
            ret = -1;
        }
        if (ret == 0) {
            printf("[2] wc_ecc_sign_hash (transparent crypto-callback):\n");
            ret = wc_ecc_sign_hash(test_hash, sizeof(test_hash), sig, &sigLen,
                                   &rng, &key);
            printf("    ret = %d (sigLen=%u)\n", ret, (unsigned)sigLen);
        }
        if (ret == 0) {
            printf("[3] wc_ecc_verify_hash (vs CCB-derived public key):\n");
            ret = wc_ecc_verify_hash(sig, sigLen, test_hash, sizeof(test_hash),
                                     &verified, &key);
            printf("    ret = %d verified = %d\n", ret, verified);
            if (ret == 0 && verified != 1) {
                ret = -1;
            }
        }
        if (ret == 0) {
            printf("[4] wc_ecc_import_wrapped_private_ex arg validation:\n");
            ret = ccb_import_arg_checks();
            printf("    ret = %d (all malformed calls rejected)\n", ret);
        }
        if (ret == 0) {
            printf("[5] wc_ecc_import_wrapped_private_ex round-trip + state:\n");
            ret = ccb_import_roundtrip(&key, sig, sigLen);
            printf("    ret = %d (re-import state OK, sig verified)\n", ret);
        }

        if (haveKey) {
            wc_ecc_free(&key);
        }
        if (haveRng) {
            wc_FreeRng(&rng);
        }
        wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
    }
#else
    printf("CCB support not compiled in (need WOLFSSL_STM32_CCB on a U3)\n");
    ret = NOT_COMPILED_IN;
#endif

    wolfCrypt_Cleanup();
    printf("\nResult: %d (%s)\n", ret, ret == 0 ? "PASS" : "FAIL");
    printf("Test complete\n");
    for (;;) { }
}
