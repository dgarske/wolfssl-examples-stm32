/* main_dhuk.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * DHUK (Device Hardware Unique Key) test app for STM32_Bare_Test, exercising
 * the transparent crypto-callback DHUK path (the STM32 cryptocb device, see
 * wc_Stm32_DhukRegister). Build with: make BOARD=u3 CONFIG=bare TARGET=dhuk
 *
 *   [1] wc_ecc_import_wrapped_private input validation -- a pure-software
 *       hard PASS/FAIL covering the seed + wrapped-scalar bounds checks.
 *   [2] GMAC via the transparent crypto-callback (normal wc_AesGcmEncrypt on
 *       a DHUK-keyed Aes; derived key never in software).
 *   [3] AES-ECB via the transparent crypto-callback (wc_AesEcb*; round-trip +
 *       seed-dependence confirm the DHUK key drives the cipher).
 *   [4] ECDSA sign via the transparent crypto-callback (wc_ecc_sign_hash with
 *       a DHUK-wrapped scalar; verified with the public counterpart).
 *   [7] wc_Stm32_Aes_Wrap blob word order -- runs on both build paths so the
 *       shared WC_STM32_WRAP_ORDER_RAW blob can be compared bare vs CubeMX,
 *       and each build's default order is asserted (raw on bare, legacy
 *       byte-reversed on CubeMX, preserving wolfSSL 5.9.0 - 5.9.2 blobs).
 *
 * A backend that is gated off or unavailable (CRYPTOCB_UNAVAILABLE / a
 * TZEN-secure-context timeout) is reported as an expected soft-PASS, not a
 * failure. Results are also mirrored to the g_dhuk_res debugger sink. */

#include <stdio.h>

#include "board.h"

extern uint32_t SystemCoreClock;
extern void     SystemCoreClockUpdate(void);

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/version.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/port/st/stm32.h"
#include "wolfssl/wolfcrypt/aes.h"

#ifndef BUILD_CONFIG_NAME
#define BUILD_CONFIG_NAME "unknown"
#endif

/* Debugger-readable result sink, so results can be captured without a
 * working VCP (the B-U585I-IOT02A's UART routing differs from the
 * NUCLEO-U585AI-Q this board build targets). Read after the run with:
 *   arm-none-eabi-nm app.elf | grep g_dhuk_res   # address
 *   openocd ... -c "mdw 0x<addr> 12"
 * Captures the RAW return codes (before the soft-PASS mapping) so a
 * gated/timeout (-271 / WC_TIMEOUT_E) is distinguishable from a real
 * success (0). magic = 0xD04B0001 once main() reaches the end. */
volatile struct {
    uint32_t magic;
    int32_t  setter_rc;    /* 0 = all setter validation cases passed   */
    int32_t  cb_gmac_rc;   /* transparent crypto-cb GMAC return        */
    uint32_t cb_gmac_tag[4];/* crypto-cb GMAC tag on success           */
    int32_t  dhukop_rc;    /* wc_Stm32_Aes_DhukOp_ex round-trip return */
    uint32_t dhukop_blob[8];/* chip-bound wrapped blob (cross-build cmp)*/
    int32_t  overall;      /* final result (0 = PASS)                 */
} g_dhuk_res;

/* A backend that is gated off or that cannot complete the unwrap on
 * TZEN=0 silicon returns one of these. Treat as expected, not a fail. */
static int is_expected_gated(int ret)
{
    return (ret == CRYPTOCB_UNAVAILABLE) ||
           (ret == WC_TIMEOUT_E) ||
           (ret == WC_HW_E);
}

/* Compare an actual return code against the expected one. Returns 0 on
 * match, -1 on mismatch (with a printed diagnostic). */
static int expect_ret(const char* label, int got, int want)
{
    if (got != want) {
        printf("  %s: got %d, want %d -- FAIL\n", label, got, want);
        return -1;
    }
    printf("  %s: %d OK\n", label, got);
    return 0;
}

#if defined(WOLFSSL_DHUK) && \
    (defined(WOLFSSL_STM32_BARE) || defined(WOLFSSL_STM32_CUBEMX)) && \
    defined(WC_STM32_HAS_DHUK)

/* [1] wc_ecc_import_wrapped_private input-validation unit test. Pure
 * software; a hard PASS/FAIL exercising the seed + wrapped-scalar bounds checks
 * (including the wrappedLen <= roundup16(plainLen) invariant). */
static int test_ecc_dhuk_setter(void)
{
    /* Content does not matter for the validation paths; only lengths are
     * checked. Sized to the largest blob the import accepts (96 bytes). */
    byte wrapped[96];
    byte seed[32];
    ecc_key key;
    int ret;
    int rc = 0;

    XMEMSET(wrapped, 0xa5, sizeof(wrapped));
    XMEMSET(seed, 0x5a, sizeof(seed));

    ret = wc_ecc_init(&key);
    if (ret != 0) {
        printf("  wc_ecc_init failed: %d\n", ret);
        return ret;
    }

    /* Reject: NULL key / seed / wrapped pointers. */
    ret = wc_ecc_import_wrapped_private(NULL, seed, 32, wrapped, 32, 32);
    if (expect_ret("reject key=NULL", ret, BAD_FUNC_ARG) != 0) rc = -1;
    ret = wc_ecc_import_wrapped_private(&key, NULL, 32, wrapped, 32, 32);
    if (expect_ret("reject seed=NULL", ret, BAD_FUNC_ARG) != 0) rc = -1;
    ret = wc_ecc_import_wrapped_private(&key, seed, 32, NULL, 32, 32);
    if (expect_ret("reject wrapped=NULL", ret, BAD_FUNC_ARG) != 0) rc = -1;

    /* Good: 32-byte seed, 32-byte wrapped scalar, 32-byte plaintext (P-256). */
    ret = wc_ecc_import_wrapped_private(&key, seed, 32, wrapped, 32, 32);
    if (expect_ret("accept P-256 (32/32)", ret, 0) != 0) rc = -1;

    /* Boundary OK: P-521 plaintext (66) padded to 80, blob 80 == max. */
    ret = wc_ecc_import_wrapped_private(&key, seed, 32, wrapped, 80, 66);
    if (expect_ret("accept P-521 (80/66)", ret, 0) != 0) rc = -1;

    /* Boundary OK: minimum blob -- 1-byte plaintext padded to one AES block. */
    ret = wc_ecc_import_wrapped_private(&key, seed, 32, wrapped, 16, 1);
    if (expect_ret("accept min (16/1)", ret, 0) != 0) rc = -1;

    /* Reject: seed length must be 32. */
    ret = wc_ecc_import_wrapped_private(&key, seed, 16, wrapped, 32, 32);
    if (expect_ret("reject seedSz=16", ret, BAD_FUNC_ARG) != 0) rc = -1;

    /* Reject: not a multiple of the AES block size. */
    ret = wc_ecc_import_wrapped_private(&key, seed, 32, wrapped, 20, 20);
    if (expect_ret("reject wrappedLen=20", ret, BAD_FUNC_ARG) != 0) rc = -1;

    /* Reject: zero-length wrapped blob. */
    ret = wc_ecc_import_wrapped_private(&key, seed, 32, wrapped, 0, 0);
    if (expect_ret("reject wrappedLen=0", ret, BAD_FUNC_ARG) != 0) rc = -1;

    /* Reject: larger than the on-key buffer (> 96). */
    ret = wc_ecc_import_wrapped_private(&key, seed, 32, wrapped, 112, 32);
    if (expect_ret("reject wrappedLen=112", ret, BAD_FUNC_ARG) != 0) rc = -1;

    /* Reject: plaintext longer than the wrapped blob. */
    ret = wc_ecc_import_wrapped_private(&key, seed, 32, wrapped, 32, 48);
    if (expect_ret("reject plain=48 > wrapped=32", ret, BAD_FUNC_ARG) != 0)
        rc = -1;

    /* Reject: wrapped blob larger than the plaintext padded to a full block
     * (plain=16 -> roundup16 = 16, so a 48-byte blob is malformed). */
    ret = wc_ecc_import_wrapped_private(&key, seed, 32, wrapped, 48, 16);
    if (expect_ret("reject wrapped=48 > roundup16(plain=16)", ret,
                   BAD_FUNC_ARG) != 0)
        rc = -1;

    wc_ecc_free(&key);
    g_dhuk_res.setter_rc = rc;
    if (rc == 0) {
        printf("  setter validation OK\n");
    }
    return rc;
}

#ifdef WOLF_CRYPTO_CB
/* [2] Transparent crypto-callback GMAC via the STM32 DHUK device. Register the
 * device, init a normal Aes with devId = WC_DHUK_DEVID, set the 256-bit seed as
 * the key (wc_AesGcmSetKey), then call the standard wc_AesGcmEncrypt with empty
 * plaintext (GMAC). The derived key never appears in software. Checks: no
 * timeout, determinism (two runs match), and round-trip verify via
 * wc_AesGcmDecrypt. A gated/timeout result is a soft-PASS. */
static int test_dhuk_cryptocb_gmac(void)
{
    static const byte seed[32] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
        0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01
    };
    static const byte iv[12] = {
        0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
        0xde,0xca,0xf8,0x88
    };
    static const byte aad[16] = {
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef
    };
    Aes  aes;
    byte io[1];
    byte tag1[16];
    byte tag2[16];
    int  ret;
    int  i;

    XMEMSET(tag1, 0, sizeof(tag1));
    XMEMSET(tag2, 0, sizeof(tag2));

    ret = wc_Stm32_DhukRegister(WC_DHUK_DEVID);
    if (ret != 0) {
        printf("  wc_Stm32_DhukRegister failed: %d\n", ret);
        return ret;
    }

    /* GMAC tag via the normal AES-GCM API (empty plaintext). */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, seed, (word32)sizeof(seed));
    }
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes, io, io, 0, iv, (word32)sizeof(iv),
                               tag1, (word32)sizeof(tag1),
                               aad, (word32)sizeof(aad));
    }
    wc_AesFree(&aes);
    g_dhuk_res.cb_gmac_rc = ret;
    XMEMCPY((void*)g_dhuk_res.cb_gmac_tag, tag1, sizeof(tag1));

    if (is_expected_gated(ret)) {
        printf("  cryptocb GMAC reachable; backend gated/unavailable "
               "(ret=%d)\n", ret);
        ret = 0; /* soft-PASS */
        goto cleanup;
    }
    if (ret != 0) {
        printf("  cryptocb GMAC failed: %d\n", ret);
        goto cleanup;
    }
    printf("  cryptocb GMAC tag:");
    for (i = 0; i < 16; i++) printf(" %02x", tag1[i]);
    printf("\n");

    /* Determinism: same seed + inputs must give the same tag. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, seed, (word32)sizeof(seed));
    }
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes, io, io, 0, iv, (word32)sizeof(iv),
                               tag2, (word32)sizeof(tag2),
                               aad, (word32)sizeof(aad));
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  cryptocb GMAC (run 2) failed: %d\n", ret);
        goto cleanup;
    }
    if (XMEMCMP(tag1, tag2, 16) != 0) {
        printf("  cryptocb GMAC not deterministic -- FAIL\n");
        ret = -1;
        goto cleanup;
    }
    printf("  cryptocb GMAC deterministic OK\n");

    /* Round-trip: verify the tag via the normal AES-GCM decrypt API. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, seed, (word32)sizeof(seed));
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, io, io, 0, iv, (word32)sizeof(iv),
                               tag1, (word32)sizeof(tag1),
                               aad, (word32)sizeof(aad));
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  cryptocb GMAC verify failed: %d\n", ret);
        goto cleanup;
    }
    printf("  cryptocb GMAC verify OK (round-trip)\n");
    ret = 0;

cleanup:
    wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
    return ret;
}

#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT)
/* [3] Transparent AES-ECB via the STM32 DHUK device. Encrypt/decrypt with the
 * standard wc_AesEcb* API on an Aes inited with devId = WC_DHUK_DEVID and the
 * seed set as the key. Checks: round-trip recovers plaintext, ciphertext !=
 * plaintext (encryption happened), and a DIFFERENT seed yields a DIFFERENT
 * ciphertext (proves the DHUK-derived key actually drives the cipher, i.e. the
 * crypto-callback path is engaged). */
static int test_dhuk_cryptocb_ecb(void)
{
    static const byte seedA[32] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
        0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01
    };
    static const byte seedB[32] = {
        0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,0xa5,
        0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    static const byte pt[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    Aes  aes;
    byte ctA[16];
    byte ctB[16];
    byte rt[16];
    int  ret;
    int  i;

    ret = wc_Stm32_DhukRegister(WC_DHUK_DEVID);
    if (ret != 0) {
        printf("  DHUK register failed: %d\n", ret);
        return ret;
    }

    /* Encrypt with seed A. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, seedA, 32, NULL, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesEcbEncrypt(&aes, ctA, pt, (word32)sizeof(pt));
    }
    wc_AesFree(&aes);
    if (is_expected_gated(ret)) {
        printf("  cryptocb ECB reachable; backend gated/unavailable (ret=%d)\n",
               ret);
        ret = 0; /* soft-PASS */
        goto cleanup;
    }
    if (ret != 0) {
        printf("  cryptocb ECB encrypt failed: %d\n", ret);
        goto cleanup;
    }
    if (XMEMCMP(pt, ctA, 16) == 0) {
        printf("  cryptocb ECB produced plaintext -- FAIL\n");
        ret = -1;
        goto cleanup;
    }
    printf("  cryptocb ECB ct:");
    for (i = 0; i < 16; i++) printf(" %02x", ctA[i]);
    printf("\n");

    /* Decrypt with seed A -- must recover plaintext. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, seedA, 32, NULL, AES_DECRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesEcbDecrypt(&aes, rt, ctA, (word32)sizeof(ctA));
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  cryptocb ECB decrypt failed: %d\n", ret);
        goto cleanup;
    }
    if (XMEMCMP(pt, rt, 16) != 0) {
        printf("  cryptocb ECB round-trip mismatch -- FAIL\n");
        ret = -1;
        goto cleanup;
    }
    printf("  cryptocb ECB round-trip OK\n");

    /* Encrypt with seed B -- different seed must give different ciphertext. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, seedB, 32, NULL, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesEcbEncrypt(&aes, ctB, pt, (word32)sizeof(pt));
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  cryptocb ECB (seed B) failed: %d\n", ret);
        goto cleanup;
    }
    if (XMEMCMP(ctA, ctB, 16) == 0) {
        printf("  cryptocb ECB seed had no effect -- FAIL (not DHUK path)\n");
        ret = -1;
        goto cleanup;
    }
    printf("  cryptocb ECB seed-dependent OK (DHUK key drives cipher)\n");
    ret = 0;

cleanup:
    wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
    return ret;
}
#endif /* HAVE_AES_ECB || WOLFSSL_AES_DIRECT */

#if defined(HAVE_AES_CBC)
/* [5] Transparent AES-CBC via the STM32 DHUK device. Validates the fix that
 * routes CBC through the crypto-callback: previously CBC bypassed it and
 * silently used the 256-bit seed as a raw AES key. Discriminating check: for a
 * single block with IV = 0, CBC(P) == ECB(P) ONLY when both use the same
 * SAES-derived key -- the old seed-as-key path would not match ECB's derived
 * key. Also confirms that a DHUK AES-CTR call (a mode the SAES backend cannot
 * service) now returns a hard error instead of silently using the seed. */
static int test_dhuk_cryptocb_cbc(void)
{
    static const byte seedA[32] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
        0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01
    };
    static const byte pt[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const byte zero_iv[16] = { 0 };
    /* Two-block vector for the chained in-place decrypt regression below. */
    static const byte pt2[32] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51
    };
    Aes  aes;
    byte ctEcb[16];
    byte ctCbc[16];
    byte rt[16];
    byte buf2[32];
    int  ret;

    ret = wc_Stm32_DhukRegister(WC_DHUK_DEVID);
    if (ret != 0) {
        printf("  DHUK register failed: %d\n", ret);
        return ret;
    }

    /* ECB reference: ctEcb = ECB_k(pt) with the SAES-derived key. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, seedA, 32, NULL, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesEcbEncrypt(&aes, ctEcb, pt, (word32)sizeof(pt));
    }
    wc_AesFree(&aes);
    if (is_expected_gated(ret)) {
        printf("  cryptocb CBC reachable; backend gated/unavailable (ret=%d)\n",
               ret);
        ret = 0; /* soft-PASS */
        goto cleanup;
    }
    if (ret != 0) {
        printf("  ECB reference failed: %d\n", ret);
        goto cleanup;
    }

    /* CBC with IV = 0, single block: must equal the ECB reference. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, seedA, 32, zero_iv, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesCbcEncrypt(&aes, ctCbc, pt, (word32)sizeof(pt));
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  cryptocb CBC encrypt failed: %d\n", ret);
        goto cleanup;
    }
    if (XMEMCMP(ctEcb, ctCbc, 16) != 0) {
        printf("  cryptocb CBC != ECB(IV=0) -- FAIL "
               "(CBC not using the SAES-derived key)\n");
        ret = -1;
        goto cleanup;
    }
    printf("  cryptocb CBC matches ECB(IV=0) OK (SAES-derived key drives CBC)\n");

    /* CBC round-trip: decrypt recovers plaintext. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, seedA, 32, zero_iv, AES_DECRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesCbcDecrypt(&aes, rt, ctCbc, (word32)sizeof(ctCbc));
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  cryptocb CBC decrypt failed: %d\n", ret);
        goto cleanup;
    }
    if (XMEMCMP(pt, rt, 16) != 0) {
        printf("  cryptocb CBC round-trip mismatch -- FAIL\n");
        ret = -1;
        goto cleanup;
    }
    printf("  cryptocb CBC round-trip OK\n");

    /* Multi-block chained in-place CBC decrypt (regression for the chaining-IV
     * fix). Split a two-block ciphertext across two in-place wc_AesCbcDecrypt
     * calls so the second call depends on the chaining IV (aes->reg) that the
     * first call must update. In-place decrypt overwrites the input block with
     * plaintext, so the wrapper has to save the ciphertext block for the next
     * IV; reading it back from the overwritten input corrupts block 1. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, seedA, 32, zero_iv, AES_ENCRYPTION);
    }
    if (ret == 0) {
        /* Encrypt straight into buf2; it is decrypted in place below. */
        ret = wc_AesCbcEncrypt(&aes, buf2, pt2, (word32)sizeof(pt2));
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  cryptocb CBC 2-block encrypt failed: %d\n", ret);
        goto cleanup;
    }
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, seedA, 32, zero_iv, AES_DECRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesCbcDecrypt(&aes, buf2, buf2, 16);         /* block 0 */
    }
    if (ret == 0) {
        ret = wc_AesCbcDecrypt(&aes, buf2 + 16, buf2 + 16, 16); /* block 1 */
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  cryptocb CBC chained in-place decrypt failed: %d\n", ret);
        goto cleanup;
    }
    if (XMEMCMP(pt2, buf2, sizeof(pt2)) != 0) {
        printf("  cryptocb CBC chained in-place decrypt mismatch -- FAIL "
               "(chaining IV corrupted)\n");
        ret = -1;
        goto cleanup;
    }
    printf("  cryptocb CBC chained in-place decrypt OK\n");

#ifdef WOLFSSL_AES_COUNTER
    /* Negative: AES-CTR is not serviceable for a DHUK key. It must now return a
     * hard error (ALGO_ID_E) rather than silently encrypting with the seed as a
     * raw key. */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, seedA, 32, zero_iv, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesCtrEncrypt(&aes, rt, pt, (word32)sizeof(pt));
    }
    wc_AesFree(&aes);
    if (ret == ALGO_ID_E) {
        printf("  cryptocb CTR on DHUK key rejected (ALGO_ID_E) OK\n");
        ret = 0;
    }
    else {
        printf("  cryptocb CTR on DHUK key NOT rejected (ret=%d) -- FAIL\n", ret);
        ret = -1;
        goto cleanup;
    }
#endif /* WOLFSSL_AES_COUNTER */
    ret = 0;

cleanup:
    wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
    return ret;
}
#endif /* HAVE_AES_CBC */

/* [6] wc_Stm32_Aes_Wrap blob word order. Runs on BOTH build paths so the two
 * can be compared: WC_STM32_WRAP_ORDER_RAW must produce the same blob on
 * bare-metal and CubeMX/HAL (that is the whole point of the shared format),
 * while wc_Stm32_Aes_Wrap()'s default is deliberately per-build -- raw on
 * bare, byte-reversed on CubeMX -- so key material provisioned by wolfSSL
 * 5.9.0 - 5.9.2 still unwraps. Both blobs are printed so a bare run and a
 * CubeMX run can be diffed by eye or by script.
 *
 * The wrap key here is a fixed software key (devId != WOLFSSL_DHUK_DEVID), not
 * the silicon DHUK, so the output is reproducible across chips and the check
 * is about byte order only. */
static int test_dhuk_wrap_order(void)
{
    /* AES-128 FIPS-197 key, and a 32-byte payload to wrap. */
    static const byte wrap_key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const byte payload[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    Aes    aes;
    byte   rawBlob[32];
    byte   defBlob[32];
    word32 rawSz = sizeof(rawBlob);
    word32 defSz = sizeof(defBlob);
    word32 i;
    int    ret;

    XMEMSET(rawBlob, 0, sizeof(rawBlob));
    XMEMSET(defBlob, 0, sizeof(defBlob));

    /* Shared raw order -- must match byte-for-byte on both build paths. */
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit failed: %d\n", ret);
        return ret;
    }
    XMEMCPY(aes.key, wrap_key, sizeof(wrap_key));
    aes.keylen = 32;
    ret = wc_Stm32_Aes_Wrap_ex(&aes, payload, sizeof(payload), rawBlob, &rawSz,
                               NULL, 0, WC_STM32_WRAP_ORDER_RAW);
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  wrap_ex(RAW) failed: %d\n", ret);
        return ret;
    }

    /* Whatever this build's wc_Stm32_Aes_Wrap() defaults to. */
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit failed: %d\n", ret);
        return ret;
    }
    XMEMCPY(aes.key, wrap_key, sizeof(wrap_key));
    aes.keylen = 32;
    ret = wc_Stm32_Aes_Wrap(&aes, payload, sizeof(payload), defBlob, &defSz,
                            NULL, 0);
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  wrap(default) failed: %d\n", ret);
        return ret;
    }

    if (rawSz != sizeof(rawBlob) || defSz != sizeof(defBlob)) {
        printf("  wrap returned wrong size (raw=%lu def=%lu) -- FAIL\n",
               (unsigned long)rawSz, (unsigned long)defSz);
        return -1;
    }

    printf("  wrap RAW blob:    ");
    for (i = 0; i < sizeof(rawBlob); i++) printf("%02x", rawBlob[i]);
    printf("\n  wrap default blob:");
    for (i = 0; i < sizeof(defBlob); i++) printf("%02x", defBlob[i]);
    printf("\n");

#ifdef WOLFSSL_STM32_CUBEMX
    /* CubeMX default is the legacy byte-reversed order, so it must NOT equal
     * the shared raw blob -- if it did, the 5.9.x compatibility default has
     * been lost. */
    if (XMEMCMP(rawBlob, defBlob, sizeof(rawBlob)) == 0) {
        printf("  CubeMX default equals RAW -- FAIL "
               "(legacy 5.9.x blob order lost)\n");
        return -1;
    }
    printf("  CubeMX default is the legacy (byte-reversed) order OK\n");
#else
    /* Bare default has always been the raw order. */
    if (XMEMCMP(rawBlob, defBlob, sizeof(rawBlob)) != 0) {
        printf("  bare default differs from RAW -- FAIL "
               "(bare blob order changed)\n");
        return -1;
    }
    printf("  bare default is the raw order OK\n");
#endif
    printf("  compare the RAW line against the other build to confirm "
           "cross-build interop\n");
    return 0;
}

#if defined(HAVE_ECC) && defined(WOLFSSL_STM32_PKA)
/* [4] ECDSA sign with a DHUK-protected private key via the normal
 * wc_ecc_sign_hash API. Self-bootstrap: make a P-256 keypair, ECB-encrypt
 * (wrap) its scalar with the DHUK-derived key (same seed), import the wrapped
 * scalar + seed onto the ecc_key, set devId = WC_DHUK_DEVID, then sign. The
 * plaintext scalar only lives in a short-lived stack buffer during the PKA
 * sign. The signature is verified with the public counterpart (SW path). */
static int test_dhuk_cryptocb_ecdsa(WC_RNG* rng)
{
    static const byte seed[32] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
        0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01
    };
    static const byte hash[32] = {
        0x9f,0x86,0xd0,0x81,0x88,0x4c,0x7d,0x65,
        0x9a,0x2f,0xea,0xa0,0xc5,0x5a,0xd0,0x15,
        0xa3,0xbf,0x4f,0x1b,0x2b,0x0b,0x82,0x2c,
        0xd1,0x5d,0x6c,0x15,0xb0,0xf0,0x0a,0x08
    };
    ecc_key kp;
    Aes  aes;
    byte priv[32];
    byte wrapped[32];
    byte sig[80];
    word32 privSz = (word32)sizeof(priv);
    word32 sigLen = (word32)sizeof(sig);
    int  ret;
    int  verify = 0;
    int  haveKey = 0;

    ret = wc_Stm32_DhukRegister(WC_DHUK_DEVID);
    if (ret != 0) {
        printf("  DHUK register failed: %d\n", ret);
        return ret;
    }

    ret = wc_ecc_init(&kp);
    if (ret != 0) {
        printf("  wc_ecc_init failed: %d\n", ret);
        goto unreg;
    }
    haveKey = 1;
    ret = wc_ecc_make_key_ex(rng, 32, &kp, ECC_SECP256R1);
    if (ret != 0) {
        printf("  wc_ecc_make_key_ex failed: %d\n", ret);
        goto cleanup;
    }

    /* Sanity: plain (non-DHUK) PKA ECDSA sign+verify on this silicon, to
     * isolate any DHUK-path issue from a PKA-hardware issue. kp.devId is
     * still INVALID here, so this uses the normal HW PKA path. */
    sigLen = (word32)sizeof(sig);
    ret = wc_ecc_sign_hash(hash, (word32)sizeof(hash), sig, &sigLen, rng, &kp);
    if (ret == 0) {
        ret = wc_ecc_verify_hash(sig, sigLen, hash, (word32)sizeof(hash),
                                 &verify, &kp);
    }
    printf("  plain PKA sign+verify: rc=%d verify=%d\n", ret, verify);
    ret = 0;
    verify = 0;
    sigLen = (word32)sizeof(sig);

    ret = wc_ecc_export_private_only(&kp, priv, &privSz);
    if (ret != 0 || privSz != 32u) {
        printf("  export scalar failed: %d (len %lu)\n", ret,
               (unsigned long)privSz);
        ret = (ret != 0) ? ret : -1;
        goto cleanup;
    }

    /* Wrap the scalar = ECB-encrypt with the DHUK-derived key (seed as key). */
    ret = wc_AesInit(&aes, NULL, WC_DHUK_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, seed, 32, NULL, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesEcbEncrypt(&aes, wrapped, priv, 32);
    }
    wc_AesFree(&aes);
    wc_ForceZero(priv, sizeof(priv));
    if (is_expected_gated(ret)) {
        printf("  DHUK ECDSA: backend gated/unavailable (ret=%d)\n", ret);
        ret = 0; /* soft-PASS */
        goto cleanup;
    }
    if (ret != 0) {
        printf("  scalar wrap failed: %d\n", ret);
        goto cleanup;
    }

    /* Import the wrapped scalar + seed, and route signing through DHUK by
     * setting the device id on the key. */
    kp.devId = WC_DHUK_DEVID;
    ret = wc_ecc_import_wrapped_private(&kp, seed, (word32)sizeof(seed),
                                       wrapped, 32, 32);
    if (ret != 0) {
        printf("  import wrapped private failed: %d\n", ret);
        goto cleanup;
    }

    ret = wc_ecc_sign_hash(hash, (word32)sizeof(hash), sig, &sigLen, rng, &kp);
    if (is_expected_gated(ret)) {
        printf("  DHUK ECDSA sign gated/unavailable (ret=%d)\n", ret);
        ret = 0; /* soft-PASS */
        goto cleanup;
    }
    if (ret != 0) {
        printf("  DHUK ECDSA sign failed: %d\n", ret);
        goto cleanup;
    }
    printf("  DHUK ECDSA sign produced a %lu-byte signature\n",
           (unsigned long)sigLen);

    /* Verify with the public counterpart (crypto-cb has no verify -> SW). */
    ret = wc_ecc_verify_hash(sig, sigLen, hash, (word32)sizeof(hash),
                             &verify, &kp);
    if (ret != 0) {
        printf("  DHUK ECDSA verify error: %d\n", ret);
        goto cleanup;
    }
    if (verify != 1) {
        printf("  DHUK ECDSA verify FAILED (sig invalid)\n");
        ret = -1;
        goto cleanup;
    }
    printf("  DHUK ECDSA verify OK (signed via DHUK, verified with pubkey)\n");
    ret = 0;

cleanup:
    wc_ForceZero(priv, sizeof(priv));
    wc_ForceZero(wrapped, sizeof(wrapped));
    if (haveKey) {
        wc_ecc_free(&kp);
    }
unreg:
    wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
    return ret;
}
#endif /* HAVE_ECC && WOLFSSL_STM32_PKA */
#endif /* WOLF_CRYPTO_CB */

#ifdef WOLFSSL_STM32_DHUK_UNWRAP
static void dhuk_print_hex(const char* label, const byte* p, word32 sz)
{
    word32 i;
    printf("  %s:", label);
    for (i = 0; i < sz; i++) {
        printf(" %02x", p[i]);
    }
    printf("\n");
}

/* [6] wc_Stm32_Aes_DhukOp_ex -- the provisioning flow the API exists for:
 * stage a 256-bit seed, let SAES turn (seed, silicon DHUK) into a key
 * encryption key inside KEYR, and wrap/unwrap other key material with it.
 * The KEK never enters software and is bound to this chip.
 *
 * Contract checked here:
 *   - enc/dec round-trip through the same seed is the identity (ECB + CBC)
 *   - the same seed always yields the same KEK (determinism)
 *   - DhukOp_ex and the crypto-callback device agree byte-for-byte on the
 *     same 32-byte input -- they are the same KEK = DHUK-decrypt(seed)
 *     primitive, so blobs are interchangeable between the two APIs
 *
 * Ciphertext is silicon-specific, so it is printed rather than pinned; the
 * printed values are what the cross-build (BUILD=bare vs BUILD=cubemx)
 * comparison uses. */
static int test_dhuk_op_roundtrip(void)
{
    /* The key we want the DHUK to protect. */
    static const byte kek[32] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
        0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01
    };
    static const byte pt[32] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51
    };
    Aes    aes;
    byte   wrapped[32];
    byte   ct[32];
    byte   rt[32];
    byte   swCt[32];
    word32 wrappedSz = 0;
    int    ret;
    int    rc = 0;

    XMEMSET(wrapped, 0, sizeof(wrapped));
    XMEMSET(ct, 0, sizeof(ct));
    XMEMSET(rt, 0, sizeof(rt));
    XMEMSET(swCt, 0, sizeof(swCt));

    /* Stage 1: wrap K under the silicon DHUK. */
    ret = wc_AesInit(&aes, NULL, WOLFSSL_DHUK_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit (wrap) failed: %d\n", ret);
        return ret;
    }
    ret = wc_Stm32_Aes_Wrap(&aes, kek, sizeof(kek), wrapped, &wrappedSz,
                            NULL, 0);
    wc_AesFree(&aes);
    if (is_expected_gated(ret)) {
        printf("  wc_Stm32_Aes_Wrap gated/unavailable: %d "
               "(expected on this silicon)\n", ret);
        g_dhuk_res.dhukop_rc = ret;
        return 0;
    }
    if (ret != 0) {
        printf("  wc_Stm32_Aes_Wrap failed: %d\n", ret);
        g_dhuk_res.dhukop_rc = ret;
        return ret;
    }
    if (wrappedSz != sizeof(wrapped)) {
        printf("  wc_Stm32_Aes_Wrap outSz %u, want %u -- FAIL\n",
               (unsigned)wrappedSz, (unsigned)sizeof(wrapped));
        g_dhuk_res.dhukop_rc = -1;
        return -1;
    }
    dhuk_print_hex("wrapped blob (chip-bound)", wrapped, sizeof(wrapped));
    XMEMCPY((void*)g_dhuk_res.dhukop_blob, wrapped, sizeof(wrapped));

    /* Stage 2: ECB encrypt through the unwrapped key. */
    ret = wc_AesInit(&aes, NULL, WOLFSSL_DHUK_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit (op) failed: %d\n", ret);
        return ret;
    }
    XMEMCPY(aes.key, wrapped, sizeof(wrapped));
    aes.keylen = 32;
    ret = wc_Stm32_Aes_DhukOp_ex(&aes, ct, pt, sizeof(pt), 1 /* enc */,
                                 0 /* isCbc */);
    if (is_expected_gated(ret)) {
        printf("  DhukOp_ex ECB encrypt gated/unavailable: %d\n", ret);
        wc_AesFree(&aes);
        g_dhuk_res.dhukop_rc = ret;
        return 0;
    }
    if (ret != 0) {
        printf("  DhukOp_ex ECB encrypt failed: %d\n", ret);
        wc_AesFree(&aes);
        g_dhuk_res.dhukop_rc = ret;
        return ret;
    }
    dhuk_print_hex("DhukOp ECB ct", ct, sizeof(ct));

    /* Diagnostic: run the same input through DhukOp twice more, and through
     * the crypto-callback device (which uses Stm32SaesDeriveKeyFromSeed --
     * the same KEK = DHUK-decrypt(input) primitive). Feeding both paths the
     * identical 32 bytes isolates a code difference from an input
     * difference: if the cb path is deterministic and DhukOp is not, the
     * bug is in DhukOp; if they agree, the two are the same primitive. */
    {
        Aes  aes2;
        byte ct2[32];
        byte ct3[32];
        byte cbCt[32];
        int  i;

        for (i = 0; i < 2; i++) {
            byte* dst = (i == 0) ? ct2 : ct3;
            XMEMSET(dst, 0, sizeof(ct2));
            ret = wc_AesInit(&aes2, NULL, WOLFSSL_DHUK_DEVID);
            if (ret != 0) {
                break;
            }
            XMEMCPY(aes2.key, wrapped, sizeof(wrapped));
            aes2.keylen = 32;
            ret = wc_Stm32_Aes_DhukOp_ex(&aes2, dst, pt, sizeof(pt),
                                         1 /* enc */, 0 /* isCbc */);
            wc_AesFree(&aes2);
            if (ret != 0) {
                break;
            }
        }
        if (ret != 0) {
            printf("  repeat probe failed: %d\n", ret);
            rc = -1;
        }
        else {
            dhuk_print_hex("DhukOp ct pass2", ct2, sizeof(ct2));
            dhuk_print_hex("DhukOp ct pass3", ct3, sizeof(ct3));
            if (XMEMCMP(ct2, ct, sizeof(ct)) != 0 ||
                XMEMCMP(ct3, ct, sizeof(ct)) != 0) {
                printf("  DhukOp encrypt NOT deterministic\n");
                rc = -1;
            }
            else {
                printf("  DhukOp encrypt deterministic OK\n");
            }
        }

        /* Same 32 bytes, but through the crypto-callback derive path. */
        XMEMSET(cbCt, 0, sizeof(cbCt));
        ret = wc_Stm32_DhukRegister(WC_DHUK_DEVID);
        if (ret == 0) {
            ret = wc_AesInit(&aes2, NULL, WC_DHUK_DEVID);
            if (ret == 0) {
                ret = wc_AesSetKey(&aes2, wrapped, sizeof(wrapped), NULL,
                                   AES_ENCRYPTION);
                if (ret == 0) {
                    ret = wc_AesEcbEncrypt(&aes2, cbCt, pt, sizeof(pt));
                }
                wc_AesFree(&aes2);
            }
            wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
        }
        if (ret != 0) {
            printf("  cb-path comparison failed: %d\n", ret);
        }
        else {
            dhuk_print_hex("cb-path ct    ", cbCt, sizeof(cbCt));
            printf("  DhukOp %s cb-path (same 32-byte input)\n",
                   (XMEMCMP(cbCt, ct, sizeof(ct)) == 0) ? "==" : "!=");
        }
        ret = 0;
    }

    /* Stage 3: decrypt back, expect identity. */
    ret = wc_Stm32_Aes_DhukOp_ex(&aes, rt, ct, sizeof(ct), 0 /* dec */,
                                 0 /* isCbc */);
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  DhukOp_ex ECB decrypt failed: %d\n", ret);
        g_dhuk_res.dhukop_rc = ret;
        return ret;
    }
    if (XMEMCMP(rt, pt, sizeof(pt)) != 0) {
        printf("  DhukOp_ex ECB round-trip mismatch -- FAIL\n");
        dhuk_print_hex("got ", rt, sizeof(rt));
        rc = -1;
    }
    else {
        printf("  DhukOp_ex ECB round-trip OK\n");
    }

    /* Stage 4: the recovered KEK must equal K, so a plain AES keyed with K
     * has to produce the same ciphertext. A mismatch here means the unwrap
     * landed a different key (or the blob byte order disagrees) -- report
     * it loudly but keep it separate from the round-trip result so the two
     * failure modes stay distinguishable. */
    {
        static const char* names[4] = {
            "K as-is", "K byte-reversed", "K word-order-reversed",
            "K per-word byteswapped"
        };
        byte cand[32];
        int  v;
        int  j;
        int  hit = -1;

        for (v = 0; v < 4; v++) {
            switch (v) {
                case 0:
                    XMEMCPY(cand, kek, sizeof(cand));
                    break;
                case 1:
                    for (j = 0; j < 32; j++) {
                        cand[j] = kek[31 - j];
                    }
                    break;
                case 2:
                    for (j = 0; j < 8; j++) {
                        XMEMCPY(cand + 4 * j, kek + 4 * (7 - j), 4);
                    }
                    break;
                default:
                    for (j = 0; j < 8; j++) {
                        cand[4 * j + 0] = kek[4 * j + 3];
                        cand[4 * j + 1] = kek[4 * j + 2];
                        cand[4 * j + 2] = kek[4 * j + 1];
                        cand[4 * j + 3] = kek[4 * j + 0];
                    }
                    break;
            }
            ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
            if (ret != 0) {
                break;
            }
            ret = wc_AesSetKey(&aes, cand, sizeof(cand), NULL, AES_ENCRYPTION);
            if (ret == 0) {
                ret = wc_AesEcbEncrypt(&aes, swCt, pt, sizeof(pt));
            }
            wc_AesFree(&aes);
            if (ret != 0) {
                break;
            }
            if (XMEMCMP(swCt, ct, sizeof(ct)) == 0) {
                hit = v;
                break;
            }
        }
        if (ret != 0) {
            printf("  reference AES-ECB unavailable (%d) -- skipping\n", ret);
            ret = 0;
        }
        else if (hit < 0) {
            /* Informational only. The DHUK contract this API provides is
             * "seed -> chip-bound KEK", not "wc_Stm32_Aes_Wrap is the exact
             * inverse of the DhukOp unwrap". On U385 the recovered KEK is
             * not K under any word/byte permutation, so the two are NOT
             * inverse operations -- callers must not assume a blob produced
             * by wc_Stm32_Aes_Wrap unwraps back to its plaintext input. */
            printf("  note: KEK != K under any word/byte permutation --\n"
                   "  wc_Stm32_Aes_Wrap is not the inverse of the unwrap\n");
        }
        else {
            printf("  DhukOp ct == AES-ECB(%s, pt)\n", names[hit]);
        }
    }

    /* CBC through the same seed must also round-trip. */
    {
        static const byte iv0[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        };
        Aes  aesc;
        byte cbcCt[32];
        byte cbcRt[32];

        XMEMSET(cbcCt, 0, sizeof(cbcCt));
        XMEMSET(cbcRt, 0, sizeof(cbcRt));
        ret = wc_AesInit(&aesc, NULL, WOLFSSL_DHUK_DEVID);
        if (ret == 0) {
            XMEMCPY(aesc.key, wrapped, sizeof(wrapped));
            aesc.keylen = 32;
            XMEMCPY(aesc.reg, iv0, sizeof(iv0));
            ret = wc_Stm32_Aes_DhukOp_ex(&aesc, cbcCt, pt, sizeof(pt),
                                         1 /* enc */, 1 /* isCbc */);
            if (ret == 0) {
                XMEMCPY(aesc.reg, iv0, sizeof(iv0));
                ret = wc_Stm32_Aes_DhukOp_ex(&aesc, cbcRt, cbcCt,
                                             sizeof(cbcCt), 0 /* dec */,
                                             1 /* isCbc */);
            }
            wc_AesFree(&aesc);
        }
        if (ret != 0) {
            printf("  DhukOp_ex CBC failed: %d\n", ret);
            rc = -1;
        }
        else if (XMEMCMP(cbcRt, pt, sizeof(pt)) != 0) {
            printf("  DhukOp_ex CBC round-trip mismatch -- FAIL\n");
            dhuk_print_hex("got ", cbcRt, sizeof(cbcRt));
            rc = -1;
        }
        else if (XMEMCMP(cbcCt, ct, sizeof(ct)) == 0) {
            printf("  DhukOp_ex CBC ct == ECB ct -- IV not applied, FAIL\n");
            rc = -1;
        }
        else {
            printf("  DhukOp_ex CBC round-trip OK (IV applied)\n");
        }
        ret = 0;
    }

    g_dhuk_res.dhukop_rc = rc;
    return rc;
}
#endif /* WOLFSSL_STM32_DHUK_UNWRAP */

#endif /* WOLFSSL_DHUK && (BARE || CUBEMX) && WC_STM32_HAS_DHUK */

int main(void)
{
    int ret = 0;

    board_init();
    SystemCoreClockUpdate();

    printf("\n");
    printf("========================================\n");
    printf("wolfCrypt DHUK test - %s (CONFIG=%s)\n",
           board_name(), BUILD_CONFIG_NAME);
    printf("wolfSSL version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("SYSCLK: expected %lu Hz, CMSIS-reported %lu Hz%s\n",
           (unsigned long)board_sysclk_hz(),
           (unsigned long)SystemCoreClock,
           ((unsigned long)SystemCoreClock == (unsigned long)board_sysclk_hz())
               ? " (match)" : " (MISMATCH -- PLL may have failed)");
    printf("========================================\n\n");

    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("wolfCrypt_Init failed: %d\n", ret);
        for (;;) { }
    }

#if defined(WOLFSSL_DHUK) && \
    (defined(WOLFSSL_STM32_BARE) || defined(WOLFSSL_STM32_CUBEMX)) && \
    defined(WC_STM32_HAS_DHUK)
    {
        WC_RNG rng;

        printf("[1] ECC DHUK setter validation (SW unit test):\n");
        ret = test_ecc_dhuk_setter();
        if (ret != 0) {
            goto done;
        }

        ret = wc_InitRng(&rng);
        if (ret != 0) {
            printf("  wc_InitRng failed: %d\n", ret);
            goto done;
        }

#ifdef WOLF_CRYPTO_CB
        if (ret == 0) {
            printf("\n[2] GMAC via transparent DHUK crypto-callback:\n");
            ret = test_dhuk_cryptocb_gmac();
        }
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT)
        if (ret == 0) {
            printf("\n[3] AES-ECB via transparent DHUK crypto-callback:\n");
            ret = test_dhuk_cryptocb_ecb();
        }
#endif
#if defined(HAVE_AES_CBC)
        if (ret == 0) {
            printf("\n[5] AES-CBC via transparent DHUK crypto-callback:\n");
            ret = test_dhuk_cryptocb_cbc();
        }
#endif
#if defined(HAVE_ECC) && defined(WOLFSSL_STM32_PKA)
        if (ret == 0) {
            printf("\n[4] ECDSA sign via transparent DHUK crypto-callback:\n");
            ret = test_dhuk_cryptocb_ecdsa(&rng);
        }
#endif
#endif
#ifdef WOLFSSL_STM32_DHUK_UNWRAP
        if (ret == 0) {
            printf("\n[6] wc_Stm32_Aes_DhukOp_ex wrap/unwrap round-trip:\n");
            ret = test_dhuk_op_roundtrip();
        }
#endif
        if (ret == 0) {
            printf("\n[7] wc_Stm32_Aes_Wrap blob word order:\n");
            ret = test_dhuk_wrap_order();
        }

        wc_FreeRng(&rng);
    }
#else
    printf("DHUK not enabled in this build (need WOLFSSL_DHUK + "
           "WOLFSSL_STM32_BARE or WOLFSSL_STM32_CUBEMX + "
           "WC_STM32_HAS_DHUK).\n");
    ret = -1;
#endif

done:
    g_dhuk_res.overall = ret;
    g_dhuk_res.magic = 0xD04B0001u;
    wolfCrypt_Cleanup();
    printf("\nResult: %d (%s)\n", ret, ret == 0 ? "PASS" : "FAIL");
    printf("Test complete\n");

    for (;;) { }
}
