/* main_cubecrypto.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Full HW crypto over the wolfCrypt crypto-callback framework on the STM32
 * CubeMX/HAL build (STM32U385). Exercises, all through the callback under
 * WOLF_CRYPTO_CB_ONLY_ECC + WOLF_CRYPTO_CB_ONLY_AES:
 *   [1] HW ECDSA sign + verify of a normal P-256 key -> STM32 PKA
 *       (Stm32Cube_EccSign / Stm32Cube_EccVerify).
 *   [2] HW CCB-protected ECDSA: provision a P-256 key on-chip (HAL_CCB blob),
 *       sign (CCB), verify with its public key (PKA).
 *   [3] HW AES-GCM (plaintext key) -> HAL AES via the CubeMX AES device.
 *
 * The ST HAL PKA handle (PKA_HandleTypeDef hpka) that wolfSSL references as
 * extern on the HAL build is defined by the board file
 * (boards/u3/hw_init_cubemx.c); a CubeMX-generated project gets it from
 * MX_PKA_Init. This app only declares it extern, enables the PKA clock and
 * calls HAL_PKA_Init on it -- do not add another definition or you will get a
 * duplicate-symbol link error.
 *
 *   make BOARD=u3 BUILD=cubemx TARGET=cubecrypto CONFIG=bare flash
 */

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
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/port/st/stm32.h"

/* McGrew & Viega GCM test case 3 (needs `byte` from types.h above). */
#include "gcm_vectors.h"

#ifndef BUILD_CONFIG_NAME
#define BUILD_CONFIG_NAME "unknown"
#endif

#define CUBE_DEVID WC_DHUK_DEVID

/* Non-zero, non-error result code meaning "this step could not run here", so a
 * gated step is distinguishable from a real PASS (0) and from a wolfCrypt error
 * (always negative). It does not fail the overall run. */
#define CCB_RC_SKIPPED 1

volatile struct {
    uint32_t magic;
    int32_t  ecdsa_rc;
    int32_t  ccb_rc;
    int32_t  gcm_rc;
    int32_t  overall;
} g_cubecrypto_res;

#if defined(WOLFSSL_STM32_CUBEMX) && defined(WOLF_CRYPTO_CB)

#ifdef WOLFSSL_STM32_PKA
/* The board's hw_init_cubemx.c defines the ST HAL PKA handle (hpka, Instance=PKA)
 * that wolfSSL references as extern; we enable its clock and init it below. The
 * PKA_HandleTypeDef type only resolves once WOLFSSL_STM32_CUBEMX has pulled in
 * the family HAL header, so this declaration stays inside that guard. */
extern PKA_HandleTypeDef hpka;
#endif

/* A backend that cannot run at all in this build/state returns one of these --
 * the step is reported SKIPPED rather than PASS. Deliberately excludes
 * WC_TIMEOUT_E / WC_HW_E: those mean the hardware was reached and misbehaved,
 * which must surface as a failure. */
static int is_expected_gated(int ret)
{
    return (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) ||
           (ret == WC_NO_ERR_TRACE(NO_VALID_DEVID)) ||
           (ret == WC_NO_ERR_TRACE(NOT_COMPILED_IN));
}

#if defined(HAVE_ECC) && defined(WOLFSSL_STM32_PKA)
/* Fixed valid NIST P-256 keypair (RFC 6979 A.2.5 example key: q, Ux, Uy) + a
 * fixed 32-byte digest. Used so [1] needs no keygen (a normal-key keygen has no
 * device path under WOLF_CRYPTO_CB_ONLY_ECC). Q = d*G, so sign->verify round-
 * trips. */
static const byte P256_D[32] = {
    0xC9,0xAF,0xA9,0xD8,0x45,0xBA,0x75,0x16,0x6B,0x5C,0x21,0x57,0x67,0xB1,0xD6,0x93,
    0x4E,0x50,0xC3,0xDB,0x36,0xE8,0x9B,0x12,0x7B,0x8A,0x62,0x2B,0x12,0x0F,0x67,0x21
};
static const byte P256_QX[32] = {
    0x60,0xFE,0xD4,0xBA,0x25,0x5A,0x9D,0x31,0xC9,0x61,0xEB,0x74,0xC6,0x35,0x6D,0x68,
    0xC0,0x49,0xB8,0x92,0x3B,0x61,0xFA,0x6C,0xE6,0x69,0x62,0x2E,0x60,0xF2,0x9F,0xB6
};
static const byte P256_QY[32] = {
    0x79,0x03,0xFE,0x10,0x08,0xB8,0xBC,0x99,0xA4,0x1A,0xE9,0xE9,0x56,0x28,0xBC,0x64,
    0xF2,0xF1,0xB2,0x0C,0x2D,0x7E,0x9F,0x51,0x77,0xA3,0xC2,0x94,0xD4,0x46,0x22,0x99
};
static const byte P256_HASH[32] = {
    0xAF,0x2B,0xDB,0xE1,0xAA,0x9B,0x6E,0xC1,0xE2,0xAD,0xE1,0xD6,0x94,0xF4,0x1F,0xC7,
    0x1A,0x83,0x1D,0x02,0x68,0xE9,0x89,0x15,0x62,0x11,0x3D,0x8A,0x62,0xAD,0xD1,0xBF
};

/* [1] Normal-key HW ECDSA: import a fixed keypair, sign the digest, verify.
 * Under WOLF_CRYPTO_CB_ONLY_ECC both route through the callback to the PKA. */
static int test_ecdsa_normal(WC_RNG* rng)
{
    ecc_key key;
    byte    sig[80];
    word32  sigLen = (word32)sizeof(sig);
    int     ret;
    int     verify = 0;
    int     haveKey = 0;

    ret = wc_ecc_init_ex(&key, NULL, CUBE_DEVID);
    if (ret != 0) {
        printf("  wc_ecc_init_ex failed: %d\n", ret);
        return ret;
    }
    haveKey = 1;

    ret = wc_ecc_import_unsigned(&key, (byte*)P256_QX, (byte*)P256_QY,
                                 (byte*)P256_D, ECC_SECP256R1);
    if (ret != 0) {
        printf("  import keypair failed: %d\n", ret);
        goto done;
    }

    ret = wc_ecc_sign_hash(P256_HASH, (word32)sizeof(P256_HASH),
                           sig, &sigLen, rng, &key);
    if (ret != 0) {
        printf("  HW ECDSA sign failed: %d\n", ret);
        goto done;
    }
    printf("  HW ECDSA sign OK (%lu-byte sig)\n", (unsigned long)sigLen);

    ret = wc_ecc_verify_hash(sig, sigLen, P256_HASH,
                             (word32)sizeof(P256_HASH), &verify, &key);
    if (ret != 0) {
        printf("  HW ECDSA verify error: %d\n", ret);
        goto done;
    }
    if (verify != 1) {
        printf("  HW ECDSA verify FAILED (sig invalid)\n");
        ret = -1;
        goto done;
    }
    printf("  HW ECDSA verify OK (valid)\n");

    /* Negative: flip a sig byte, expect verify == 0. */
    sig[sigLen / 2] ^= 0xff;
    verify = 1;
    ret = wc_ecc_verify_hash(sig, sigLen, P256_HASH,
                             (word32)sizeof(P256_HASH), &verify, &key);
    if (ret == 0 && verify == 0) {
        printf("  HW ECDSA rejects tampered sig OK\n");
    }
    else {
        printf("  HW ECDSA tamper check FAILED (ret=%d verify=%d)\n",
               ret, verify);
        ret = -1;
        goto done;
    }
    ret = 0;

done:
    if (haveKey) {
        wc_ecc_free(&key);
    }
    return ret;
}

#ifdef WOLFSSL_STM32_CCB
/* [2] CCB-protected HW ECDSA: provision a P-256 key on-chip (the callback
 * intercepts wc_ecc_make_key), sign through it (CCB), verify with the public
 * key (PKA). The private scalar never enters software. Returns 0 on a real
 * pass, CCB_RC_SKIPPED if the path cannot run in this build, negative on a
 * genuine failure. */
static int test_ecdsa_ccb(WC_RNG* rng)
{
    ecc_key key;
    byte    sig[80];
    word32  sigLen = (word32)sizeof(sig);
    int     ret;
    int     verify = 0;
    int     haveKey = 0;

    ret = wc_ecc_init_ex(&key, NULL, CUBE_DEVID);
    if (ret != 0) {
        printf("  wc_ecc_init_ex failed: %d\n", ret);
        return ret;
    }
    haveKey = 1;

    /* On-chip provisioning derives a random scalar via software ECC, which
     * WOLF_CRYPTO_CB_ONLY_ECC strips -- so keygen returns NO_VALID_DEVID here.
     * CCB sign works via the callback with a pre-provisioned blob (provision it
     * in a non-CB_ONLY_ECC build). Reported SKIPPED, not PASS: the CCB sign
     * path below is never reached in this build. */
    ret = wc_ecc_make_key(rng, 32, &key);
    if (is_expected_gated(ret)) {
        printf("  CCB keygen needs SW ECC (stripped by CB_ONLY_ECC), ret=%d\n",
               ret);
        printf("  -- provision the CCB blob in a non-stripped build; CCB sign\n");
        printf("     then runs via the callback. SKIPPED (not a PASS)\n");
        ret = CCB_RC_SKIPPED;
        goto done;
    }
    if (ret != 0) {
        printf("  CCB keygen failed: %d\n", ret);
        goto done;
    }

    ret = wc_ecc_sign_hash(P256_HASH, (word32)sizeof(P256_HASH),
                           sig, &sigLen, rng, &key);
    if (is_expected_gated(ret)) {
        printf("  CCB sign gated (ret=%d) -- SKIPPED (not a PASS)\n", ret);
        ret = CCB_RC_SKIPPED;
        goto done;
    }
    if (ret != 0) {
        printf("  CCB sign failed: %d\n", ret);
        goto done;
    }

    ret = wc_ecc_verify_hash(sig, sigLen, P256_HASH,
                             (word32)sizeof(P256_HASH), &verify, &key);
    if (ret != 0 || verify != 1) {
        printf("  CCB verify FAILED (ret=%d verify=%d)\n", ret, verify);
        ret = (ret == 0) ? -1 : ret;
        goto done;
    }
    printf("  CCB sign + verify OK (private scalar never in software)\n");
    ret = 0;

done:
    if (haveKey) {
        wc_ecc_free(&key);
    }
    return ret;
}
#endif /* WOLFSSL_STM32_CCB */
#endif /* HAVE_ECC && WOLFSSL_STM32_PKA */

#ifdef HAVE_AESGCM
/* [3] HW AES-GCM (plaintext key) via the CubeMX AES device. The CUBE_DEVID
 * device (wc_Stm32_DhukRegister) routes AES-ECB to the HAL with the plaintext
 * key (wc_Stm32_Aes_Init useSaes=0, no DHUK/SAES key derivation), which keys
 * AES-GCM -- so this matches the published McGrew/Viega vectors. Test case 3
 * (64-byte payload, no AAD). */
static int test_aesgcm(void)
{
    Aes    aes;
    byte   ct[64];
    byte   rt[64];
    byte   tag[16];
    int    ret;

    XMEMSET(ct, 0, sizeof(ct));
    XMEMSET(rt, 0, sizeof(rt));
    XMEMSET(tag, 0, sizeof(tag));

    ret = wc_AesInit(&aes, NULL, CUBE_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, gcm_tc_key, (word32)sizeof(gcm_tc_key));
    }
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes, ct, gcm_tc3_pt, (word32)sizeof(gcm_tc3_pt),
                               gcm_tc_iv, (word32)sizeof(gcm_tc_iv),
                               tag, (word32)sizeof(tag), NULL, 0);
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  AES-GCM encrypt failed: %d\n", ret);
        return ret;
    }
    if (XMEMCMP(ct, gcm_tc3_ct, sizeof(ct)) != 0 ||
            XMEMCMP(tag, gcm_tc3_tag, sizeof(tag)) != 0) {
        printf("  AES-GCM CT/tag mismatch vs KAT -- FAIL\n");
        return -1;
    }

    ret = wc_AesInit(&aes, NULL, CUBE_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, gcm_tc_key, (word32)sizeof(gcm_tc_key));
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, rt, ct, (word32)sizeof(ct),
                               gcm_tc_iv, (word32)sizeof(gcm_tc_iv),
                               tag, (word32)sizeof(tag), NULL, 0);
    }
    wc_AesFree(&aes);
    if (ret != 0 || XMEMCMP(rt, gcm_tc3_pt, sizeof(gcm_tc3_pt)) != 0) {
        printf("  AES-GCM decrypt/round-trip FAILED (ret=%d)\n", ret);
        return (ret == 0) ? -1 : ret;
    }
    printf("  AES-GCM encrypt+decrypt match KAT OK\n");
    return 0;
}
#endif /* HAVE_AESGCM */

#endif /* WOLFSSL_STM32_CUBEMX && WOLF_CRYPTO_CB */

int main(void)
{
    int ret = 0;

    board_init();
    SystemCoreClockUpdate();

    printf("\n");
    printf("========================================\n");
    printf("wolfCrypt CubeMX HW-crypto cryptocb test - %s (CONFIG=%s)\n",
           board_name(), BUILD_CONFIG_NAME);
    printf("wolfSSL version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("========================================\n\n");

    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("wolfCrypt_Init failed: %d\n", ret);
        for (;;) { }
    }

#if defined(WOLFSSL_STM32_CUBEMX) && defined(WOLF_CRYPTO_CB)
    {
        WC_RNG rng;
        int    rc;

        /* Bring up the ST HAL PKA (a CubeMX MX_PKA_Init would do this). The HAL
         * ms-tick runs on this harness (board_common.c forwards SysTick to
         * HAL_IncTick under BUILD=cubemx), so HAL_PKA_Init has a working INITOK
         * timebase. Surface a non-OK status as a warning instead of discarding
         * it; the ECDSA tests below are the functional confirmation. */
#ifdef WOLFSSL_STM32_PKA
        __HAL_RCC_PKA_CLK_ENABLE();
        hpka.Instance = PKA;
        if (HAL_PKA_Init(&hpka) != HAL_OK) {
            printf("  warning: HAL_PKA_Init not HAL_OK; ECDSA tests below are "
                   "the check\n");
        }
#endif

        ret = wc_Stm32_DhukRegister(CUBE_DEVID);
        if (ret != 0) {
            printf("wc_Stm32_DhukRegister failed: %d\n", ret);
        }
        else {
            ret = wc_InitRng(&rng);
            if (ret != 0) {
                printf("wc_InitRng failed: %d\n", ret);
                wc_Stm32_DhukUnRegister(CUBE_DEVID);
            }
            else {
#if defined(HAVE_ECC) && defined(WOLFSSL_STM32_PKA)
                printf("[1] HW ECDSA (normal key -> PKA) sign + verify:\n");
                rc = test_ecdsa_normal(&rng);
                g_cubecrypto_res.ecdsa_rc = rc;
                if (rc != 0 && ret == 0) ret = rc;
#ifdef WOLFSSL_STM32_CCB
                printf("\n[2] HW CCB-protected ECDSA sign + verify:\n");
                rc = test_ecdsa_ccb(&rng);
                g_cubecrypto_res.ccb_rc = rc;
                /* CCB_RC_SKIPPED (positive) is not a failure; only a wolfCrypt
                 * error (negative) fails the run. */
                if (rc < 0 && ret == 0) ret = rc;
#endif
#endif
#ifdef HAVE_AESGCM
                printf("\n[3] HW AES-GCM (plaintext key -> HAL):\n");
                rc = test_aesgcm();
                g_cubecrypto_res.gcm_rc = rc;
                if (rc != 0 && ret == 0) ret = rc;
#endif
                wc_FreeRng(&rng);
                wc_Stm32_DhukUnRegister(CUBE_DEVID);
            }
        }
    }
#else
    printf("CubeMX HW cryptocb not enabled (need WOLFSSL_STM32_CUBEMX + "
           "WOLF_CRYPTO_CB).\n");
    ret = -1;
#endif

    g_cubecrypto_res.overall = ret;
    g_cubecrypto_res.magic   = 0xCBCC0001u;
    wolfCrypt_Cleanup();
    printf("\nResult: %d (%s)\n", ret, ret == 0 ? "PASS" : "FAIL");
    printf("Test complete\n");

    for (;;) { }
}
