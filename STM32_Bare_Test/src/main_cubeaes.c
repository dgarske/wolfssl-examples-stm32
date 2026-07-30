/* main_cubeaes.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * WOLF_CRYPTO_CB_ONLY_AES on the STM32 CubeMX/HAL build. Registers the CubeMX
 * AES crypto-callback device (wc_Stm32_AesRegister) and runs AES-GCM
 * known-answer tests with a plaintext key. Under WOLF_CRYPTO_CB_ONLY_AES the
 * software AES core is stripped and every AES block routes through the crypto
 * callback; the device's AES-ECB handler lets wc_AesGcmSetKey derive the GHASH
 * subkey H on the HAL, after which wc_AesGcmEncrypt runs on the native HAL GCM
 * engine. KAT vectors are McGrew & Viega "The Galois/Counter Mode of Operation
 * (GCM)" test cases 3 (64-byte payload, no AAD) and 4 (20-byte AAD, 60-byte
 * payload with a partial trailing block).
 *
 *   make BOARD=u3 BUILD=cubemx TARGET=cubeaes CONFIG=bare flash
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
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/port/st/stm32.h"

/* McGrew & Viega GCM test cases 3 and 4 (needs `byte` from types.h above). */
#include "gcm_vectors.h"

#ifndef BUILD_CONFIG_NAME
#define BUILD_CONFIG_NAME "unknown"
#endif

/* Debugger-readable result sink (magic once main() completes). */
volatile struct {
    uint32_t magic;
    int32_t  tc3_rc;
    int32_t  tc4_rc;
    int32_t  overall;
} g_cubeaes_res;

#if defined(WOLFSSL_STM32_CUBEMX) && defined(WOLF_CRYPTO_CB) && \
    defined(HAVE_AESGCM)

/* Registered crypto-callback device id for the AES HAL device. This is the
 * port's own default id (wolfssl/wolfcrypt/port/st/stm32.h), the same one
 * main_aesplain.c registers -- an application may pick any free devId, but
 * reusing the port's keeps the two examples consistent. */
#define CUBE_AES_DEVID WOLFSSL_STM32_AES_DEVID

static void print_hex(const char* label, const byte* p, int n)
{
    int i;
    printf("  %s:", label);
    for (i = 0; i < n; i++) {
        printf(" %02x", p[i]);
    }
    printf("\n");
}

/* One GCM KAT: encrypt -> match CT+tag, decrypt -> recover PT, tamper -> reject.
 * All AES work is serviced through the registered CubeMX AES cryptocb device. */
static int gcm_kat(const char* name,
    const byte* pt, word32 ptSz,
    const byte* aad, word32 aadSz,
    const byte* expCt, const byte* expTag, word32 tagSz)
{
    Aes    aes;
    byte   ct[64];
    byte   rt[64];
    byte   tag[16];
    int    ret;

    if (ptSz > sizeof(ct) || tagSz == 0 || tagSz > sizeof(tag)) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(ct,  0, sizeof(ct));
    XMEMSET(rt,  0, sizeof(rt));
    XMEMSET(tag, 0, sizeof(tag));

    printf("[%s] encrypt:\n", name);
    ret = wc_AesInit(&aes, NULL, CUBE_AES_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit failed: %d\n", ret);
        return ret;
    }
    ret = wc_AesGcmSetKey(&aes, gcm_tc_key, (word32)sizeof(gcm_tc_key));
    if (ret != 0) {
        printf("  wc_AesGcmSetKey failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }
    ret = wc_AesGcmEncrypt(&aes, ct, pt, ptSz,
                           gcm_tc_iv, (word32)sizeof(gcm_tc_iv),
                           tag, tagSz, aad, aadSz);
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  wc_AesGcmEncrypt failed: %d\n", ret);
        return ret;
    }
    print_hex("ct ", ct,  (int)ptSz);
    print_hex("tag", tag, (int)tagSz);
    if (XMEMCMP(ct, expCt, ptSz) != 0) {
        printf("  CT mismatch vs KAT -- FAIL\n");
        return -1;
    }
    if (XMEMCMP(tag, expTag, tagSz) != 0) {
        printf("  TAG mismatch vs KAT -- FAIL\n");
        return -1;
    }
    printf("  CT + tag match KAT OK\n");

    /* Decrypt + verify tag: must recover the plaintext. */
    ret = wc_AesInit(&aes, NULL, CUBE_AES_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, gcm_tc_key, (word32)sizeof(gcm_tc_key));
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, rt, ct, ptSz,
                               gcm_tc_iv, (word32)sizeof(gcm_tc_iv),
                               tag, tagSz, aad, aadSz);
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  wc_AesGcmDecrypt failed: %d\n", ret);
        return ret;
    }
    if (XMEMCMP(rt, pt, ptSz) != 0) {
        printf("  round-trip PT mismatch -- FAIL\n");
        return -1;
    }
    printf("  decrypt recovered PT OK\n");

    /* Negative: a tampered tag must be rejected with AES_GCM_AUTH_E. */
    tag[0] ^= 0xffu;
    ret = wc_AesInit(&aes, NULL, CUBE_AES_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, gcm_tc_key, (word32)sizeof(gcm_tc_key));
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, rt, ct, ptSz,
                               gcm_tc_iv, (word32)sizeof(gcm_tc_iv),
                               tag, tagSz, aad, aadSz);
    }
    wc_AesFree(&aes);
    if (ret != WC_NO_ERR_TRACE(AES_GCM_AUTH_E)) {
        printf("  tamper NOT rejected (ret=%d) -- FAIL\n", ret);
        return -1;
    }
    printf("  tamper rejected (AES_GCM_AUTH_E) OK\n");
    return 0;
}
#endif /* WOLFSSL_STM32_CUBEMX && WOLF_CRYPTO_CB && HAVE_AESGCM */

int main(void)
{
    int ret = 0;

    board_init();
    SystemCoreClockUpdate();

    printf("\n");
    printf("========================================\n");
    printf("wolfCrypt CubeMX AES cryptocb test - %s (CONFIG=%s)\n",
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

#if defined(WOLFSSL_STM32_CUBEMX) && defined(WOLF_CRYPTO_CB) && \
    defined(HAVE_AESGCM)
    {
        int rc;

        ret = wc_Stm32_AesRegister(CUBE_AES_DEVID);
        if (ret != 0) {
            printf("wc_Stm32_AesRegister failed: %d\n", ret);
        }
        else {
            printf("Registered CubeMX AES cryptocb device (devId=%d), "
                   "WOLF_CRYPTO_CB_ONLY_AES=%s\n\n", CUBE_AES_DEVID,
#ifdef WOLF_CRYPTO_CB_ONLY_AES
                   "yes"
#else
                   "no"
#endif
                   );

            rc = gcm_kat("TC3 whole-block/no-AAD", gcm_tc3_pt,
                         (word32)sizeof(gcm_tc3_pt), NULL, 0,
                         gcm_tc3_ct, gcm_tc3_tag, 16);
            g_cubeaes_res.tc3_rc = rc;
            if (rc != 0 && ret == 0) {
                ret = rc;
            }

            printf("\n");
            rc = gcm_kat("TC4 AAD+partial-tail", gcm_tc4_pt,
                         (word32)sizeof(gcm_tc4_pt), gcm_tc4_aad,
                         (word32)sizeof(gcm_tc4_aad),
                         gcm_tc4_ct, gcm_tc4_tag, 16);
            g_cubeaes_res.tc4_rc = rc;
            if (rc != 0 && ret == 0) {
                ret = rc;
            }

            wc_Stm32_AesUnRegister(CUBE_AES_DEVID);
        }
    }
#else
    printf("CubeMX AES cryptocb not enabled (need WOLFSSL_STM32_CUBEMX + "
           "WOLF_CRYPTO_CB + HAVE_AESGCM).\n");
    ret = -1;
#endif

    g_cubeaes_res.overall = ret;
    g_cubeaes_res.magic   = 0xCBAE0001u;
    wolfCrypt_Cleanup();
    printf("\nResult: %d (%s)\n", ret, ret == 0 ? "PASS" : "FAIL");
    printf("Test complete\n");

    for (;;) { }
}
