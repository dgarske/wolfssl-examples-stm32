/* main_plaingcm.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Direct hardware AES-GCM check for the bare-metal STM32 AES engine with a
 * plaintext key -- validates encrypt AND decrypt-verify on the HW GCM path. It
 * calls wc_Stm32_Aes_Gcm() directly, so there is NO software fallback: if the
 * return is 0 and the output matches the published McGrew & Viega GCM
 * test-case-3 vector (whole-block, 12-byte IV), the hardware GCM engine
 * produced it.
 *
 * Boards whose silicon carries an AES IP with a HW GCM mode (the Makefile
 * enforces the same list): CRYP IP on f437 / f439 / h7; TinyAES (routed to SAES
 * on h7s3 / n657) on h7s3 / u3 / u585 / u545 / l4a6 / l562 / wba52 / n657.
 * Not c5a3 / c562: the STM32C5 CMSIS names the GCM phase field AES_CR_CPHASE
 * rather than AES_CR_GCMPH, and wolfSSL only abstracts that rename on the
 * DHUK/SAES path, so the plaintext-key wc_Stm32_Aes_Gcm() is the
 * CRYPTOCB_UNAVAILABLE stub there. Use TARGET=aesplain on C5 instead.
 *
 *   make BOARD=f439 CONFIG=bare TARGET=plaingcm flash
 *   make BOARD=u3   CONFIG=bare TARGET=plaingcm flash
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

/* McGrew & Viega GCM test case 3 (needs `byte` from types.h above). */
#include "gcm_vectors.h"

#ifndef BUILD_CONFIG_NAME
#define BUILD_CONFIG_NAME "unknown"
#endif

volatile struct {
    uint32_t magic;
    int32_t  overall;
} g_plaingcm_res;

#if defined(WOLFSSL_STM32_BARE) && defined(STM32_CRYPTO) && defined(HAVE_AESGCM)

static int hw_gcm_kat(void)
{
    Aes  aes;
    byte ct[64];
    byte rt[64];
    byte tag[16];
    int  ret;

    XMEMSET(ct, 0, sizeof(ct));
    XMEMSET(rt, 0, sizeof(rt));
    XMEMSET(tag, 0, sizeof(tag));

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
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

    /* Direct HW encrypt (no SW fallback). UNAVAILABLE would mean the HW path
     * declined -- treated here as a failure so we never silently pass on SW. */
    ret = wc_Stm32_Aes_Gcm(&aes, ct, gcm_tc3_pt, (word32)sizeof(gcm_tc3_pt),
                           gcm_tc_iv, (word32)sizeof(gcm_tc_iv),
                           tag, (word32)sizeof(tag),
                           NULL, 0, 1 /* enc */);
    if (ret != 0) {
        printf("  HW encrypt returned %d (0 expected; not on HW?) -- FAIL\n",
               ret);
        wc_AesFree(&aes);
        return ret ? ret : -1;
    }
    if (XMEMCMP(ct, gcm_tc3_ct, sizeof(gcm_tc3_ct)) != 0 ||
            XMEMCMP(tag, gcm_tc3_tag, sizeof(gcm_tc3_tag)) != 0) {
        printf("  HW CT/tag mismatch vs KAT -- FAIL\n");
        wc_AesFree(&aes);
        return -1;
    }
    printf("  HW encrypt: CT + tag match published vector OK\n");

    /* Direct HW decrypt-verify. */
    ret = wc_Stm32_Aes_Gcm(&aes, rt, ct, (word32)sizeof(ct),
                           gcm_tc_iv, (word32)sizeof(gcm_tc_iv),
                           tag, (word32)sizeof(tag),
                           NULL, 0, 0 /* dec */);
    if (ret != 0 || XMEMCMP(rt, gcm_tc3_pt, sizeof(gcm_tc3_pt)) != 0) {
        printf("  HW decrypt failed (ret=%d) -- FAIL\n", ret);
        wc_AesFree(&aes);
        return ret ? ret : -1;
    }
    printf("  HW decrypt: recovered PT OK\n");

    /* Tamper the tag: HW decrypt must reject with AES_GCM_AUTH_E. */
    tag[0] ^= 0xffu;
    ret = wc_Stm32_Aes_Gcm(&aes, rt, ct, (word32)sizeof(ct),
                           gcm_tc_iv, (word32)sizeof(gcm_tc_iv),
                           tag, (word32)sizeof(tag),
                           NULL, 0, 0 /* dec */);
    wc_AesFree(&aes);
    if (ret != WC_NO_ERR_TRACE(AES_GCM_AUTH_E)) {
        printf("  HW tamper NOT rejected (ret=%d) -- FAIL\n", ret);
        return -1;
    }
    printf("  HW decrypt: tamper rejected (AES_GCM_AUTH_E) OK\n");
    return 0;
}
#endif /* WOLFSSL_STM32_BARE && STM32_CRYPTO && HAVE_AESGCM */

int main(void)
{
    int ret = 0;

    board_init();
    SystemCoreClockUpdate();

    printf("\n========================================\n");
    printf("wolfCrypt bare STM32 HW AES-GCM (plaintext key) - %s (CONFIG=%s)\n",
           board_name(), BUILD_CONFIG_NAME);
    printf("wolfSSL version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("========================================\n\n");

    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("wolfCrypt_Init failed: %d\n", ret);
        for (;;) { }
    }

#if defined(WOLFSSL_STM32_BARE) && defined(STM32_CRYPTO) && defined(HAVE_AESGCM)
    printf("[direct wc_Stm32_Aes_Gcm KAT] whole-block, 12-byte IV\n");
    ret = hw_gcm_kat();
#else
    printf("HW AES-GCM not available in this build "
           "(need WOLFSSL_STM32_BARE + STM32_CRYPTO + HAVE_AESGCM).\n");
    ret = -1;
#endif

    g_plaingcm_res.overall = ret;
    g_plaingcm_res.magic   = 0x9C30A1u;
    wolfCrypt_Cleanup();
    printf("\nResult: %d (%s)\n", ret, ret == 0 ? "PASS" : "FAIL");
    printf("Test complete\n");

    for (;;) { }
}
