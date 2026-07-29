/* main_plaingcm.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Direct hardware AES-GCM check for the bare-metal STM32 AES engine with a
 * plaintext key -- validates encrypt AND decrypt-verify on the HW GCM path
 * (CRYP IP on F2/F4/F7/H7; TinyAES GCM on U3/U5/H5/...). It calls
 * wc_Stm32_Aes_Gcm() directly, so there is NO software fallback: if the return
 * is 0 and the output matches the published McGrew & Viega GCM test-case-3
 * vector (whole-block, 12-byte IV), the hardware GCM engine produced it.
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

#ifndef BUILD_CONFIG_NAME
#define BUILD_CONFIG_NAME "unknown"
#endif

volatile struct {
    uint32_t magic;
    int32_t  overall;
} g_plaingcm_res;

#if defined(WOLFSSL_STM32_BARE) && defined(STM32_CRYPTO) && defined(HAVE_AESGCM)

/* McGrew GCM test case 3: 128-bit key, 64-byte payload (whole blocks), no AAD. */
static const byte g_key[16] = {
    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
    0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
};
static const byte g_iv[12] = {
    0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88
};
static const byte g_pt[64] = {
    0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
    0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
    0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
    0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
    0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,
    0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
    0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,
    0xba,0x63,0x7b,0x39,0x1a,0xaf,0xd2,0x55
};
static const byte g_ct[64] = {
    0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,
    0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
    0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,
    0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
    0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,
    0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
    0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,
    0x3d,0x58,0xe0,0x91,0x47,0x3f,0x59,0x85
};
static const byte g_tag[16] = {
    0x4d,0x5c,0x2a,0xf3,0x27,0xcd,0x64,0xa6,
    0x2c,0xf3,0x5a,0xbd,0x2b,0xa6,0xfa,0xb4
};

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
    ret = wc_AesGcmSetKey(&aes, g_key, (word32)sizeof(g_key));
    if (ret != 0) {
        printf("  wc_AesGcmSetKey failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }

    /* Direct HW encrypt (no SW fallback). UNAVAILABLE would mean the HW path
     * declined -- treated here as a failure so we never silently pass on SW. */
    ret = wc_Stm32_Aes_Gcm(&aes, ct, g_pt, (word32)sizeof(g_pt),
                           g_iv, (word32)sizeof(g_iv), tag, (word32)sizeof(tag),
                           NULL, 0, 1 /* enc */);
    if (ret != 0) {
        printf("  HW encrypt returned %d (0 expected; not on HW?) -- FAIL\n",
               ret);
        wc_AesFree(&aes);
        return ret ? ret : -1;
    }
    if (XMEMCMP(ct, g_ct, sizeof(g_ct)) != 0 ||
            XMEMCMP(tag, g_tag, sizeof(g_tag)) != 0) {
        printf("  HW CT/tag mismatch vs KAT -- FAIL\n");
        wc_AesFree(&aes);
        return -1;
    }
    printf("  HW encrypt: CT + tag match published vector OK\n");

    /* Direct HW decrypt-verify. */
    ret = wc_Stm32_Aes_Gcm(&aes, rt, ct, (word32)sizeof(ct),
                           g_iv, (word32)sizeof(g_iv), tag, (word32)sizeof(tag),
                           NULL, 0, 0 /* dec */);
    if (ret != 0 || XMEMCMP(rt, g_pt, sizeof(g_pt)) != 0) {
        printf("  HW decrypt failed (ret=%d) -- FAIL\n", ret);
        wc_AesFree(&aes);
        return ret ? ret : -1;
    }
    printf("  HW decrypt: recovered PT OK\n");

    /* Tamper the tag: HW decrypt must reject with AES_GCM_AUTH_E. */
    tag[0] ^= 0xffu;
    ret = wc_Stm32_Aes_Gcm(&aes, rt, ct, (word32)sizeof(ct),
                           g_iv, (word32)sizeof(g_iv), tag, (word32)sizeof(tag),
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
