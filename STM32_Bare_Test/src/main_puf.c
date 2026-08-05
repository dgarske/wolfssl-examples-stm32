/* main_puf.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * SRAM PUF regression app for STM32_Bare_Test. Runs the wolfCrypt PUF fuzzy
 * extractor end-to-end on real silicon in synthetic-SRAM mode
 * (WOLFSSL_PUF_TEST): enroll, clean reconstruct, reconstruct at the t-bit
 * correction limit, and an over-limit case that must not silently reproduce
 * the enrolled key. Exercises whatever BCH profile the build selected
 * (WC_PUF_BCH_T) and codeword count (WC_PUF_NUM_CODEWORDS).
 *
 *   make BOARD=h5 CONFIG=bare TARGET=puf PUF_T=13 flash
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
#include "wolfssl/wolfcrypt/puf.h"

#ifndef BUILD_CONFIG_NAME
#define BUILD_CONFIG_NAME "unknown"
#endif

/* Deterministic, profile-agnostic fill of the raw SRAM image. */
static void puf_fill(byte* sram, word32 sz)
{
    word32 i;
    for (i = 0; i < sz; i++)
        sram[i] = (byte)((i * 167u + 13u) ^ (i << 3));
}

/* Flip 'count' distinct bits inside one 128-bit codeword block, spread 7
 * apart so up to t+1 flips stay within the used n=127 bits. */
static void puf_flip(byte* sram, int block, int count)
{
    int i, base = block * 128;
    for (i = 0; i < count; i++) {
        int p = base + i * 7;
        sram[p / 8] ^= (byte)(1 << (7 - (p % 8)));
    }
}

int main(void)
{
    wc_PufCtx ctx;
    byte sram[WC_PUF_RAW_BYTES];
    byte noisy[WC_PUF_RAW_BYTES];
    byte helper[WC_PUF_HELPER_BYTES];
    byte id1[WC_PUF_ID_SZ], id2[WC_PUF_ID_SZ];
    byte key1[WC_PUF_KEY_SZ], key2[WC_PUF_KEY_SZ];
    const byte info[] = "stm32-puf";
    int m, n, k, t, nc, nb, b;
    int ret = 0;
    int fail = 0;

    board_init();
    SystemCoreClockUpdate();

    wc_PufGetParams(&m, &n, &k, &t, &nc);

    printf("\n");
    printf("========================================\n");
    printf("wolfCrypt SRAM PUF - %s (CONFIG=%s)\n",
           board_name(), BUILD_CONFIG_NAME);
    printf("wolfSSL version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("PUF profile: BCH(%d,%d,t=%d) codewords=%d "
           "raw=%d helper=%d\n", n, k, t, nc,
           (int)WC_PUF_RAW_BYTES, (int)WC_PUF_HELPER_BYTES);
    printf("profile id: app %08lX  lib %08lX\n",
           (unsigned long)WC_PUF_PROFILE_ID,
           (unsigned long)wc_PufGetProfileId());
    printf("========================================\n\n");

    /* A partial rebuild that mixes, say, a t=13 application with t=10 library
     * objects gives the two sides different sizeof(wc_PufCtx) and corrupts
     * memory on the first call. Catch it here instead. */
    if (wc_PufGetProfileId() != (word32)WC_PUF_PROFILE_ID) {
        printf("[0] profile: FAIL (library/application mismatch)\n");
        printf("\nResult: 1 (FAIL)\nTest complete\n");
        for (;;) { }
    }

    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("wolfCrypt_Init failed: %d\n", ret);
        printf("Result: %d (FAIL)\nTest complete\n", ret);
        for (;;) { }
    }

    puf_fill(sram, (word32)sizeof(sram));
    nb = nc < 3 ? nc : 3;

    /* [1] enroll */
    if (wc_PufInit(&ctx) != 0 ||
        wc_PufSetTestData(&ctx, sram, sizeof(sram)) != 0 ||
        wc_PufReadSram(&ctx, sram, sizeof(sram)) != 0 ||
        wc_PufEnroll(&ctx) != 0) {
        printf("[1] enroll: FAIL\n"); fail = 1; goto done;
    }
    if (wc_PufGetHelperData(&ctx, helper, sizeof(helper)) != 0 ||
        wc_PufGetIdentity(&ctx, id1, sizeof(id1)) != 0 ||
        wc_PufDeriveKey(&ctx, info, sizeof(info), key1, sizeof(key1)) != 0) {
        printf("[1] enroll: FAIL\n"); fail = 1; goto done;
    }
    printf("[1] enroll: PASS\n");

    /* [2] clean reconstruct - identity + key must match */
    if (wc_PufInit(&ctx) != 0 ||
        wc_PufSetTestData(&ctx, sram, sizeof(sram)) != 0 ||
        wc_PufReadSram(&ctx, sram, sizeof(sram)) != 0 ||
        wc_PufReconstructEx(&ctx, helper, sizeof(helper),
            (word32)WC_PUF_PROFILE_ID) != 0 ||
        wc_PufGetIdentity(&ctx, id2, sizeof(id2)) != 0 ||
        XMEMCMP(id1, id2, WC_PUF_ID_SZ) != 0 ||
        wc_PufDeriveKey(&ctx, info, sizeof(info), key2, sizeof(key2)) != 0 ||
        XMEMCMP(key1, key2, WC_PUF_KEY_SZ) != 0) {
        printf("[2] clean reconstruct: FAIL\n"); fail = 1; goto done;
    }
    printf("[2] clean reconstruct: PASS\n");

    /* [3] reconstruct at the t-bit correction limit */
    XMEMCPY(noisy, sram, sizeof(sram));
    for (b = 0; b < nb; b++)
        puf_flip(noisy, b, t);
    if (wc_PufInit(&ctx) != 0 ||
        wc_PufSetTestData(&ctx, noisy, sizeof(noisy)) != 0 ||
        wc_PufReadSram(&ctx, noisy, sizeof(noisy)) != 0 ||
        wc_PufReconstruct(&ctx, helper, sizeof(helper)) != 0 ||
        wc_PufGetIdentity(&ctx, id2, sizeof(id2)) != 0 ||
        XMEMCMP(id1, id2, WC_PUF_ID_SZ) != 0) {
        printf("[3] reconstruct t=%d flips/block: FAIL\n", t);
        fail = 1; goto done;
    }
    printf("[3] reconstruct %d flips/block x %d: PASS\n", t, nb);

    /* [4] over-limit: t+1 flips must fail OR differ, never silently correct */
    XMEMCPY(noisy, sram, sizeof(sram));
    puf_flip(noisy, 0, t + 1);
    if (wc_PufInit(&ctx) != 0 ||
        wc_PufSetTestData(&ctx, noisy, sizeof(noisy)) != 0 ||
        wc_PufReadSram(&ctx, noisy, sizeof(noisy)) != 0) {
        printf("[4] over-limit: FAIL (setup)\n"); fail = 1; goto done;
    }
    /* a successful decode must not reproduce the enrolled identity or key */
    if (wc_PufReconstruct(&ctx, helper, sizeof(helper)) == 0) {
        if (wc_PufGetIdentity(&ctx, id2, sizeof(id2)) == 0 &&
                XMEMCMP(id1, id2, WC_PUF_ID_SZ) == 0) {
            printf("[4] over-limit: FAIL (identity reproduced)\n");
            fail = 1; goto done;
        }
        if (wc_PufDeriveKey(&ctx, info, sizeof(info), key2,
                sizeof(key2)) == 0 &&
                XMEMCMP(key1, key2, WC_PUF_KEY_SZ) == 0) {
            printf("[4] over-limit: FAIL (key reproduced)\n");
            fail = 1; goto done;
        }
    }
    printf("[4] over-limit t+1: PASS\n");

    /* [5] helper data from a differently configured build must be refused
     * rather than decoded into a silently wrong key */
    if (wc_PufInit(&ctx) != 0 ||
        wc_PufSetTestData(&ctx, sram, sizeof(sram)) != 0 ||
        wc_PufReadSram(&ctx, sram, sizeof(sram)) != 0) {
        printf("[5] profile mismatch: FAIL (setup)\n"); fail = 1; goto done;
    }
    if (wc_PufReconstructEx(&ctx, helper, sizeof(helper),
            ((word32)WC_PUF_PROFILE_ID) ^ 1u) != BAD_FUNC_ARG) {
        printf("[5] profile mismatch: FAIL (not rejected)\n");
        fail = 1; goto done;
    }
    printf("[5] foreign profile id rejected: PASS\n");

done:
    printf("\nResult: %d (%s)\n", fail, fail ? "FAIL" : "PASS");
    printf("Test complete\n");
    for (;;) { }
}
