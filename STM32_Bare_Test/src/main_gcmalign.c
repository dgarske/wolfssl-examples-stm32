/* main_gcmalign.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Regression demo for skoll HIGH-1: the 8-bit-table (GCM_TABLE) GCM_gmult_len
 * added by PR#10949 reads the caller-supplied data block with LDM (multi-word
 * load), which faults on a non-word-aligned address on ARMv7-M / Thumb-2.
 * KAT vectors are word-aligned static arrays and never trigger it; a real TLS
 * record puts AAD/ciphertext at an odd offset.
 *
 * This runs wc_AesGcmEncrypt (software GHASH path) twice: once with a word
 * aligned AAD block, once with the AAD at offset +1. Build with CONFIG=asm
 * GCM=table to route GHASH through the new thumb2 8-bit GCM_gmult_len.
 *
 *   make BOARD=f767 CONFIG=asm TARGET=gcmalign GCM=table flash   (expect fault)
 *   make BOARD=f767 CONFIG=c   TARGET=gcmalign GCM=table flash   (control: OK)
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

#ifndef BUILD_CONFIG_NAME
#define BUILD_CONFIG_NAME "unknown"
#endif

volatile struct {
    uint32_t magic;
    int32_t  overall;
} g_gcmalign_res;

#if defined(HAVE_AESGCM)

static const byte k[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const byte iv[12] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b
};

/* 32-byte AAD store, word aligned; we index base and base+1 out of it. */
static XALIGNED(4) byte aad_store[40];

static int run_gcm(const byte* aad, word32 aadSz, const char* label)
{
    Aes   aes;
    byte  in[16];
    byte  out[16];
    byte  tag[16];
    int   ret;

    XMEMSET(in,  0xA5, sizeof(in));
    XMEMSET(out, 0,    sizeof(out));
    XMEMSET(tag, 0,    sizeof(tag));

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { printf("  %s wc_AesInit=%d\n", label, ret); return ret; }
    ret = wc_AesGcmSetKey(&aes, k, (word32)sizeof(k));
    if (ret != 0) { printf("  %s SetKey=%d\n", label, ret); wc_AesFree(&aes); return ret; }

    printf("  %s: aad=%p (offset %u) sz=%u -- calling wc_AesGcmEncrypt...\n",
           label, (void*)aad, (unsigned)((size_t)aad & 3u), (unsigned)aadSz);

    ret = wc_AesGcmEncrypt(&aes, out, in, (word32)sizeof(in),
                           iv, (word32)sizeof(iv),
                           tag, (word32)sizeof(tag),
                           aad, aadSz);

    printf("  %s: SURVIVED, ret=%d tag[0]=%02x\n", label, ret, tag[0]);
    wc_AesFree(&aes);
    return ret;
}
#endif /* HAVE_AESGCM */

int main(void)
{
    int ret = 0;

    board_init();
    SystemCoreClockUpdate();

    printf("\n========================================\n");
    printf("PR10949 GCM AAD-alignment demo - %s (CONFIG=%s)\n",
           board_name(), BUILD_CONFIG_NAME);
    printf("wolfSSL version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("========================================\n\n");

    ret = wolfCrypt_Init();
    if (ret != 0) { printf("wolfCrypt_Init=%d\n", ret); for (;;) { } }

#if defined(HAVE_AESGCM)
    XMEMSET(aad_store, 0x5c, sizeof(aad_store));

    /* Test A: one full 16-byte AAD block, word aligned. Must pass. */
    printf("[A] aligned AAD (1 full block):\n");
    ret = run_gcm(aad_store, 16, "aligned");
    if (ret != 0) {
        printf("  aligned run FAILED unexpectedly ret=%d\n", ret);
    }

    /* Test B: same 16-byte block at offset +1 (odd). If HIGH-1 is real, the
     * LDM in the 8-bit GCM_gmult_len faults here and nothing further prints. */
    printf("[B] UNALIGNED AAD (+1), watch for a fault (no SURVIVED line):\n");
    ret = run_gcm(aad_store + 1, 16, "unaligned");
    if (ret != 0) {
        printf("  unaligned run returned ret=%d\n", ret);
    }
    printf("Both runs completed without a fault.\n");
#else
    printf("HAVE_AESGCM not defined in this build.\n");
    ret = -1;
#endif

    g_gcmalign_res.overall = ret;
    g_gcmalign_res.magic   = 0xA1160Du;
    wolfCrypt_Cleanup();
    printf("\nResult: %d (%s)\n", ret, ret == 0 ? "PASS" : "FAIL");
    printf("Test complete\n");

    for (;;) { }
}
