/* main_cubeaes.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * WOLF_CRYPTO_CB_ONLY_AES on the STM32 CubeMX/HAL build. Registers the CubeMX
 * AES crypto-callback device (wc_Stm32_CubeAesRegister) and runs AES-GCM
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

#ifndef BUILD_CONFIG_NAME
#define BUILD_CONFIG_NAME "unknown"
#endif

/* Registered crypto-callback device id for the AES HAL device. */
#define CUBE_AES_DEVID 77

/* Debugger-readable result sink (magic once main() completes). */
volatile struct {
    uint32_t magic;
    int32_t  tc3_rc;
    int32_t  tc4_rc;
    int32_t  overall;
} g_cubeaes_res;

#if defined(WOLFSSL_STM32_CUBEMX) && defined(WOLF_CRYPTO_CB) && \
    defined(HAVE_AESGCM)

/* Shared 128-bit key + 96-bit IV for the GCM test cases. */
static const byte g_key[16] = {
    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
    0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
};
static const byte g_iv[12] = {
    0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
    0xde,0xca,0xf8,0x88
};

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
    ret = wc_AesGcmSetKey(&aes, g_key, (word32)sizeof(g_key));
    if (ret != 0) {
        printf("  wc_AesGcmSetKey failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }
    ret = wc_AesGcmEncrypt(&aes, ct, pt, ptSz, g_iv, (word32)sizeof(g_iv),
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
        ret = wc_AesGcmSetKey(&aes, g_key, (word32)sizeof(g_key));
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, rt, ct, ptSz, g_iv, (word32)sizeof(g_iv),
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
        ret = wc_AesGcmSetKey(&aes, g_key, (word32)sizeof(g_key));
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, rt, ct, ptSz, g_iv, (word32)sizeof(g_iv),
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
        /* GCM test case 3: 64-byte payload (4 whole blocks), no AAD. */
        static const byte tc3_pt[64] = {
            0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
            0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
            0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
            0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
            0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,
            0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
            0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,
            0xba,0x63,0x7b,0x39,0x1a,0xaf,0xd2,0x55
        };
        static const byte tc3_ct[64] = {
            0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,
            0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
            0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,
            0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
            0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,
            0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
            0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,
            0x3d,0x58,0xe0,0x91,0x47,0x3f,0x59,0x85
        };
        static const byte tc3_tag[16] = {
            0x4d,0x5c,0x2a,0xf3,0x27,0xcd,0x64,0xa6,
            0x2c,0xf3,0x5a,0xbd,0x2b,0xa6,0xfa,0xb4
        };
        /* GCM test case 4: 60-byte payload (partial trailing block) + 20-byte
         * AAD -- exercises the AAD and partial-block paths. */
        static const byte tc4_aad[20] = {
            0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
            0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
            0xab,0xad,0xda,0xd2
        };
        static const byte tc4_pt[60] = {
            0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
            0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
            0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
            0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
            0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,
            0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
            0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,
            0xba,0x63,0x7b,0x39
        };
        static const byte tc4_ct[60] = {
            0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,
            0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
            0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,
            0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
            0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,
            0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
            0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,
            0x3d,0x58,0xe0,0x91
        };
        static const byte tc4_tag[16] = {
            0x5b,0xc9,0x4f,0xbc,0x32,0x21,0xa5,0xdb,
            0x94,0xfa,0xe9,0x5a,0xe7,0x12,0x1a,0x47
        };
        int rc;

        ret = wc_Stm32_CubeAesRegister(CUBE_AES_DEVID);
        if (ret != 0) {
            printf("wc_Stm32_CubeAesRegister failed: %d\n", ret);
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

            rc = gcm_kat("TC3 whole-block/no-AAD", tc3_pt,
                         (word32)sizeof(tc3_pt), NULL, 0,
                         tc3_ct, tc3_tag, 16);
            g_cubeaes_res.tc3_rc = rc;
            if (rc != 0 && ret == 0) {
                ret = rc;
            }

            printf("\n");
            rc = gcm_kat("TC4 AAD+partial-tail", tc4_pt,
                         (word32)sizeof(tc4_pt), tc4_aad,
                         (word32)sizeof(tc4_aad), tc4_ct, tc4_tag, 16);
            g_cubeaes_res.tc4_rc = rc;
            if (rc != 0 && ret == 0) {
                ret = rc;
            }

            wc_Stm32_CubeAesUnRegister(CUBE_AES_DEVID);
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
