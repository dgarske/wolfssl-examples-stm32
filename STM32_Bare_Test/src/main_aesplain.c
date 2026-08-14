/* main_aesplain.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Plaintext-key AES vs DHUK-seed AES on the STM32 bare-metal build, both active
 * at once and selected per Aes by devId. Registers two crypto-callback devices:
 *
 *   - the plaintext-key AES device (wc_Stm32_AesRegister, WOLFSSL_STM32_AES_DEVID)
 *     runs a caller-supplied key directly on the HW CRYP engine, and
 *   - the DHUK device (wc_Stm32_DhukRegister, WC_DHUK_DEVID) treats the key bytes
 *     as a 256-bit seed for the SAES/DHUK key ladder.
 *
 * Test 1 runs AES-GCM known-answer tests through the plaintext device (McGrew &
 * Viega GCM cases 3 and 4 -- the latter with AAD and a partial trailing block),
 * proving the key is used verbatim; encrypt and decrypt-verify both run on the
 * AES-GCM hardware. Test 2 feeds the SAME 32 key bytes to both devices: the
 * plaintext ciphertext differs from the DHUK (device-bound) ciphertext, and each
 * device decrypts its own output -- demonstrating run-time selection by devId.
 *
 * Built with the STM32_BARE_CB_ONLY preset (WOLF_CRYPTO_CB_ONLY_AES): the
 * software AES core is stripped and every AES block routes through a device;
 * each device's AES-ECB handler keys GCM's GHASH subkey H.
 *
 *   make BOARD=u585 TARGET=aesplain flash
 *   make BOARD=u3   TARGET=aesplain flash
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
    int32_t  kat_rc;
    int32_t  coexist_rc;
    int32_t  overall;
} g_aesplain_res;

#if defined(WOLFSSL_STM32_BARE) && defined(WOLF_CRYPTO_CB) && \
    defined(HAVE_AESGCM)

/* AES-GCM one-shot on a given devId: encrypt into ct/tag. 0 on success. */
static int gcm_encrypt(int devId, const byte* key, word32 keySz,
    byte* ct, byte* tag, word32 tagSz, const byte* pt, word32 ptSz,
    const byte* aad, word32 aadSz)
{
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, devId);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, key, keySz);
    }
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes, ct, pt, ptSz,
                               gcm_tc_iv, (word32)sizeof(gcm_tc_iv),
                               tag, tagSz, aad, aadSz);
    }
    wc_AesFree(&aes);
    return ret;
}

/* AES-GCM decrypt-verify on a given devId. 0 on success (tag OK, PT recovered). */
static int gcm_decrypt(int devId, const byte* key, word32 keySz,
    byte* rt, const byte* ct, const byte* tag, word32 tagSz, word32 ptSz,
    const byte* aad, word32 aadSz)
{
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, devId);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, key, keySz);
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, rt, ct, ptSz,
                               gcm_tc_iv, (word32)sizeof(gcm_tc_iv),
                               tag, tagSz, aad, aadSz);
    }
    wc_AesFree(&aes);
    return ret;
}

/* One plaintext-device KAT: encrypt -> match published CT/tag, decrypt ->
 * recover PT, tamper -> reject. */
static int plain_gcm_one(const char* name, const byte* pt, word32 ptSz,
    const byte* aad, word32 aadSz, const byte* expCt, const byte* expTag)
{
    byte ct[64];
    byte rt[64];
    byte tag[16];
    int  ret;

    /* Reject a vector too long for the fixed output buffers (the tag length is
     * fixed at sizeof(tag) by every call below). */
    if (ptSz > (word32)sizeof(ct)) {
        return BAD_FUNC_ARG;
    }

    printf("  [%s]\n", name);
    XMEMSET(ct, 0, sizeof(ct));
    XMEMSET(rt, 0, sizeof(rt));
    XMEMSET(tag, 0, sizeof(tag));

    ret = gcm_encrypt(WOLFSSL_STM32_AES_DEVID, gcm_tc_key,
                      (word32)sizeof(gcm_tc_key), ct, tag, 16, pt, ptSz,
                      aad, aadSz);
    if (ret != 0) {
        printf("    encrypt failed: %d\n", ret);
        return ret;
    }
    if (XMEMCMP(ct, expCt, ptSz) != 0 || XMEMCMP(tag, expTag, 16) != 0) {
        printf("    CT/tag mismatch vs KAT -- FAIL\n");
        return -1;
    }
    printf("    CT + tag match published vector OK\n");

    ret = gcm_decrypt(WOLFSSL_STM32_AES_DEVID, gcm_tc_key,
                      (word32)sizeof(gcm_tc_key), rt, ct, tag, 16, ptSz,
                      aad, aadSz);
    if (ret != 0 || XMEMCMP(rt, pt, ptSz) != 0) {
        printf("    round-trip failed (ret=%d) -- FAIL\n", ret);
        return (ret != 0) ? ret : -1;
    }
    printf("    decrypt recovered PT OK\n");

    tag[0] ^= 0xffu;
    ret = gcm_decrypt(WOLFSSL_STM32_AES_DEVID, gcm_tc_key,
                      (word32)sizeof(gcm_tc_key), rt, ct, tag, 16, ptSz,
                      aad, aadSz);
    if (ret != WC_NO_ERR_TRACE(AES_GCM_AUTH_E)) {
        printf("    tamper NOT rejected (ret=%d) -- FAIL\n", ret);
        return -1;
    }
    printf("    tamper rejected (AES_GCM_AUTH_E) OK\n");
    return 0;
}

/* Test 1: plaintext device reproduces published AES-GCM vectors (proves the key
 * is the actual AES key, not a seed). TC3 is whole-block/no-AAD; TC4 has AAD and
 * a partial trailing block (NPBLB + header phase). */
static int plaintext_kat(void)
{
    int ret;

    printf("[plaintext KAT] devId=%d (verbatim key)\n",
           WOLFSSL_STM32_AES_DEVID);
    ret = plain_gcm_one("TC3 whole-block/no-AAD", gcm_tc3_pt,
                        (word32)sizeof(gcm_tc3_pt), NULL, 0,
                        gcm_tc3_ct, gcm_tc3_tag);
    if (ret != 0) {
        return ret;
    }
    return plain_gcm_one("TC4 AAD+partial-tail", gcm_tc4_pt,
                         (word32)sizeof(gcm_tc4_pt), gcm_tc4_aad,
                         (word32)sizeof(gcm_tc4_aad), gcm_tc4_ct, gcm_tc4_tag);
}

/* Test 2: feed the same 32 bytes to both devices. Plaintext ciphertext must
 * differ from the DHUK device-bound ciphertext, and each device must decrypt
 * its own output -- proving both are active and chosen by devId. */
static int coexist(void)
{
    static const byte key32[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const byte pt[16] = {
        0x53,0x69,0x6e,0x67,0x6c,0x65,0x20,0x62,
        0x6c,0x6f,0x63,0x6b,0x20,0x6d,0x73,0x67
    };
    byte ctPlain[16], ctDhuk[16], rt[16];
    byte tagPlain[16], tagDhuk[16];
    int  ret;

    printf("[coexist] plaintext devId=%d vs DHUK devId=%d, same 32 key bytes\n",
           WOLFSSL_STM32_AES_DEVID, WC_DHUK_DEVID);

    ret = gcm_encrypt(WOLFSSL_STM32_AES_DEVID, key32, (word32)sizeof(key32),
                      ctPlain, tagPlain, 16, pt, (word32)sizeof(pt),
                      NULL, 0);
    if (ret != 0) {
        printf("  plaintext encrypt failed: %d\n", ret);
        return ret;
    }
    ret = gcm_encrypt(WC_DHUK_DEVID, key32, (word32)sizeof(key32),
                      ctDhuk, tagDhuk, 16, pt, (word32)sizeof(pt),
                      NULL, 0);
    if (ret != 0) {
        printf("  DHUK encrypt failed: %d\n", ret);
        return ret;
    }
    if (XMEMCMP(ctPlain, ctDhuk, sizeof(ctPlain)) == 0) {
        printf("  plaintext and DHUK ciphertext identical -- FAIL "
               "(DHUK not deriving)\n");
        return -1;
    }
    printf("  plaintext CT != DHUK CT OK (distinct keys per devId)\n");

    ret = gcm_decrypt(WOLFSSL_STM32_AES_DEVID, key32, (word32)sizeof(key32),
                      rt, ctPlain, tagPlain, 16, (word32)sizeof(pt),
                      NULL, 0);
    if (ret != 0 || XMEMCMP(rt, pt, sizeof(pt)) != 0) {
        printf("  plaintext round-trip failed (ret=%d) -- FAIL\n", ret);
        return (ret != 0) ? ret : -1;
    }
    ret = gcm_decrypt(WC_DHUK_DEVID, key32, (word32)sizeof(key32),
                      rt, ctDhuk, tagDhuk, 16, (word32)sizeof(pt),
                      NULL, 0);
    if (ret != 0 || XMEMCMP(rt, pt, sizeof(pt)) != 0) {
        printf("  DHUK round-trip failed (ret=%d) -- FAIL\n", ret);
        return (ret != 0) ? ret : -1;
    }
    printf("  both devices decrypt their own output OK\n");
    return 0;
}
#endif /* WOLFSSL_STM32_BARE && WOLF_CRYPTO_CB && HAVE_AESGCM */

int main(void)
{
    int ret = 0;

    board_init();
    SystemCoreClockUpdate();

    printf("\n");
    printf("========================================\n");
    printf("wolfCrypt plaintext-vs-DHUK AES test - %s (CONFIG=%s)\n",
           board_name(), BUILD_CONFIG_NAME);
    printf("wolfSSL version: %s\n", LIBWOLFSSL_VERSION_STRING);
    printf("========================================\n\n");

    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("wolfCrypt_Init failed: %d\n", ret);
        for (;;) { }
    }

#if defined(WOLFSSL_STM32_BARE) && defined(WOLF_CRYPTO_CB) && \
    defined(HAVE_AESGCM)
    {
        int rc;

        ret = wc_Stm32_AesRegister(WOLFSSL_STM32_AES_DEVID);
        if (ret == 0) {
            ret = wc_Stm32_DhukRegister(WC_DHUK_DEVID);
        }
        if (ret != 0) {
            printf("device registration failed: %d\n", ret);
        }
        else {
            printf("Registered plaintext AES (devId=%d) + DHUK (devId=%d)\n\n",
                   WOLFSSL_STM32_AES_DEVID, WC_DHUK_DEVID);

            rc = plaintext_kat();
            g_aesplain_res.kat_rc = rc;
            if (rc != 0 && ret == 0) {
                ret = rc;
            }

            printf("\n");
            rc = coexist();
            g_aesplain_res.coexist_rc = rc;
            if (rc != 0 && ret == 0) {
                ret = rc;
            }

            wc_Stm32_DhukUnRegister(WC_DHUK_DEVID);
            wc_Stm32_AesUnRegister(WOLFSSL_STM32_AES_DEVID);
        }
    }
#else
    printf("plaintext-vs-DHUK AES test needs WOLFSSL_STM32_BARE + "
           "WOLF_CRYPTO_CB + HAVE_AESGCM.\n");
    ret = -1;
#endif

    g_aesplain_res.overall = ret;
    g_aesplain_res.magic   = 0xAE91A1u;
    wolfCrypt_Cleanup();
    printf("\nResult: %d (%s)\n", ret, ret == 0 ? "PASS" : "FAIL");
    printf("Test complete\n");

    for (;;) { }
}
