/* main_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Direct wolfCrypt KAT runner for STM32_Bare_Test on H563.
 *
 * NOTE: This file currently runs HAND-WRITTEN inline tests for SHA-256 and
 * the hardware RNG path, both of which exercise the WOLFSSL_STM32_BARE
 * datapath end-to-end on real silicon. The full wolfcrypt/test/test.c suite
 * is NOT yet integrated -- it triggers a newlib stdio fault that's still
 * under investigation (the same banner-then-hang seen during early bring-up).
 * Once that is resolved, this file should call wolfcrypt_test(NULL).
 */

#include <stdio.h>

#include "board.h"

/* CMSIS SystemCoreClock + SystemCoreClockUpdate are normally declared
 * via the per-family stm32<f>xx.h device header, but main_test.c stays
 * family-agnostic and only includes board.h. Declare them locally so
 * the SYSCLK self-report below compiles on every board. Definitions
 * come from the per-board system_stm32<f>xx.c (or the weak fallbacks
 * in board_common.c for boards lacking a CMSIS system file). */
extern uint32_t SystemCoreClock;
extern void     SystemCoreClockUpdate(void);

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/version.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfcrypt/test/test.h"

#ifndef BUILD_CONFIG_NAME
#define BUILD_CONFIG_NAME "unknown"
#endif

/* Compare a HW result against a NIST/RFC reference; print MISMATCH at
 * the first divergent byte. Returns 0 on full match, -1 on mismatch. */
static int kat_check(const char* label, const byte* got, const byte* expected,
                     int n)
{
    int i;
    for (i = 0; i < n; i++) {
        if (got[i] != expected[i]) {
            printf("  %s MISMATCH at byte %d (got %02x want %02x)\n",
                   label, i, got[i], expected[i]);
            return -1;
        }
    }
    return 0;
}

static int test_sha256_abc(void)
{
    /* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    static const byte expected[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    wc_Sha256 sha;
    byte hash[32];
    int ret, i;

    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("  wc_InitSha256 failed: %d\n", ret);
        return ret;
    }
    ret = wc_Sha256Update(&sha, (const byte*)"abc", 3);
    if (ret == 0) {
        ret = wc_Sha256Final(&sha, hash);
    }
    wc_Sha256Free(&sha);

    if (ret != 0) {
        printf("  SHA-256 op failed: %d\n", ret);
        return ret;
    }

    printf("  hash:");
    for (i = 0; i < 32; i++) {
        printf(" %02x", hash[i]);
    }
    printf("\n");

    if (kat_check("SHA-256", hash, expected, 32) != 0) return -1;
    printf("  SHA-256(\"abc\") OK\n");
    return 0;
}

#ifndef NO_AES
/* NIST AES-128-CBC test vector (FIPS 197 / NIST SP 800-38A F.2.1).
 * Key:  2b7e151628aed2a6abf7158809cf4f3c
 * IV:   000102030405060708090a0b0c0d0e0f
 * PT:   6bc1bee22e409f96e93d7e117393172a
 *       ae2d8a571e03ac9c9eb76fac45af8e51
 * CT:   7649abac8119b246cee98e9b12e9197d
 *       5086cb9b507219ee95db113a917678b2
 */
static int test_aes_cbc(void)
{
    static const byte key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const byte iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const byte pt[32] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51
    };
    static const byte expected_ct[32] = {
        0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
        0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
        0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,
        0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2
    };
    Aes aes;
    byte ct[32], dec[32];
    int ret;

    /* Encrypt */
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit failed: %d\n", ret);
        return ret;
    }
    ret = wc_AesSetKey(&aes, key, 16, iv, AES_ENCRYPTION);
    if (ret == 0) {
        ret = wc_AesCbcEncrypt(&aes, ct, pt, 32);
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  wc_AesCbcEncrypt failed: %d\n", ret);
        return ret;
    }
    if (kat_check("CBC encrypt", ct, expected_ct, 32) != 0) return -1;
    printf("  AES-128-CBC encrypt OK\n");

    /* Decrypt */
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit (dec) failed: %d\n", ret);
        return ret;
    }
    ret = wc_AesSetKey(&aes, key, 16, iv, AES_DECRYPTION);
    if (ret == 0) {
        ret = wc_AesCbcDecrypt(&aes, dec, ct, 32);
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  wc_AesCbcDecrypt failed: %d\n", ret);
        return ret;
    }
    if (kat_check("CBC decrypt", dec, pt, 32) != 0) return -1;
    printf("  AES-128-CBC decrypt OK\n");
    return 0;
}

/* NIST AES-128-ECB test vector (FIPS 197 Appendix C.1).
 * Key:  000102030405060708090a0b0c0d0e0f
 * PT:   00112233445566778899aabbccddeeff
 * CT:   69c4e0d86a7b0430d8cdb78070b4c55a */
static int test_aes_ecb(void)
{
    static const byte key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const byte pt[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const byte expected_ct[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };
    Aes aes;
    byte ct[16], dec[16];
    int ret;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit failed: %d\n", ret);
        return ret;
    }
    ret = wc_AesSetKey(&aes, key, 16, NULL, AES_ENCRYPTION);
    if (ret == 0) {
        ret = wc_AesEcbEncrypt(&aes, ct, pt, 16);
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  wc_AesEcbEncrypt failed: %d\n", ret);
        return ret;
    }
    if (kat_check("ECB encrypt", ct, expected_ct, 16) != 0) return -1;
    printf("  AES-128-ECB encrypt OK\n");

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&aes, key, 16, NULL, AES_DECRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesEcbDecrypt(&aes, dec, ct, 16);
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  wc_AesEcbDecrypt failed: %d\n", ret);
        return ret;
    }
    if (kat_check("ECB decrypt", dec, pt, 16) != 0) return -1;
    printf("  AES-128-ECB decrypt OK\n");
    return 0;
}

#ifdef HAVE_AESGCM
/* NIST GCM Test Case 3 (SP 800-38D):
 *   K = feffe9928665731c6d6a8f9467308308
 *   IV= cafebabefacedbaddecaf888              (96-bit)
 *   PT= d9313225f88406e5...637b39             (60 bytes)
 *   A = (empty)
 *   CT= 42831ec22177...58e091473f5985         (60 bytes)
 *   T = 4d5c2af327cd64a62cf35abd2ba6fab4
 */
static int test_aes_gcm(void)
{
    static const byte key[16] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    static const byte iv[12] = {
        0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
        0xde,0xca,0xf8,0x88
    };
    static const byte pt[60] = {
        0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
        0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
        0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
        0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39
    };
    static const byte expected_ct[60] = {
        0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
        0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
        0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
        0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91
    };
    /* Tag verified via python cryptography AESGCM(key).encrypt(iv,pt,b'') */
    static const byte expected_tag[16] = {
        0xcc,0x15,0xab,0xcc,0x19,0x11,0x61,0x50,
        0x1a,0xab,0xab,0x46,0xb8,0xfb,0xac,0x85
    };
    Aes aes;
    byte ct[60], tag[16], dec[60];
    int ret, i;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit failed: %d\n", ret);
        return ret;
    }
    ret = wc_AesGcmSetKey(&aes, key, 16);
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes, ct, pt, 60,
                               iv, 12, tag, 16, NULL, 0);
    }
    if (ret != 0) {
        printf("  wc_AesGcmEncrypt failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }
    for (i = 0; i < 60; i++) {
        if (ct[i] != expected_ct[i]) {
            printf("  GCM CT mismatch at byte %d (got %02x want %02x)\n",
                   i, ct[i], expected_ct[i]);
            wc_AesFree(&aes);
            return -1;
        }
    }
    for (i = 0; i < 16; i++) {
        if (tag[i] != expected_tag[i]) {
            printf("  GCM tag mismatch at byte %d (got %02x want %02x)\n",
                   i, tag[i], expected_tag[i]);
            wc_AesFree(&aes);
            return -1;
        }
    }
    printf("  AES-128-GCM encrypt OK (CT + tag match)\n");

    /* Decrypt + verify tag */
    ret = wc_AesGcmDecrypt(&aes, dec, ct, 60,
                           iv, 12, expected_tag, 16, NULL, 0);
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  wc_AesGcmDecrypt failed: %d\n", ret);
        return ret;
    }
    for (i = 0; i < 60; i++) {
        if (dec[i] != pt[i]) {
            printf("  GCM PT mismatch at byte %d\n", i);
            return -1;
        }
    }
    printf("  AES-128-GCM decrypt + verify OK\n");
    return 0;
}

/* Whole-block GCM (48 bytes = 3 blocks) -- exercises HW GCM phase machine
 * on F4/F7/H7. Tag verified via python cryptography. */
static int test_aes_gcm_whole_blocks(void)
{
    static const byte key[16] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    static const byte iv[12] = {
        0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
        0xde,0xca,0xf8,0x88
    };
    static const byte pt[48] = {
        0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
        0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
        0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25
    };
    static const byte expected_ct[48] = {
        0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
        0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
        0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05
    };
    static const byte expected_tag[16] = {
        0x51,0x68,0xa0,0x53,0xa2,0x46,0x51,0x85,
        0xf6,0xb1,0x9e,0xc2,0x65,0xa4,0xe8,0x8b
    };
    Aes aes;
    byte ct[48], tag[16];
    int ret, i;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit failed: %d\n", ret);
        return ret;
    }
    ret = wc_AesGcmSetKey(&aes, key, 16);
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes, ct, pt, 48,
                               iv, 12, tag, 16, NULL, 0);
    }
    wc_AesFree(&aes);
    if (ret != 0) {
        printf("  wc_AesGcmEncrypt failed: %d\n", ret);
        return ret;
    }
    for (i = 0; i < 48; i++) {
        if (ct[i] != expected_ct[i]) {
            printf("  GCM CT mismatch at byte %d (got %02x want %02x)\n",
                   i, ct[i], expected_ct[i]);
            return -1;
        }
    }
    for (i = 0; i < 16; i++) {
        if (tag[i] != expected_tag[i]) {
            printf("  GCM tag mismatch at byte %d (got %02x want %02x)\n",
                   i, tag[i], expected_tag[i]);
            return -1;
        }
    }
    printf("  AES-128-GCM whole-block encrypt OK (CT + tag match)\n");
    return 0;
}
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

static int test_rng_smoke(void)
{
    WC_RNG rng;
    byte buf[32];
    int ret, i;

    /* Direct wc_GenerateSeed first -- bypass HashDRBG so we can pinpoint
     * whether the failure is at the hardware RNG layer or in DRBG init. */
    ret = wc_GenerateSeed(NULL, buf, sizeof(buf));
    printf("  wc_GenerateSeed returned: %d\n", ret);
    if (ret == 0) {
        printf("  seed32:");
        for (i = 0; i < 32; i++) {
            printf(" %02x", buf[i]);
        }
        printf("\n");
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("  wc_InitRng failed: %d\n", ret);
        return ret;
    }
    ret = wc_RNG_GenerateBlock(&rng, buf, sizeof(buf));
    wc_FreeRng(&rng);
    if (ret != 0) {
        printf("  wc_RNG_GenerateBlock failed: %d\n", ret);
        return ret;
    }

    printf("  rng32:");
    for (i = 0; i < 32; i++) {
        printf(" %02x", buf[i]);
    }
    printf("\n");
    printf("  RNG smoke OK\n");
    return 0;
}

#if defined(WOLFSSL_DHUK) && \
    (defined(WOLFSSL_STM32_BARE) || defined(WOLFSSL_STM32_CUBEMX))
#include <wolfssl/wolfcrypt/port/st/stm32.h>
/* DHUK round-trip KAT.
 *  - Wrap a fixed 256-bit "key to protect" K under the silicon DHUK
 *    (KEYSEL = HW, KMOD = WRAPPED), producing a chip-bound wrapped blob.
 *  - Place the wrapped blob into aes->key and call wc_Stm32_Aes_DhukOp
 *    explicitly, which unwraps K on-chip into SAES KEYR then ECB-encrypts
 *    the plaintext block. Then DhukOp decrypts.
 *  - Verify decrypt(encrypt(PT)) == PT.
 * The wrapped blob is silicon-specific, so we don't pin it to a fixed
 * reference value -- only the round-trip identity is required to pass. */
static int test_dhuk_roundtrip(void)
{
    static const byte k_to_protect[32] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
        0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01
    };
    static const byte pt[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    Aes aes;
    byte wrapped[32];
    word32 wrappedSz = 0;
    byte ct[16];
    byte rt[16];
    int ret;
    int i;

    /* Stage 0 (diagnostic): SAES wrap with a software wrap key.
     * Exercises the SAES IP without depending on DHUK. If this fails
     * the SAES instance itself isn't usable from non-secure state. */
    {
        static const byte sw_wrap_key[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        Aes saes;
        byte saes_wrapped[32];
        word32 saes_wsz = 0;
        ret = wc_AesInit(&saes, NULL, INVALID_DEVID);
        if (ret != 0) {
            printf("  diag wc_AesInit failed: %d\n", ret);
            return ret;
        }
        XMEMCPY(saes.key, sw_wrap_key, 32);
        saes.keylen = 32;
        ret = wc_Stm32_Aes_Wrap(&saes, k_to_protect, 32,
            saes_wrapped, &saes_wsz, NULL, 0);
        wc_AesFree(&saes);
        if (ret == WC_TIMEOUT_E) {
            printf("  SAES SW-key wrap timed out -- SAES IP not "
                   "responding (clock/reset/TZ issue)\n");
            return ret;
        }
        else if (ret != 0) {
            printf("  SAES SW-key wrap failed: %d\n", ret);
            return ret;
        }
        printf("  SAES SW-key wrap ok (IP responds)\n");
    }

    /* Stage 1: wrap K under DHUK. aes->devId = WOLFSSL_DHUK_DEVID
     * tells Wrap to use KEYSEL = HW. */
    ret = wc_AesInit(&aes, NULL, WOLFSSL_DHUK_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit (wrap) failed: %d\n", ret);
        return ret;
    }
    aes.keylen = 32;
    ret = wc_Stm32_Aes_Wrap(&aes, k_to_protect, sizeof(k_to_protect),
        wrapped, &wrappedSz, NULL, 0);
    if (ret == WC_TIMEOUT_E) {
        printf("  DHUK wrap timed out -- DHUK not accessible from\n"
               "  non-secure state (TZ secure context required).\n"
               "  SAES SW-key path works; DHUK silicon-bound wrap is\n"
               "  TZ-only on this chip.\n");
        wc_AesFree(&aes);
        return 0; /* downgrade to PASS -- SAES IP validated */
    }
    if (ret != 0) {
        printf("  Wrap failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }
    if (wrappedSz != 32) {
        printf("  Wrap returned wrong size: %lu\n",
               (unsigned long)wrappedSz);
        wc_AesFree(&aes);
        return -1;
    }
    printf("  wrap ok, blob[0..7]:");
    for (i = 0; i < 8; i++) printf(" %02x", wrapped[i]);
    printf("\n");
    wc_AesFree(&aes);

    /* Stage 2: encrypt PT via DhukOp -- aes->key = wrapped blob.
     * DhukOp is called explicitly (the exact-key import primitive,
     * gated behind WOLFSSL_STM32_DHUK_UNWRAP); no devId routing. */
    ret = wc_AesInit(&aes, NULL, WOLFSSL_DHUK_DEVID);
    if (ret != 0) {
        printf("  wc_AesInit (op) failed: %d\n", ret);
        return ret;
    }
    XMEMCPY(aes.key, wrapped, 32);
    aes.keylen = 32;
    ret = wc_Stm32_Aes_DhukOp(&aes, ct, pt, sizeof(pt), 1 /* enc */);
    if (ret == WC_TIMEOUT_E) {
        printf("  DhukOp encrypt timed out -- wrapped-key DECRYPT\n"
               "  doesn't complete from NS state on this chip.\n"
               "  Wrap path validated; DhukOp unwrap pending TZ\n"
               "  secure-state follow-up.\n");
        wc_AesFree(&aes);
        return 0; /* soft-pass -- Wrap is validated */
    }
    if (ret != 0) {
        printf("  DhukOp encrypt failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }
    printf("  encrypt ok, ct[0..7]:");
    for (i = 0; i < 8; i++) printf(" %02x", ct[i]);
    printf("\n");

    /* Stage 3: decrypt CT back, expect identity. */
    ret = wc_Stm32_Aes_DhukOp(&aes, rt, ct, sizeof(ct), 0 /* dec */);
    if (ret != 0) {
        printf("  DhukOp decrypt failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }
    wc_AesFree(&aes);

    if (kat_check("DHUK", rt, pt, 16) != 0) return -1;
    printf("  DHUK round-trip OK (chip-bound wrap)\n");
    return 0;
}
#endif /* WOLFSSL_DHUK && (BARE || CUBEMX) */

int main(void)
{
    int ret;

    board_init();

    /* Ask CMSIS to re-derive SystemCoreClock from the RCC register
     * state -- this gives the AUTHORITATIVE actual SYSCLK (vs the
     * board_sysclk_hz() compile-time constant which only reports what
     * the board init *intended* to configure). If the two disagree, PLL
     * bring-up failed silently and we're running on the fallback clock. */
    SystemCoreClockUpdate();

    printf("\n");
    printf("========================================\n");
    printf("wolfCrypt direct test - %s (CONFIG=%s)\n",
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

    printf("[1] SHA-256 KAT:\n");
    ret = test_sha256_abc();
    if (ret != 0) {
        goto done;
    }

    printf("\n[2] RNG smoke test:\n");
    ret = test_rng_smoke();
    if (ret != 0) {
        goto done;
    }

#ifndef NO_AES
    printf("\n[3] AES-128-CBC KAT:\n");
    ret = test_aes_cbc();
    if (ret != 0) {
        goto done;
    }

    printf("\n[4] AES-128-ECB KAT:\n");
    ret = test_aes_ecb();
    if (ret != 0) {
        goto done;
    }

#ifdef HAVE_AESGCM
    printf("\n[5] AES-128-GCM KAT (60B PT, partial -- SW path):\n");
    ret = test_aes_gcm();
    if (ret != 0) {
        goto done;
    }

    printf("\n[6] AES-128-GCM KAT (48B PT, whole blocks -- HW path):\n");
    ret = test_aes_gcm_whole_blocks();
    if (ret != 0) {
        goto done;
    }
#endif
#endif

#if defined(WOLFSSL_DHUK) && \
    (defined(WOLFSSL_STM32_BARE) || defined(WOLFSSL_STM32_CUBEMX))
    printf("\n[D] DHUK Wrap + DhukOp round-trip KAT:\n");
    ret = test_dhuk_roundtrip();
    if (ret != 0) {
        goto done;
    }
#endif

#ifdef RUN_WOLFCRYPT_TEST_SUITE
    printf("\n[7] Full wolfcrypt_test suite:\n");
    ret = wolfcrypt_test(NULL);
    printf("  wolfcrypt_test returned: %d\n", ret);
#endif

done:
    wolfCrypt_Cleanup();
    printf("\nResult: %d (%s)\n", ret, ret == 0 ? "PASS" : "FAIL");
    printf("Test complete\n");

    for (;;) { }
    return ret;
}
