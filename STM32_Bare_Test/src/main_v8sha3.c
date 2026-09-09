/* main_v8sha3.c - STM32V8 HASH SHA-3/SHAKE silicon probe (no wolfCrypt)
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * The V8 HASH block advertises six ALGO codes beyond SHA-1/2 (0x4..0x7,
 * 0x8..0x9), inferred as SHA3-224/256/384/512 + SHAKE128/256 -- the SVD enum
 * names are placeholders, so this probe settles it against NIST vectors on
 * silicon. It also answers the question that decides the ML-KEM/ML-DSA
 * story: can SHAKE resume a squeeze (second DCAL without INIT continuing
 * the output stream), or is it fixed-length like the STM32MP13?
 *
 * Raw hex is printed; verify host-side (python3 hashlib sha3_256/shake_256).
 */

#include "stm32v8xx.h"
#include "board.h"
#include <stdio.h>

#define ALGO_SHIFT      HASH_CR_ALGO_Pos
#define DATATYPE_8B     (2u << 4)   /* byte-swap input, per wolfSSL usage */
#define WAIT_LIMIT      1000000u

static int wait_flag(volatile uint32_t *reg, uint32_t mask)
{
    uint32_t i;
    for (i = 0; i < WAIT_LIMIT; i++) {
        if ((*reg & mask) != 0u) {
            return 0;
        }
    }
    return -1;
}

static void dump_hr(const char *tag, unsigned int words)
{
    unsigned int i;
    printf("%s:", tag);
    for (i = 0; i < words; i++) {
        printf(" %08lx", (unsigned long)HASH_S->HR[i]);
    }
    printf("\n");
}

/* One fixed-length hash: init with the given ALGO code, absorb len bytes,
 * finalize, dump 'words' output words. Returns 0 on flag-wait success. */
static int probe_hash(const char *tag, uint32_t algo, const char *msg,
    uint32_t len, unsigned int words)
{
    uint32_t w;
    uint32_t i;

    HASH_S->CR = (algo << ALGO_SHIFT) | DATATYPE_8B | HASH_CR_INIT;
    for (i = 0; i < len; i += 4u) {
        uint32_t b0 = (uint32_t)(unsigned char)msg[i];
        uint32_t b1 = (i + 1u < len) ? (uint32_t)(unsigned char)msg[i+1u] : 0u;
        uint32_t b2 = (i + 2u < len) ? (uint32_t)(unsigned char)msg[i+2u] : 0u;
        uint32_t b3 = (i + 3u < len) ? (uint32_t)(unsigned char)msg[i+3u] : 0u;
        w = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        HASH_S->DIN = w;
    }
    HASH_S->STR = (len * 8u) & HASH_STR_NBLW_Msk;
    HASH_S->STR |= HASH_STR_DCAL;
    if (wait_flag(&HASH_S->SR, HASH_SR_DCIS) != 0) {
        printf("%s: TIMEOUT (SR=%08lx)\n", tag, (unsigned long)HASH_S->SR);
        return -1;
    }
    dump_hr(tag, words);
    return 0;
}

int main(void)
{
    int rc;

    board_init();
    printf("\n[v8sha3] HASH SHA-3/SHAKE probe\n");

    RCC_S->AHB3ENR |= RCC_AHB3ENR_HASHEN;
    (void)RCC_S->AHB3ENR;

    /* --- fixed-length SHA-3, ALGO codes 0x4..0x7, vs NIST("abc") --- */
    probe_hash("sha3_224(abc) a4", 0x4u, "abc", 3u, 7u);
    probe_hash("sha3_256(abc) a5", 0x5u, "abc", 3u, 8u);
    probe_hash("sha3_384(abc) a6", 0x6u, "abc", 3u, 12u);
    probe_hash("sha3_512(abc) a7", 0x7u, "abc", 3u, 16u);
    /* empty-message corner */
    probe_hash("sha3_256() a5", 0x5u, "", 0u, 8u);

    /* --- SHAKE, codes 0x8/0x9: first output block --- */
    probe_hash("shake128(abc) a8", 0x8u, "abc", 3u, 16u);
    rc = probe_hash("shake256(abc) a9", 0x9u, "abc", 3u, 16u);

    /* --- THE question: does a second DCAL (no INIT) continue the
     * stream? If HR changes to SHAKE256("abc") bytes 64..127, the
     * squeeze is resumable and PQC offload is on the table. --- */
    if (rc == 0) {
        /* DCIS is sticky from the first finalize; a wait on it now would
         * return instantly and prove nothing. Try to clear it first (W0C
         * attempt), and report whether the second wait was genuine. */
        HASH_S->SR = 0u;
        if ((HASH_S->SR & HASH_SR_DCIS) != 0u) {
            printf("squeeze2: DCIS not clearable without INIT "
                   "(SR=%08lx) -- resume test INCONCLUSIVE by this method\n",
                (unsigned long)HASH_S->SR);
        }
        HASH_S->STR |= HASH_STR_DCAL;
        if (wait_flag(&HASH_S->SR, HASH_SR_DCIS) == 0) {
            dump_hr("shake256 squeeze2", 16u);
        }
        else {
            printf("squeeze2: TIMEOUT (SR=%08lx)\n",
                (unsigned long)HASH_S->SR);
        }
    }

    printf("[v8sha3] done\n");
    while (1) { }
}
