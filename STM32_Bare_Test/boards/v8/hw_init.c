/* hw_init.c - NUCLEO-V873XJ (STM32V873XJ, Cortex-M85) bring-up
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * The VCP USART is not identified yet (the SVD carries no pin muxing and the
 * factory image clocks no USART), so board_putc() writes a RAM ring buffer
 * the host reads over SWD instead of driving a UART.
 *
 * Addressing uses the Secure aliases: the part has no TZEN option byte, both
 * flash-bank watermarks are secure and BOOTADD is 0x18000000, so it always
 * runs Secure. A CMSIS header built without -mcmse resolves the plain names
 * to the non-secure aliases, which RIFSC blocks.
 */

#include "stm32v8xx.h"
#include "board.h"
#include <stdio.h>

/* Defined weak in boards/common/board_common.c; no system_stm32v8xx.c here. */
extern uint32_t SystemCoreClock;

#ifndef V8_SYSCLK_HZ
/* MEASURED, not read from RCC: the PLL is not configured here and no
 * reference manual is public, so the clock was calibrated against host
 * wall-clock (benchmark self-reported 66.0 s while really taking 16.8 s,
 * ratio 3.93 against the assumed 64 MHz). benchmark.c times with SysTick,
 * so a wrong value here silently scales every reported rate. Note
 * CPU_FREQ_BOOST is disabled in the option bytes, so this is not the
 * part's 800 MHz rate. */
#define V8_SYSCLK_HZ 250000000u
#endif

/* Cache enables, individually overridable from the build. */
#ifndef V8_ENABLE_ICACHE
#define V8_ENABLE_ICACHE 1
#endif
#ifndef V8_ENABLE_DCACHE
#define V8_ENABLE_DCACHE 0
#endif
/* Explicit MPU memory attributes. The Armv8-M default map nominally makes
 * flash and SRAM cacheable, but the D-cache does not behave with it on this
 * part, so state the attributes rather than inherit them. */
#ifndef V8_ENABLE_MPU
#define V8_ENABLE_MPU 0
#endif

#ifndef V8_CONSOLE_SIZE
#define V8_CONSOLE_SIZE 16384u
#endif

#define V8_CONSOLE_MAGIC 0x56384C47u  /* 'V8LG' */

/* Read back over SWD:
 *   arm-none-eabi-nm app.elf | grep v8_console
 *   STM32_Programmer_CLI -c port=swd sn=<SN> mode=UR -r32 <addr> <len>
 * 'wrote' keeps counting past V8_CONSOLE_SIZE so truncation is detectable. */
typedef struct {
    volatile uint32_t magic;
    volatile uint32_t wrote;
    volatile uint32_t overflow;
    volatile uint32_t boots;     /* increments per run - detects re-runs */
    volatile uint8_t  buf[V8_CONSOLE_SIZE];
} v8_console_t;

/* .noinit so a mode=UR connect (which resets the part) does not wipe the log
 * from the run we are trying to read. aligned(8) is sufficient: CMSIS 6.x
 * SCB_CleanDCache_by_Addr covers partial lines (DCCMVAC ignores bits 4:0),
 * and raising to aligned(32) changes board_putc codegen, which re-triggers
 * the placement-sensitive freeze (see board.mk). */
volatile v8_console_t v8_console
    __attribute__((used, aligned(8), section(".noinit")));

void board_putc(int ch)
{
    uint32_t idx;

    idx = v8_console.wrote;
    if (idx < V8_CONSOLE_SIZE) {
        v8_console.buf[idx] = (uint8_t)ch;
    }
    else {
        v8_console.overflow = 1u;
    }
    v8_console.wrote = idx + 1u;

    /* The console is read back over SWD, and the debug access port reads
     * through the bus -- it does not snoop the D-cache. With the D-cache
     * enabled a dirty line would leave the host reading stale bytes, which
     * looks exactly like the log having stopped. Clean the header and the
     * touched cache line so what the host sees is what we wrote. */
    if ((SCB->CCR & SCB_CCR_DC_Msk) != 0u) {
        SCB_CleanDCache_by_Addr((uint32_t *)(void *)&v8_console, 32);
        if (idx < V8_CONSOLE_SIZE) {
            SCB_CleanDCache_by_Addr(
                (uint32_t *)(void *)&v8_console.buf[idx & ~((uint32_t)31)], 32);
        }
    }
}

/* Raw fault record: plain word stores, no printf, so it survives a fault
 * taken inside printf/malloc (where the shared WC_FAULT_HANDLER's own printf
 * would hang silently). magic 'V8FR' when written. Read over SWD:
 *   nm app.elf | grep v8_fault ; -r32 <addr> 48 */
#define V8_FAULT_MAGIC 0x56384652u

typedef struct {
    volatile uint32_t magic;
    volatile uint32_t r0, r1, r2, r3, r12, lr, pc, xpsr;
    volatile uint32_t cfsr, hfsr, mmfar, bfar;
} v8_fault_t;
volatile v8_fault_t v8_fault __attribute__((used, aligned(8), section(".noinit")));

__attribute__((used)) void v8_fault_record(uint32_t *frame)
{
    v8_fault.r0    = frame[0];
    v8_fault.r1    = frame[1];
    v8_fault.r2    = frame[2];
    v8_fault.r3    = frame[3];
    v8_fault.r12   = frame[4];
    v8_fault.lr    = frame[5];
    v8_fault.pc    = frame[6];
    v8_fault.xpsr  = frame[7];
    v8_fault.cfsr  = SCB->CFSR;
    v8_fault.hfsr  = SCB->HFSR;
    v8_fault.mmfar = SCB->MMFAR;
    v8_fault.bfar  = SCB->BFAR;
    v8_fault.magic = V8_FAULT_MAGIC;
}

/* Override the shared handler: raw-record first (survives a fault taken
 * inside printf/malloc), then attempt the readable printf dump. */
void wc_fault_dump(uint32_t *frame, const char *which)
{
    v8_fault_record(frame);
    printf("\n[FAULT] %s pc=0x%08lx lr=0x%08lx cfsr=0x%08lx\n",
        which, (unsigned long)frame[6], (unsigned long)frame[5],
        (unsigned long)SCB->CFSR);
    for (;;) { }
}

/* Fault handlers come from boards/common/board_common.c (WC_FAULT_HANDLER),
 * which printfs CFSR/HFSR and the stacked PC -- and printf lands in
 * v8_console, so a fault is visible in the SWD read-back. Note a true
 * LOCKUP (double fault, e.g. a stack overflow that corrupts the exception
 * frame) runs no handler at all, so an abrupt end to the log with no
 * [FAULT] line is itself diagnostic. */

static void v8_dump_rcc(void);
#ifdef V8_TRY_PLL
static uint32_t v8_pll_hz = 0u;
#endif

void board_init(void)
{
    /* Fresh log per run; boots counts how many times we came through here so
     * a stale buffer cannot be mistaken for a live one. */
    v8_console.boots    = (v8_console.magic == V8_CONSOLE_MAGIC)
                          ? v8_console.boots + 1u : 1u;
    v8_console.magic    = V8_CONSOLE_MAGIC;
    v8_console.wrote    = 0u;
    v8_console.overflow = 0u;

    /* The boot ROM hands off with its own MPU configuration in place; clear
     * it so our map applies. */
    ARM_MPU_Disable();

#if V8_ENABLE_MPU
    /* attr0 Normal write-back R/W-allocate, attr1 Device-nGnRE. */
    ARM_MPU_SetMemAttr(0u, ARM_MPU_ATTR(
        ARM_MPU_ATTR_MEMORY_(1u, 1u, 1u, 1u),
        ARM_MPU_ATTR_MEMORY_(1u, 1u, 1u, 1u)));
    ARM_MPU_SetMemAttr(1u, ARM_MPU_ATTR(
        ARM_MPU_ATTR_DEVICE, ARM_MPU_ATTR_DEVICE_nGnRE));

    /* Secure flash: executable, read-only, cacheable. */
    ARM_MPU_SetRegion(0u,
        ARM_MPU_RBAR(0x18000000u, ARM_MPU_SH_NON, 1u, 1u, 0u),
        ARM_MPU_RLAR(0x183FFFFFu, 0u));
    /* Secure AXI SRAM: read/write, execute-never, cacheable. */
    ARM_MPU_SetRegion(1u,
        ARM_MPU_RBAR(0x34000000u, ARM_MPU_SH_NON, 0u, 1u, 1u),
        ARM_MPU_RLAR(0x340FFFFFu, 0u));
    /* Peripherals (both aliases): Device, execute-never. */
    ARM_MPU_SetRegion(2u,
        ARM_MPU_RBAR(0x40000000u, ARM_MPU_SH_NON, 0u, 1u, 1u),
        ARM_MPU_RLAR(0x5FFFFFFFu, 1u));

    /* PRIVDEFENA so anything not covered falls back to the default map. */
    ARM_MPU_Enable(MPU_CTRL_PRIVDEFENA_Msk);
#endif

    /* Take faults in our own handlers rather than escalating to a ROM
     * lockup, so a bad access is debuggable. */
    SCB->SHCSR |= (SCB_SHCSR_BUSFAULTENA_Msk |
                   SCB_SHCSR_MEMFAULTENA_Msk |
                   SCB_SHCSR_USGFAULTENA_Msk);

    /* Full access to CP10/CP11 (FPU). */
    SCB->CPACR |= ((3u << 20) | (3u << 22));
    __DSB();
    __ISB();

    /* I-cache on, D-cache off. Measured on this board: I-cache is worth
     * 1.4x to 2.7x (SHA-256 1.11 -> 2.75 MiB/s, ECDSA P-256 sign 324.8 ->
     * 122.5 ms). D-cache enable returns and board_init() completes, but the
     * first printf then emits nothing; explicit MPU attributes did not help.
     * Override either with -DV8_ENABLE_ICACHE / -DV8_ENABLE_DCACHE. */
#if V8_ENABLE_ICACHE
    SCB_EnableICache();
#endif
#if V8_ENABLE_DCACHE
    SCB_EnableDCache();
#endif

    /* 48 MHz generator for the RNG (V8 has no RNG kernel-clock mux in
     * CCIPR1..12; the MCG48 block is the source). Enable and wait ready,
     * bounded, before wolfCrypt touches the RNG. */
    RCC_S->CR |= RCC_CR_MCG48MCKEN;
    {
        uint32_t t0;
        for (t0 = 0; t0 < 1000000u; t0++) {
            if ((RCC_S->SR & RCC_SR_MCG48RDY) != 0u) {
                break;
            }
        }
    }

#ifdef V8_TRY_PLL
    /* Experimental PLL bring-up (no RM: N6-style +1 encodings assumed).
     * mcg_48m ref: DIVM=2 (/3 -> 16 MHz), DIVN=61 (x62 -> 992 MHz VCO),
     * DIVP=1 (/2 -> 496 MHz). Fail-safe: bounded lock wait; on timeout we
     * stay on MCG at 250 MHz and say so. Run from SRAM so flash wait-states
     * cannot bite at the higher clock. */
    {
        uint32_t i;
#ifndef V8_PLL_VCORGE
#define V8_PLL_VCORGE 0u
#endif
        RCC_S->PLL1CFGR = (2u << 24) | ((uint32_t)V8_PLL_VCORGE << 20)
                        | (1u << 16) | (1u << 8); /* M, VCORGE, SRC, PEN */
#ifndef V8_PLL_DIVN
#define V8_PLL_DIVN 61u   /* x62: 16 MHz ref -> 992 MHz VCO -> /2 = 496 MHz */
#endif
#ifndef V8_PLL_OUT_HZ
#define V8_PLL_OUT_HZ 496000000u
#endif
        RCC_S->PLL1DIVR1 = ((uint32_t)V8_PLL_DIVN << 16);
#ifndef V8_PLL_DIVP
#define V8_PLL_DIVP 1u
#endif
        RCC_S->PLL1DIVR2 = ((uint32_t)V8_PLL_DIVP << 8) | (1u << 24);
        RCC_S->CR |= (1u << 24);                       /* PLL1ON */
        for (i = 0; i < 2000000u; i++) {
            if ((RCC_S->SR & (1u << 24)) != 0u) {      /* PLL1RDY */
                break;
            }
        }
        if ((RCC_S->SR & (1u << 24)) != 0u) {
            RCC_S->CFGR1 = (RCC_S->CFGR1 & ~(3u << 24)) | (2u << 24);
            for (i = 0; i < 100000u; i++) {
                if (((RCC_S->CFGR1 >> 28) & 3u) == 2u) {
                    break;
                }
            }
            v8_pll_hz = (((RCC_S->CFGR1 >> 28) & 3u) == 2u)
                        ? V8_PLL_OUT_HZ : 0u;
        }
        else {
            v8_pll_hz = 0u;
        }
    }
#endif

    board_common_systick_init(board_sysclk_hz());
    v8_dump_rcc();
#ifdef V8_TRY_PLL
    printf("[pll] %s (SR=%08lx CFGR1=%08lx)\n",
        (v8_pll_hz != 0u) ? "LOCKED+SWITCHED (PLL)" : "fallback MCG 250 MHz",
        (unsigned long)RCC_S->SR, (unsigned long)RCC_S->CFGR1);
#endif

    /* v8 ships no system_stm32v8xx.c, so SystemCoreClock would stay at the
     * weak 0 fallback. PLL builds take board_sysclk_hz() so a locked PLL is
     * reflected; the default arm stays a constant store to keep codegen
     * identical to the hardware-validated build (see the placement note in
     * board.mk). */
#ifdef V8_TRY_PLL
    SystemCoreClock = board_sysclk_hz();
#else
    SystemCoreClock = V8_SYSCLK_HZ;
#endif

}

/* One-shot RCC state dump (raw hex, decode against STM32V873.svd). */
static void v8_dump_rcc(void)
{
    printf("[rcc] CR=%08lx SR=%08lx CFGR1=%08lx CFGR2=%08lx\n",
        (unsigned long)RCC_S->CR, (unsigned long)RCC_S->SR,
        (unsigned long)RCC_S->CFGR1, (unsigned long)RCC_S->CFGR2);
    printf("[rcc] PLL1CFGR=%08lx DIVR1=%08lx DIVR2=%08lx DIVR3=%08lx\n",
        (unsigned long)RCC_S->PLL1CFGR, (unsigned long)RCC_S->PLL1DIVR1,
        (unsigned long)RCC_S->PLL1DIVR2, (unsigned long)RCC_S->PLL1DIVR3);
    printf("[rcc] PLL2CFGR=%08lx P2DIVR1=%08lx\n",
        (unsigned long)RCC_S->PLL2CFGR, (unsigned long)RCC_S->PLL2DIVR1);
}

uint32_t board_sysclk_hz(void)
{
#ifdef V8_TRY_PLL
    if (v8_pll_hz != 0u) {
        return v8_pll_hz;
    }
#endif
    return V8_SYSCLK_HZ;
}

const char *board_name(void)
{
    return "NUCLEO-V873XJ (STM32V873XJ Cortex-M85)";
}
