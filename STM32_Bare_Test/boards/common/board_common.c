/* board_common.c - shared SysTick + newlib retarget for STM32_Bare_Test
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * All boards share:
 *   - SysTick_Handler / s_uptime_ms / board_uptime_ms
 *   - newlib _write / __io_putchar that forwards each byte to board_putc
 *
 * Each board's hw_init.c provides:
 *   - board_putc(int) -- the UART-specific byte sink
 *   - board_init() -- clock + GPIO + UART config, then board_common_systick_init
 *   - board_sysclk_hz, board_name
 */

#include <stdint.h>
#include <stdio.h>

#include "board.h"

#if defined(STM32_BOARD_H7) || defined(STM32_BOARD_H723) || \
      defined(STM32_BOARD_H7A3)
    #include "stm32h7xx.h"
#elif defined(STM32_BOARD_H7S3)
    #include "stm32h7rsxx.h"
#elif defined(STM32_BOARD_N657)
    #include "stm32n6xx.h"
#elif defined(STM32_BOARD_H5) || defined(STM32_BOARD_H573)
    #include "stm32h5xx.h"
#elif defined(STM32_BOARD_F207)
    #include "stm32f2xx.h"
#elif defined(STM32_BOARD_F303)
    #include "stm32f3xx.h"
#elif defined(STM32_BOARD_F437) || defined(STM32_BOARD_F439)
    #include "stm32f4xx.h"
#elif defined(STM32_BOARD_F767)
    #include "stm32f7xx.h"
#elif defined(STM32_BOARD_C031)
    #include "stm32c0xx.h"
#elif defined(STM32_BOARD_G071)
    #include "stm32g0xx.h"
#elif defined(STM32_BOARD_G491) || defined(STM32_BOARD_G474)
    #include "stm32g4xx.h"
#elif defined(STM32_BOARD_L4A6)
    #include "stm32l4xx.h"
#elif defined(STM32_BOARD_L552) || defined(STM32_BOARD_L562)
    #include "stm32l5xx.h"
#elif defined(STM32_BOARD_U5) || defined(STM32_BOARD_U585) || \
      defined(STM32_BOARD_U545)
    #include "stm32u5xx.h"
#elif defined(STM32_BOARD_U3)
    #include "stm32u3xx.h"
#elif defined(STM32_BOARD_U083)
    #include "stm32u0xx.h"
#elif defined(STM32_BOARD_WB55)
    #include "stm32wbxx.h"
#elif defined(STM32_BOARD_WL55)
    #include "stm32wlxx.h"
#elif defined(STM32_BOARD_WBA52)
    #include "stm32wbaxx.h"
#elif defined(STM32_BOARD_C562) || defined(STM32_BOARD_C5A3)
    #include "stm32c5xx.h"
#elif defined(STM32_BOARD_V8)
    #include "stm32v8xx.h"
#else
    #error "boards/common/board_common.c: unknown STM32_BOARD_* family"
#endif

/* Each board provides board_putc(int) -- the single UART byte sink. */
extern void board_putc(int ch);

/* Weak CMSIS SystemCoreClock + SystemCoreClockUpdate fallbacks. Boards
 * that ship a system_stm32<f>xx.c (the ST CMSIS device-startup helper)
 * provide strong definitions that win at link time. Boards that don't
 * (c5a3 today) fall back to these stubs so main_test.c still links --
 * the CMSIS-reported SYSCLK print just stays at the board_sysclk_hz
 * intent value, no PLL-failure detection. */
__attribute__((weak)) uint32_t SystemCoreClock = 0;
__attribute__((weak)) void     SystemCoreClockUpdate(void) { }

/* ---- SysTick (1 ms tick) ---------------------------------------------- */
static volatile uint32_t s_uptime_ms;

/* Under BUILD=cubemx the HAL has its own ms tick (uwTick) that advances
 * every SysTick interrupt; the HAL's HAL_GetTick() returns uwTick, and
 * any HAL_* with a timeout (HAL_CRYP_Encrypt etc.) hangs if uwTick is
 * frozen. board_common_systick_init() reconfigures SysTick AFTER
 * HAL_Init runs, replacing HAL's vector-table SysTick handler with ours.
 * To keep HAL's tick alive we forward to HAL_IncTick() here when CUBEMX
 * is the build flavor; BARE builds have no HAL_IncTick symbol so we
 * leave the call out entirely. */
#ifdef STM32_BUILD_CUBEMX
extern void HAL_IncTick(void);
#endif

void SysTick_Handler(void)
{
    s_uptime_ms++;
#ifdef STM32_BUILD_CUBEMX
    HAL_IncTick();
#endif
}

void board_common_systick_init(uint32_t sysclk_hz)
{
    SysTick->LOAD = (sysclk_hz / 1000u) - 1u;
    SysTick->VAL  = 0;
    SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk |
                    SysTick_CTRL_TICKINT_Msk   |
                    SysTick_CTRL_ENABLE_Msk;
}

uint32_t board_uptime_ms(void)
{
    return s_uptime_ms;
}

/* ---- shared GPIO-AF and USART init ----------------------------------- */
/* Helpers below target the modern STM32 USART layout (ISR / TDR /
 * TEACK / REACK). The older F2 / F4 family uses SR / DR / TC instead;
 * boards on that IP open-code their own uart_init() and never call
 * these helpers. The CMSIS header for F2 / F4 lacks USART_ISR_TEACK,
 * so we gate the entire block on that symbol to keep board_common.c
 * compilable across the full board matrix. */
#ifdef USART_ISR_TEACK

/* Configure two adjacent GPIO pins as AF on a modern STM32 GPIO bank
 * (MODER + OSPEEDR + AFR[2] shape). gpio_v is a GPIO_TypeDef pointer
 * (the family typedef is in scope here via the include above). */
void board_common_uart_pin_init(void *gpio_v, uint8_t tx_pin,
    uint8_t rx_pin, uint8_t af)
{
    GPIO_TypeDef *gpio = (GPIO_TypeDef *)gpio_v;
    uint32_t af_mask;
    uint32_t af_val;
    uint8_t  tx_bank;
    uint8_t  rx_bank;
    uint8_t  tx_off;
    uint8_t  rx_off;

    /* DSB ensures the caller's RCC->AHB?ENR |= GPIO?EN write has
     * propagated before we touch GPIO registers. Without this the very
     * first MODER access can be silently dropped because the GPIO
     * clock domain has not yet enabled. */
    __DSB();

    /* MODER: 2 bits per pin; clear, then set AF (10b). */
    gpio->MODER &= ~((3u << (tx_pin * 2u)) | (3u << (rx_pin * 2u)));
    gpio->MODER |=  ((2u << (tx_pin * 2u)) | (2u << (rx_pin * 2u)));

    /* OSPEEDR: 2 bits per pin; very-high (11b). */
    gpio->OSPEEDR |= ((3u << (tx_pin * 2u)) | (3u << (rx_pin * 2u)));

    /* AFR[]: 4 bits per pin. Pins 0..7 -> AFR[0], pins 8..15 -> AFR[1]. */
    tx_bank = (uint8_t)(tx_pin >> 3);
    rx_bank = (uint8_t)(rx_pin >> 3);
    tx_off  = (uint8_t)((tx_pin & 7u) * 4u);
    rx_off  = (uint8_t)((rx_pin & 7u) * 4u);
    af_val  = (uint32_t)af & 0xFu;

    af_mask = (0xFu << tx_off);
    gpio->AFR[tx_bank] = (gpio->AFR[tx_bank] & ~af_mask) | (af_val << tx_off);
    af_mask = (0xFu << rx_off);
    gpio->AFR[rx_bank] = (gpio->AFR[rx_bank] & ~af_mask) | (af_val << rx_off);
}

/* Bring up a standard USART (USART_TypeDef shape: CR1 / BRR / ISR /
 * TDR / TEACK / REACK). Caller has enabled the kernel clock. */
void board_common_uart_basic_init(void *usart_v, uint32_t pclk_hz,
    uint32_t baud)
{
    USART_TypeDef *usart = (USART_TypeDef *)usart_v;

    /* DSB ensures the caller's APB?ENR |= USARTxEN write has propagated
     * before we touch USART registers. */
    __DSB();

    usart->CR1 = 0;
    usart->BRR = pclk_hz / baud;
    usart->CR1 = USART_CR1_TE | USART_CR1_RE | USART_CR1_UE;

    while ((usart->ISR & (USART_ISR_TEACK | USART_ISR_REACK)) !=
           (USART_ISR_TEACK | USART_ISR_REACK)) {
        /* spin */
    }
}

#endif /* USART_ISR_TEACK */

/* ---- newlib printf retarget ------------------------------------------ */
#ifdef __GNUC__
int __io_putchar(int ch)
{
    if (ch == '\n') {
        board_putc('\r');
    }
    board_putc(ch);
    return ch;
}

int _write(int file, char *ptr, int len)
{
    int i;
    (void)file;
    for (i = 0; i < len; i++) {
        __io_putchar((unsigned char)ptr[i]);
    }
    return len;
}
#endif

/* ---- Exception / fault handlers --------------------------------------
 * Default vendor startup_*.s provides Default_Handler as a `b .` busy
 * loop -- any hard fault / NMI / mem manage / bus fault appears as a
 * silent lock-up. Override here so we print enough state to triage:
 *   - The 8-word exception frame from MSP (R0, R1, R2, R3, R12, LR, PC, xPSR)
 *   - SCB->CFSR / HFSR / MMFAR / BFAR (Cortex-M3/4/7/33; not all valid on M0+)
 * The handlers are written so they're safe to call before SysTick init.
 *
 * To use, the per-board startup must NOT define these as `WEAK` to its
 * own Default_Handler -- the GCC startup_stm32*.s files declare them
 * with `.weak`, so our strong definitions here override automatically.
 *
 * Cortex-M0/M0+ have no CFSR / HFSR / MMFAR / BFAR -- skip those reads
 * on architectures without them (gated on __CORTEX_M >= 3). */
#if !defined(__ARM_ARCH_6M__)
/* Externally-visible (naked asm trampoline jumps to it by name). Weak so a
 * board can override it -- e.g. to record registers with raw stores before
 * attempting printf, which itself hangs if the fault was taken inside
 * printf/malloc. */
void wc_fault_dump(uint32_t *frame, const char *which);
__attribute__((weak)) void wc_fault_dump(uint32_t *frame, const char *which)
{
    /* Stack frame on entry: R0,R1,R2,R3,R12,LR,PC,xPSR */
    printf("\n[FAULT] %s\n", which);
    printf("  R0  = 0x%08lx  R1  = 0x%08lx  R2 = 0x%08lx  R3 = 0x%08lx\n",
        (unsigned long)frame[0], (unsigned long)frame[1],
        (unsigned long)frame[2], (unsigned long)frame[3]);
    printf("  R12 = 0x%08lx  LR  = 0x%08lx  PC = 0x%08lx  PSR= 0x%08lx\n",
        (unsigned long)frame[4], (unsigned long)frame[5],
        (unsigned long)frame[6], (unsigned long)frame[7]);
#ifdef SCB_CFSR_MEMFAULTSR_Pos
    printf("  CFSR  = 0x%08lx  HFSR = 0x%08lx\n",
        (unsigned long)SCB->CFSR, (unsigned long)SCB->HFSR);
    printf("  MMFAR = 0x%08lx  BFAR = 0x%08lx\n",
        (unsigned long)SCB->MMFAR, (unsigned long)SCB->BFAR);
#endif
    /* Halt -- a hard fault means the chip state is suspect, don't return. */
    for (;;) { }
}

/* Naked trampoline: capture MSP or PSP based on EXC_RETURN.SPSEL,
 * pass to wc_fault_dump as the stack-frame pointer. */
#define WC_FAULT_HANDLER(name, label)                                   \
    __attribute__((naked)) void name(void)                              \
    {                                                                   \
        __asm volatile (                                                \
            "tst lr, #4         \n" /* EXC_RETURN bit 2 = SPSEL */      \
            "ite eq             \n"                                     \
            "mrseq r0, msp      \n"                                     \
            "mrsne r0, psp      \n"                                     \
            "ldr r1, =1f        \n"                                     \
            "b wc_fault_dump    \n"                                     \
            "1: .asciz \"" label "\"\n"                                 \
            ".align 2           \n"                                     \
        );                                                              \
    }

WC_FAULT_HANDLER(HardFault_Handler,   "HardFault")
WC_FAULT_HANDLER(MemManage_Handler,   "MemManage")
WC_FAULT_HANDLER(BusFault_Handler,    "BusFault")
WC_FAULT_HANDLER(UsageFault_Handler,  "UsageFault")
#else
/* Cortex-M0/M0+: no CFSR/HFSR, no Thumb-2 ITE -- minimal halt+spin. */
void HardFault_Handler(void)
{
    printf("\n[FAULT] HardFault (M0/M0+; no CFSR)\n");
    for (;;) { }
}
#endif

/* ---- Stack + heap tracking (STACK=1) ---------------------------------- */
/* When the Makefile is invoked with STACK=1, the user_settings.h block    */
/* enables wolfssl's HAVE_STACK_SIZE_VERBOSE + WOLFSSL_TRACK_MEMORY_VERBOSE */
/* + USE_WOLFSSL_MEMORY, and wolfcrypt/benchmark/benchmark.c emits per-    */
/* algorithm peak stack + peak heap CSV columns. The wolfssl helper        */
/* StackSizeHWMReset() (in mem_track.h) walks the painted stack region to  */
/* find the high-water mark; it needs the four globals below to be set to  */
/* the actual stack carve from the board's linker script.                  */
#if defined(STM32_BARE_STACK_TRACK)
    #include <string.h>
    #include "wolfssl/wolfcrypt/mem_track.h"

    /* Linker-script-provided stack bounds. Every boards/<x>/*_flat.ld     */
    /* defines _estack at the top of RAM and _Min_Stack_Size as the carve  */
    /* size; the symbol VALUE is what we read via address-of.              */
    extern uint32_t _estack;
    extern uint32_t _Min_Stack_Size;

    /* wolfssl globals -- declared THREAD_LS_T in mem_track.h, which       */
    /* resolves to empty for single-threaded bare-metal builds.            */
    extern unsigned char *StackSizeCheck_myStack;
    extern size_t         StackSizeCheck_stackSize;
    extern size_t         StackSizeCheck_stackSizeHWM;
    extern size_t        *StackSizeCheck_stackSizeHWM_ptr;
    extern void          *StackSizeCheck_stackOffsetPointer;

    void board_common_stack_track_init(void *frame_ptr)
    {
        uint32_t stack_top;
        uint32_t stack_sz;
        unsigned char *base;

        stack_top = (uint32_t)(uintptr_t)&_estack;
        stack_sz  = (uint32_t)(uintptr_t)&_Min_Stack_Size;
        base      = (unsigned char *)(uintptr_t)(stack_top - stack_sz);

        StackSizeCheck_myStack            = base;
        StackSizeCheck_stackSize          = (size_t)stack_sz;
        StackSizeCheck_stackSizeHWM       = 0;
        StackSizeCheck_stackSizeHWM_ptr   = &StackSizeCheck_stackSizeHWM;
        StackSizeCheck_stackOffsetPointer = frame_ptr;

        /* Paint the region below the caller's frame with STACK_CHECK_VAL. */
        (void)StackSizeHWMReset();
    }
#endif
