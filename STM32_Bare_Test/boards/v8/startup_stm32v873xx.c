/* startup_stm32v873xx.c - minimal C startup for NUCLEO-V873XJ (Cortex-M85)
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Linked and run in Secure state: the part has no TZEN option byte, both
 * flash-bank watermarks are secure and BOOTADD is 0x18000000. Only SysTick
 * is wired; other interrupts land in Default_Handler.
 */

#include "stm32v8xx.h"

extern uint32_t __StackTop;
extern uint32_t __StackLimit;
/* __copy_table_* / __zero_table_* are declared by CMSIS (cmsis_gcc_m.h) as
 * const __copy_table_t / __zero_table_t; re-declaring them as uint32_t here
 * is a type-qualifier conflict, so use the CMSIS types directly. */

extern int  main(void);
/* CMSIS __cmsis_start: processes the linker's copy/zero tables then enters
 * the program. It declares __copy_table_t / __zero_table_t and the
 * __copy_table_* / __zero_table_* symbols in its own scope, so do not
 * re-declare them here. */
extern __NO_RETURN void __PROGRAM_START(void);

void Reset_Handler(void);
void Default_Handler(void);

/* Core exceptions: weak so a board/test file can override any of them. */
void NMI_Handler(void)        __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void)  __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void)  __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void)   __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SecureFault_Handler(void)__attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void)        __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler(void)   __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void)     __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void)    __attribute__((weak, alias("Default_Handler")));

/* 16 core entries + room for every device IRQ in STM32V873.svd. */
#define V8_NUM_DEVICE_IRQ 240

typedef void (*vector_t)(void);

const vector_t __vectors[16 + V8_NUM_DEVICE_IRQ]
    __attribute__((section(".vectors"), used)) = {
    (vector_t)(&__StackTop),
    Reset_Handler,
    NMI_Handler,
    HardFault_Handler,
    MemManage_Handler,
    BusFault_Handler,
    UsageFault_Handler,
    SecureFault_Handler,
    0, 0, 0,
    SVC_Handler,
    DebugMon_Handler,
    0,
    PendSV_Handler,
    SysTick_Handler,
    /* Rest default to 0; the NVIC is never enabled for them, so a stray
     * interrupt traps in HardFault rather than branching wild. */
};

void Default_Handler(void)
{
    while (1) {
        /* spin - attach a debugger and read the stacked PC */
    }
}

/* Naked: a jump-started entry (SRAM load via debugger, no vector fetch)
 * arrives with garbage SP, so not even a prologue push is safe until MSP
 * is ours. Set stack in asm, then continue in C. */
__attribute__((naked)) void Reset_Handler(void)
{
    __asm volatile(
        "movs r0, #0            \n"
        "msr  msplim, r0        \n"
        "ldr  r0, =__StackTop   \n"
        "msr  msp, r0           \n"
        "ldr  r0, =__StackLimit \n"
        "msr  msplim, r0        \n"
        "b    Reset_Continue    \n");
}

__attribute__((used)) void Reset_Continue(void)
{
    SCB->VTOR = (uint32_t)&__vectors[0];
    __DSB();
    __ISB();

    /* Copies .data, zeroes .bss, then enters the program. */
    __PROGRAM_START();
}
