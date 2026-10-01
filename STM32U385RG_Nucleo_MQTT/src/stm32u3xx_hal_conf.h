/* stm32u3xx_hal_conf.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * Minimal STM32U3 HAL configuration for the STM32U385RG_Nucleo_MQTT demo.
 * Picked up by stm32u3xx_hal.h (#include "stm32u3xx_hal_conf.h").
 *
 * Only the modules this demo uses are pulled in. CRYP / HASH headers
 * are always included; the matching HAL .c sources are only compiled
 * for CONFIG=hw via the Makefile, so unused symbols stay unreferenced
 * and gc-sections drops the dead code.
 */
#ifndef STM32U3XX_HAL_CONF_H
#define STM32U3XX_HAL_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stm32u3xx_hal_def.h"

/* ---------------- Module selection ---------------- */
#define HAL_MODULE_ENABLED
#define HAL_CORTEX_MODULE_ENABLED
#define HAL_DMA_MODULE_ENABLED
#define HAL_EXTI_MODULE_ENABLED
#define HAL_FLASH_MODULE_ENABLED
#define HAL_GPIO_MODULE_ENABLED
#define HAL_ICACHE_MODULE_ENABLED
#define HAL_PWR_MODULE_ENABLED
#define HAL_RCC_MODULE_ENABLED
#define HAL_UART_MODULE_ENABLED
#define HAL_RNG_MODULE_ENABLED
#define HAL_CRYP_MODULE_ENABLED
#define HAL_HASH_MODULE_ENABLED
#ifdef WOLFSSL_STM32_PKA
    #define HAL_PKA_MODULE_ENABLED
#endif

/* ---------------- Oscillator values ---------------- */
#if !defined(HSE_VALUE)
    #define HSE_VALUE                       (16000000UL)
#endif
#if !defined(HSE_STARTUP_TIMEOUT)
    #define HSE_STARTUP_TIMEOUT             (100UL)
#endif
#if !defined(MSI_VALUE)
    #define MSI_VALUE                       (4000000UL)
#endif
#if !defined(MSIRC0_VALUE)
    #define MSIRC0_VALUE                    (96000000UL)
#endif
#if !defined(MSIRC1_VALUE)
    #define MSIRC1_VALUE                    (24000000UL)
#endif
#if !defined(HSI_VALUE)
    #define HSI_VALUE                       (16000000UL)
#endif
#if !defined(HSI48_VALUE)
    #define HSI48_VALUE                     (48000000UL)
#endif
#if !defined(LSI_VALUE)
    #define LSI_VALUE                       (32000UL)
#endif
#if !defined(LSI_STARTUP_TIMEOUT)
    #define LSI_STARTUP_TIMEOUT             (130UL)
#endif
#if !defined(LSE_VALUE)
    #define LSE_VALUE                       (32768UL)
#endif
#if !defined(LSE_STARTUP_TIMEOUT)
    #define LSE_STARTUP_TIMEOUT             (5000UL)
#endif
#if !defined(EXTERNAL_SAI1_CLOCK_VALUE)
    #define EXTERNAL_SAI1_CLOCK_VALUE       (48000UL)
#endif
#if !defined(EXTERNAL_SAI2_CLOCK_VALUE)
    #define EXTERNAL_SAI2_CLOCK_VALUE       (48000UL)
#endif

/* ---------------- System config ------------------- */
#define VDD_VALUE                       (3300UL)
#define TICK_INT_PRIORITY               ((1UL<<__NVIC_PRIO_BITS) - 1UL)
#define USE_RTOS                        0U
#define PREFETCH_ENABLE                 1U

/* ---------------- HAL feature toggles ------------- */
#define USE_HAL_CRYP_REGISTER_CALLBACKS 0U
#define USE_HAL_HASH_REGISTER_CALLBACKS 0U
#define USE_HAL_RNG_REGISTER_CALLBACKS  0U
#define USE_HAL_UART_REGISTER_CALLBACKS 0U
#define USE_HAL_DMA_REGISTER_CALLBACKS  0U
#define USE_SPI_CRC                     0U

/* ---------------- Module headers ------------------ */
#ifdef HAL_RCC_MODULE_ENABLED
    #include "stm32u3xx_hal_rcc.h"
#endif
#ifdef HAL_GPIO_MODULE_ENABLED
    #include "stm32u3xx_hal_gpio.h"
#endif
#ifdef HAL_DMA_MODULE_ENABLED
    #include "stm32u3xx_hal_dma.h"
#endif
#ifdef HAL_CORTEX_MODULE_ENABLED
    #include "stm32u3xx_hal_cortex.h"
#endif
#ifdef HAL_EXTI_MODULE_ENABLED
    #include "stm32u3xx_hal_exti.h"
#endif
#ifdef HAL_FLASH_MODULE_ENABLED
    #include "stm32u3xx_hal_flash.h"
#endif
#ifdef HAL_ICACHE_MODULE_ENABLED
    #include "stm32u3xx_hal_icache.h"
#endif
#ifdef HAL_PWR_MODULE_ENABLED
    #include "stm32u3xx_hal_pwr.h"
#endif
#ifdef HAL_UART_MODULE_ENABLED
    #include "stm32u3xx_hal_uart.h"
#endif
#ifdef HAL_RNG_MODULE_ENABLED
    #include "stm32u3xx_hal_rng.h"
#endif
#ifdef HAL_HASH_MODULE_ENABLED
    #include "stm32u3xx_hal_hash.h"
#endif
#ifdef HAL_CRYP_MODULE_ENABLED
    #include "stm32u3xx_hal_cryp.h"
#endif
#ifdef HAL_PKA_MODULE_ENABLED
    #include "stm32u3xx_hal_pka.h"
#endif

/* ---------------- assert_param() ------------------ */
#ifdef USE_FULL_ASSERT
    #include "stm32_assert.h"
#else
    #define assert_param(expr) ((void)0U)
#endif

#ifdef __cplusplus
}
#endif

#endif /* STM32U3XX_HAL_CONF_H */
