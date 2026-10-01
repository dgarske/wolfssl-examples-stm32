/* hw_init.c
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
 * HW init for STM32U385RG — clocks, RNG (+ HASH/CRYP for `hw` variant).
 *
 * SystemClock_Config() drives SYSCLK directly from MSIS RC0 / DIV1 = 96 MHz
 * (no PLL — STM32U3 MSIS RC0 reaches 96 MHz natively when EPOD booster is
 * enabled). HCLK = SYSCLK, PCLKx not divided.
 */

#include "stm32u3xx_hal.h"
#include <stdio.h>

RNG_HandleTypeDef   hrng;
#ifdef WOLFSSL_STM32_HASH
HASH_HandleTypeDef  hhash;
#endif
#ifdef WOLFSSL_STM32_AES
CRYP_HandleTypeDef  hcryp;
#endif

static void SystemClock_Config(void)
{
    RCC_OscInitTypeDef osc = {0};
    RCC_ClkInitTypeDef clk = {0};

    if (HAL_PWREx_ConfigSupply(PWR_SMPS_SUPPLY) != HAL_OK) {
        goto fail;
    }
    if (HAL_RCCEx_EpodBoosterClkConfig(RCC_EPODBOOSTER_SOURCE_MSIS,
                                       RCC_EPODBOOSTER_DIV1) != HAL_OK) {
        goto fail;
    }
    if (HAL_PWREx_EnableEpodBooster() != HAL_OK) {
        goto fail;
    }
    if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1)
            != HAL_OK) {
        goto fail;
    }

    __HAL_FLASH_SET_LATENCY(FLASH_LATENCY_2);

    osc.OscillatorType = RCC_OSCILLATORTYPE_MSIS;
    osc.MSISState      = RCC_MSI_ON;
    osc.MSISSource     = RCC_MSI_RC0;
    osc.MSISDiv        = RCC_MSI_DIV1;
    if (HAL_RCC_OscConfig(&osc) != HAL_OK) {
        goto fail;
    }

    clk.ClockType      = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK
                       | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2
                       | RCC_CLOCKTYPE_PCLK3;
    clk.SYSCLKSource   = RCC_SYSCLKSOURCE_MSIS;
    clk.AHBCLKDivider  = RCC_SYSCLK_DIV1;
    clk.APB1CLKDivider = RCC_HCLK_DIV1;
    clk.APB2CLKDivider = RCC_HCLK_DIV1;
    clk.APB3CLKDivider = RCC_HCLK_DIV1;
    if (HAL_RCC_ClockConfig(&clk, FLASH_LATENCY_2) != HAL_OK) {
        goto fail;
    }
    return;

fail:
    while (1) { __NOP(); }
}

static void ICache_Init(void)
{
    if (HAL_ICACHE_ConfigAssociativityMode(ICACHE_1WAY) != HAL_OK) {
        return;
    }
    (void)HAL_ICACHE_Enable();
}

static void RNG_Init(void)
{
    /* HSI48 is enabled by default on U385 via the RCC driver; RNG clocks off it */
    RCC_PeriphCLKInitTypeDef pclk = {0};
    pclk.PeriphClockSelection = RCC_PERIPHCLK_RNG;
    pclk.RngClockSelection    = RCC_RNGCLKSOURCE_HSI48;
    (void)HAL_RCCEx_PeriphCLKConfig(&pclk);

    __HAL_RCC_HSI48_ENABLE();
    while (__HAL_RCC_GET_FLAG(RCC_FLAG_HSI48RDY) == 0U) { /* wait */ }

    __HAL_RCC_RNG_CLK_ENABLE();
    hrng.Instance = RNG;
    if (HAL_RNG_Init(&hrng) != HAL_OK) {
        while (1) { __NOP(); }
    }
}

#ifdef WOLFSSL_STM32_HASH
static void HASH_Init(void)
{
    __HAL_RCC_HASH_CLK_ENABLE();
    hhash.Instance           = HASH;
    hhash.Init.DataType      = HASH_BYTE_SWAP;
    /* wolfSSL's STM32 HASH port re-inits algorithm per-call; leave sane default */
    (void)HAL_HASH_Init(&hhash);
}
#endif

#ifdef WOLFSSL_STM32_AES
static void CRYP_Init(void)
{
    __HAL_RCC_AES_CLK_ENABLE();
    hcryp.Instance = AES;
    /* wolfSSL port re-configures per-operation; leave defaults */
}
#endif

void hw_init(void)
{
    /* wolfBoot jumps to the app with interrupts masked */
    __enable_irq();
    HAL_Init();
    SystemClock_Config();
    ICache_Init();
    RNG_Init();
#ifdef WOLFSSL_STM32_HASH
    HASH_Init();
#endif
#ifdef WOLFSSL_STM32_AES
    CRYP_Init();
#endif
}

void Error_Handler(void)
{
    while (1) { __NOP(); }
}

#ifdef USE_FULL_ASSERT
void assert_failed(uint8_t *file, uint32_t line)
{
    printf("ASSERT: %s:%lu\n", (char*)file, (unsigned long)line);
    while (1) { __NOP(); }
}
#endif
