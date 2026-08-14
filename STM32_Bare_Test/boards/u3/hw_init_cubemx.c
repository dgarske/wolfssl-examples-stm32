/* hw_init_cubemx.c - STM32U385RG-Q (NUCLEO-U385RG-Q), CubeMX/HAL board init
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Mirrors boards/u3/hw_init.c -- SYSCLK = MSIS RC0 96 MHz (U3 max) via the
 * EPOD booster at VOS range 1 (LDO supply; SMPS not required for 96 MHz).
 *   USART1 on PA9 (TX) / PA10 (RX) AF7, 115200 8N1
 *   HSI48 on for RNG kernel clock (default RNGSEL = HSI48)
 */

#include "stm32u3xx_hal.h"
#include <stdio.h>
#include <stdint.h>

#include "board.h"

static UART_HandleTypeDef s_huart1;

/* wolfSSL's CubeMX PKA path (stm32_ecc_sign_hash_ex / _verify_hash_ex) uses
 * this handle by extern reference and expects the application to have brought
 * the peripheral up -- unlike the bare path, whose HAL_PKA_* shims init it
 * lazily. STM32_HW_CLOCK_AUTO does not cover PKA. */
PKA_HandleTypeDef hpka = { .Instance = PKA };

static void pka_init_cubemx(void)
{
    __HAL_RCC_PKA_CLK_ENABLE();
    /* The PKA pulls its seed from the RNG, so the RNG clock must be on before
     * HAL_PKA_Init or INITOK never asserts. */
    __HAL_RCC_RNG_CLK_ENABLE();
    if (HAL_PKA_Init(&hpka) != HAL_OK) {
        printf("PKA init FAILED: CR=0x%08lx SR=0x%08lx\n",
               (unsigned long)PKA->CR, (unsigned long)PKA->SR);
    }
}

void board_putc(int ch)
{
    uint8_t b = (uint8_t)ch;
    (void)HAL_UART_Transmit(&s_huart1, &b, 1u, HAL_MAX_DELAY);
}

static int clock_init_cubemx(void)
{
    RCC_OscInitTypeDef osc = {0};
    RCC_ClkInitTypeDef clk = {0};

    /* 96 MHz via MSIS RC0 + EPOD booster at VOS range 1 (LDO supply). Order
     * mirrors the bare path / ST U385 example minus the SMPS switch. The PWR
     * clock must be on or the VOSR/booster writes are silently dropped. */
    __HAL_RCC_PWR_CLK_ENABLE();
    if (HAL_RCCEx_EpodBoosterClkConfig(RCC_EPODBOOSTER_SOURCE_MSIS,
                                       RCC_EPODBOOSTER_DIV1) != HAL_OK) {
        return -1;
    }
    if (HAL_PWREx_EnableEpodBooster() != HAL_OK) {
        return -1;
    }
    if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK) {
        return -1;
    }

    osc.OscillatorType = RCC_OSCILLATORTYPE_MSIS | RCC_OSCILLATORTYPE_HSI48;
    osc.MSISState  = RCC_MSI_ON;
    osc.MSISSource = RCC_MSI_RC0;   /* 96 MHz */
    osc.MSISDiv    = RCC_MSI_DIV1;
    osc.HSI48State = RCC_HSI48_ON;
    if (HAL_RCC_OscConfig(&osc) != HAL_OK) {
        return -1;
    }

    clk.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK \
                  | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2 \
                  | RCC_CLOCKTYPE_PCLK3;
    clk.SYSCLKSource   = RCC_SYSCLKSOURCE_MSIS;
    clk.AHBCLKDivider  = RCC_SYSCLK_DIV1;
    clk.APB1CLKDivider = RCC_HCLK_DIV1;
    clk.APB2CLKDivider = RCC_HCLK_DIV1;
    clk.APB3CLKDivider = RCC_HCLK_DIV1;
    if (HAL_RCC_ClockConfig(&clk, FLASH_LATENCY_2) != HAL_OK) {
        return -1;
    }
    return 0;
}

static int uart_init_cubemx(void)
{
    GPIO_InitTypeDef gpio = {0};

    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_USART1_CLK_ENABLE();

    gpio.Pin       = GPIO_PIN_9 | GPIO_PIN_10;
    gpio.Mode      = GPIO_MODE_AF_PP;
    gpio.Pull      = GPIO_NOPULL;
    gpio.Speed     = GPIO_SPEED_FREQ_HIGH;
    gpio.Alternate = GPIO_AF7_USART1;
    HAL_GPIO_Init(GPIOA, &gpio);

    s_huart1.Instance = USART1;
    s_huart1.Init.BaudRate = 115200;
    s_huart1.Init.WordLength = UART_WORDLENGTH_8B;
    s_huart1.Init.StopBits = UART_STOPBITS_1;
    s_huart1.Init.Parity = UART_PARITY_NONE;
    s_huart1.Init.Mode = UART_MODE_TX_RX;
    s_huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    s_huart1.Init.OverSampling = UART_OVERSAMPLING_16;
    s_huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
    s_huart1.Init.ClockPrescaler = UART_PRESCALER_DIV1;
    s_huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
    if (HAL_UART_Init(&s_huart1) != HAL_OK) {
        return -1;
    }
    return 0;
}

void board_init(void)
{
    SCB->CPACR |= (0xFu << 20);
    FPU->FPCCR &= ~(FPU_FPCCR_LSPEN_Msk);
    __DSB();
    __ISB();

    SystemInit();
    (void)HAL_Init();
    (void)clock_init_cubemx();
    (void)uart_init_cubemx();
    pka_init_cubemx();
    board_common_systick_init(96000000u);
}

uint32_t board_sysclk_hz(void)
{
    return 96000000u;
}

const char *board_name(void)
{
    return "NUCLEO-U385RG-Q (CubeMX/HAL)";
}
