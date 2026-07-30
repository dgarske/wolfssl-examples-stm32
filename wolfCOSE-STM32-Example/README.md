# wolfCOSE STM32 CubeMX Example

This directory contains a pre-configured STM32CubeMX project that uses the wolfCOSE CMSIS pack, a zero-allocation CBOR (RFC 8949) and COSE (RFC 9052/9053) library built on wolfCrypt. It runs a COSE_Sign1 ES256 sign and verify self test on the device and prints the result over UART. This example was built and verified on real NUCLEO-H563ZI hardware.

The wolfCOSE CMSIS pack is hosted at wolfSSL: <https://www.wolfssl.com/files/ide/I-CUBE-wolfCOSE.pack>
It depends on the wolfSSL pack: <https://www.wolfssl.com/files/ide/I-CUBE-wolfSSL.pack>

## Supported Boards

- NUCLEO-H563ZI (the provided `.ioc`). Any STM32 with a UART and RNG works; see "Other STM32 boards" below.

## Quick Start

### Step 1: Install the Packs

1. Download the wolfSSL pack from <https://www.wolfssl.com/files/ide/I-CUBE-wolfSSL.pack> and the wolfCOSE pack from <https://www.wolfssl.com/files/ide/I-CUBE-wolfCOSE.pack>
2. In STM32CubeMX, go to **Help -> Manage Embedded Software Packages -> From Local...** and install the wolfSSL pack, then the wolfCOSE pack.

### Step 2: Open the Provided Project

1. Open `NUCLEO-H563ZI/NUCLEO-H563ZI-wolfCOSE.ioc` in STM32CubeMX (do not create your own; USART3, RNG, clocks, and both pack components are already configured).
2. Click **Generate Code** (Makefile toolchain is preselected).

### Step 3: Use Software Crypto (STM32H5 workaround)

The wolfSSL pack enables the STM32H5 hardware hash by default, which currently mis-references a HAL enum on the H5. Use software crypto instead. In the generated `wolfSSL/wolfSSL.I-CUBE-wolfSSL_conf.h`, inside the `#elif defined(STM32H563xx)` block, comment out the hardware-crypto lines:

```c
    // #define WOLFSSL_STM32H5
    // #define STM32_HAL_V2
    // #undef  NO_STM32_HASH
    // #define WOLFSSL_STM32_PKA
```

Then add the TRNG seed hook at the end of that same file:

```c
extern int wolfCOSE_stm32_seed(unsigned char* output, unsigned int sz);
#undef  CUSTOM_RAND_GENERATE_SEED
#define CUSTOM_RAND_GENERATE_SEED wolfCOSE_stm32_seed
```

### Step 4: Add the Glue to main.c

In the `USER CODE BEGIN Includes` section:

```c
#include <stdio.h>
extern int wolfCOSETest(void);
```

In `USER CODE BEGIN 2` (in `main()`, after the peripherals are initialized):

```c
printf("\r\n== wolfCOSE NUCLEO-H563ZI ==\r\n");
wolfCOSETest();
fflush(stdout);
```

In `USER CODE BEGIN 4` (entropy from the TRNG and printf over USART3):

```c
int wolfCOSE_stm32_seed(unsigned char* output, unsigned int sz)
{
    extern RNG_HandleTypeDef hrng;
    uint32_t rnd = 0;
    unsigned int i;

    for (i = 0; i < sz; i++) {
        if ((i & 3u) == 0u) {
            if (HAL_RNG_GenerateRandomNumber(&hrng, &rnd) != HAL_OK) {
                return -1;
            }
        }
        output[i] = (unsigned char)(rnd >> ((i & 3u) * 8u));
    }
    return 0;
}

int __io_putchar(int ch)
{
    (void)HAL_UART_Transmit(&huart3, (uint8_t*)&ch, 1, HAL_MAX_DELAY);
    return ch;
}
```

`fflush(stdout)` matters: newlib block-buffers stdout on embedded, so without it the `PASS` line stays in the buffer and never reaches the UART.

### Step 5: Build and Run

Build with the STM32CubeIDE toolchain (its arm-none-eabi-gcc includes newlib; a bare Homebrew arm-none-eabi-gcc fails on `math.h`):

```bash
make GCC_PATH=/path/to/STM32CubeIDE/.../gnu-tools-for-stm32/tools/bin
```

Flash (STM32CubeIDE, STM32CubeProgrammer, or OpenOCD), open the ST-LINK virtual COM port at 115200 baud, and reset the board. Expected output:

```
== wolfCOSE NUCLEO-H563ZI ==
Running wolfCOSE test (COSE_Sign1 ES256)...
wolfCOSE test: PASS (COSE_Sign1 99 bytes)
```

That is a real COSE_Sign1 ES256 message signed and verified on the Cortex-M33, using software SP-math ECC and TRNG entropy.

## Other STM32 boards

The provided `.ioc` is specific to the NUCLEO-H563ZI (its pins and clocks). For a different STM32 (F4, F7, H7, etc.):

1. Create a new project for your board, enable a UART for output and the RNG peripheral.
2. Add the wolfSSL `wolfCrypt Core` and wolfCOSE `Core` + `Test` components, and generate.
3. Add the same Step 4 glue (point `__io_putchar` at your board's UART handle).
4. The Step 3 software-crypto edit is only needed on the STM32H5; on other families the wolfSSL pack's default crypto config builds as-is.

## Troubleshooting

### No UART output
- Confirm the terminal is on the ST-LINK VCP at 115200 baud.
- Ensure `fflush(stdout)` follows `wolfCOSETest()` and `__io_putchar` targets the right UART handle.

### `HASH_ALGOSELECTION_SHA256` undeclared (build error)
- The STM32H5 hardware-hash block is still active; apply the Step 3 edit.

### `wc_GenerateSeed()` error or RNG failure
- The TRNG seed hook (Step 3) or the seed function (Step 4) is missing, or the RNG peripheral is not enabled.

### `math.h: No such file` (command-line build)
- Build with the STM32CubeIDE toolchain via `GCC_PATH`; a newlib-less arm-none-eabi-gcc cannot build it.

## License

wolfCOSE is provided under GPLv3 or a commercial license from wolfSSL Inc.
